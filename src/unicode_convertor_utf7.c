/* Copyright (C) 2010 G.P. Halkes
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 3, as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Get/put routines for UTF-7. */

#include "charconv.h"
#include "utf.h"
#include "unicode_convertor.h"

#define PLUS 43
#define MINUS 45


static cc_bool is_direct(uint_fast32_t c) {
	static const uint32_t is_direct_table[128 / 32] = {
		UINT32_C(0x2600), UINT32_C(0x87fff381), UINT32_C(0x07fffffe), UINT32_C(0x07fffffe) };
	return c < 128 && ((is_direct_table[c >> 5] & (1 << (c & 31))) != 0);
}

static cc_bool is_base64(uint_fast8_t c) {
	static const uint32_t is_base64_table[256 / 32] = {
		0, UINT32_C(0x3ff8800), UINT32_C(0x7fffffe), UINT32_C(0x7fffffe), 0, 0, 0, 0};
	return (is_base64_table[c >> 5] & (1 << (c & 31))) != 0;
}

static cc_bool is_optionally_direct(uint_fast8_t c) {
	static const uint32_t is_od_table[256 / 32] = {
		UINT32_C(0x2600), UINT32_C(0xfffff7ff), UINT32_C(0xefffffff), UINT32_C(0x3fffffff), 0, 0, 0, 0 };
	return (is_od_table[c >> 5] & (1 << (c & 31))) != 0;
}

static const uint8_t base64_to_value[256] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0,  63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
	 0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
	 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0};

static const uint8_t value_to_base64[64] = {
	 65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,
	 81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  97,  98,  99, 100, 101, 102,
	103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
	119, 120, 121, 122,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  43,  47};

#define ENSURE_OUTBYTESLEFT(x) do { if (*outbytesleft < x) return CHARCONV_NO_SPACE; } while (0)

#define HANDLE_DIRECT_FROM_BASE64(saved_state) do { \
	if (codepoint == MINUS) { \
		ENSURE_OUTBYTESLEFT(2 + saved_state); \
		if (saved_state) { \
			*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save]; \
			handle->state.utf7_put_save = 0; \
		} \
		*(*outbuf)++ = MINUS; \
		*(*outbuf)++ = MINUS; \
		*outbytesleft -= 2 + saved_state; \
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT; \
		return CHARCONV_SUCCESS; \
	} else if (is_direct(codepoint)) { \
		if (is_base64(codepoint)) { \
			ENSURE_OUTBYTESLEFT(2 + saved_state); \
			if (saved_state) { \
				*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save]; \
				handle->state.utf7_put_save = 0; \
			} \
			*(*outbuf)++ = MINUS; \
			*(*outbuf)++ = codepoint; \
			*outbytesleft -= 3; \
		} else { \
			ENSURE_OUTBYTESLEFT(1 + saved_state); \
			if (saved_state) { \
				*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save]; \
				handle->state.utf7_put_save = 0; \
			} \
			*(*outbuf)++ = codepoint; \
			(*outbytesleft) -= 1 + saved_state; \
		} \
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT; \
		return CHARCONV_SUCCESS; \
	} \
} while (0)

#define HANDLE_UNICODE(bits_left, include_plus) do { \
	if (codepoint > UINT32_C(0x10000)) { \
		ENSURE_OUTBYTESLEFT(5 + (bits_left == 2) + include_plus); \
		codepoint -= UINT32_C(0x10000); \
		low_surrogate = (codepoint & 0x3ff) + UINT32_C(0xdc00); \
		codepoint = (codepoint >> 10) + UINT32_C(0xd800); \
	} \
	ENSURE_OUTBYTESLEFT(2 + (bits_left != 6) + include_plus); \
	if (include_plus) \
		*(*outbuf)++ = PLUS; \
	*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save | (codepoint >> (16 - bits_left))]; \
	*(*outbuf)++ = value_to_base64[(codepoint >> (16 - bits_left - 6)) & 0x3f]; \
	if (bits_left == 4) { \
		*(*outbuf)++ = value_to_base64[(codepoint >> (16 - bits_left - 6)) & 0x3f]; \
		handle->state.utf7_put_save = 0; \
		handle->state.utf7_put_mode = UTF7_MODE_BASE64_0; \
	} else if (bits_left == 2) { \
		handle->state.utf7_put_save = (codepoint & 3) << 4; \
		handle->state.utf7_put_mode = UTF7_MODE_BASE64_4; \
	} else if (bits_left == 6) { \
		handle->state.utf7_put_save = (codepoint & 15) << 2; \
		handle->state.utf7_put_mode = UTF7_MODE_BASE64_2; \
	} \
	handle->state.utf7_put_mode = UTF7_MODE_BASE64_2; \
	*outbytesleft -= 2 + (bits_left != 6) + include_plus; \
	if (low_surrogate != 0) \
		goto next_surrogate; \
	return CHARCONV_SUCCESS; \
} while (0)

int put_utf7(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
	uint_fast32_t low_surrogate = 0;

next_surrogate:
	switch (handle->state.utf7_put_mode) {
		case UTF7_MODE_DIRECT:
			if (is_direct(codepoint)) {
				ENSURE_OUTBYTESLEFT(1);
				*(*outbuf)++ = codepoint;
				(*outbytesleft)--;
			} else if (codepoint == PLUS) {
				ENSURE_OUTBYTESLEFT(2);
				*(*outbuf)++ = PLUS;
				*(*outbuf)++ = MINUS;
				*outbytesleft -= 2;
			} else {
				HANDLE_UNICODE(6, 1);
			}
			return CHARCONV_SUCCESS;
		case UTF7_MODE_BASE64_0:
			HANDLE_DIRECT_FROM_BASE64(0);
			HANDLE_UNICODE(6, 0);
		case UTF7_MODE_BASE64_2:
			HANDLE_DIRECT_FROM_BASE64(1);
			HANDLE_UNICODE(2, 0);
		case UTF7_MODE_BASE64_4:
			HANDLE_DIRECT_FROM_BASE64(1);
			HANDLE_UNICODE(4, 0);
		default:
			return CHARCONV_INTERNAL_ERROR;
	}
}

int from_unicode_flush_utf7(convertor_state_t *handle, char **outbuf, size_t *outbytesleft) {
	switch (handle->state.utf7_put_mode) {
		case UTF7_MODE_DIRECT:
			break;
		case UTF7_MODE_BASE64_0:
			ENSURE_OUTBYTESLEFT(1);
			*(*outbuf)++ = MINUS;
			(*outbytesleft)--;
			break;
		case UTF7_MODE_BASE64_2:
		case UTF7_MODE_BASE64_4:
			ENSURE_OUTBYTESLEFT(2);
			*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save];
			*(*outbuf)++ = MINUS;
			*outbytesleft -= 2;
			break;
		default:
			return CHARCONV_INTERNAL_ERROR;
	}
	return CHARCONV_SUCCESS;
}

#define SKIP_BYTES(x) do { *inbytesleft = _inbytesleft - (x); *inbuf = (char *) (_inbuf + (x)); } while (0)

uint_fast32_t get_utf7(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, cc_bool skip) {
	uint_fast32_t codepoint, high_surrogate = 0;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	uint_fast8_t next_mode;
	int handled, i, extra_skip;

	while (_inbytesleft > 0) {
		switch (handle->state.utf7_get_mode) {
			case UTF7_MODE_DIRECT:
				if (*_inbuf == PLUS) {
					handle->state.utf7_get_mode = UTF7_MODE_SWITCHED;
					*inbytesleft = --_inbytesleft;
					*inbuf = (char *) (++_inbuf);
					break;
				} else if (is_optionally_direct(*_inbuf)) {
					*inbytesleft = _inbytesleft - 1;
					*inbuf = (char *) (_inbuf + 1);
					return *_inbuf;
				}
				if (skip)
					SKIP_BYTES(1);
				return CHARCONV_UTF_ILLEGAL;
			case UTF7_MODE_SWITCHED:
				if (*_inbuf == MINUS) {
					handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					*inbytesleft = _inbytesleft - 1;
					*inbuf = (char *) (_inbuf + 1);
					return PLUS;
				} else if (!is_base64(*_inbuf)) {
					handled = 1;
					goto skip_non_base64;
				}
				/* FALLTHROUGH */
			case UTF7_MODE_BASE64_0:
				if (is_base64(*_inbuf)) {
					if (_inbytesleft < 3)
						return CHARCONV_UTF_INCOMPLETE;

					if (!is_base64(_inbuf[1]) || !is_base64(_inbuf[2])) {
						handled = 3;
						goto skip_non_base64;
					}

					/* Note that we only advance the pointer by 2, because there will be two bits left
					   in the last byte. So the next time we look at the input, we need to look at
					   those two bits. */
					codepoint = base64_to_value[*_inbuf++];
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf++];
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf];
					codepoint >>= 2;
					_inbytesleft -= 2;

					next_mode = UTF7_MODE_BASE64_2;
					goto handle_surrogates;
				}
				handled = 1;
				goto switch_to_direct;
			case UTF7_MODE_BASE64_2:
				if (_inbytesleft < 2)
					return CHARCONV_UTF_INCOMPLETE;
				if (is_base64(_inbuf[1])) {
					if (_inbytesleft < 4)
						return CHARCONV_INCOMPLETE;

					if (!is_base64(_inbuf[2]) || !is_base64(_inbuf[3])) {
						handled = 4;
						goto skip_non_base64;
					}

					/* Note that we only advance the pointer by 3, because there will be four bits left
					   in the last byte. So the next time we look at the input, we need to look at
					   those four bits. */
					codepoint = base64_to_value[*_inbuf++] & 3;
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf++];
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf++];
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf];
					codepoint >>= 4;
					_inbytesleft -= 3;

					next_mode = UTF7_MODE_BASE64_4;
					goto handle_surrogates;
				}

				if ((base64_to_value[*_inbuf] & 3) != 0) {
					if (skip) {
						SKIP_BYTES(1);
						handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					}
					return CHARCONV_UTF_ILLEGAL;
				}
				handled = 2;
				goto switch_to_direct;

			case UTF7_MODE_BASE64_4:
				if (_inbytesleft < 2)
					return CHARCONV_UTF_INCOMPLETE;
				if (is_base64(_inbuf[1])) {
					if (_inbytesleft < 3)
						return CHARCONV_INCOMPLETE;

					if (!is_base64(_inbuf[2])) {
						handled = 3;
						goto skip_non_base64;
					}

					codepoint = base64_to_value[*_inbuf++] & 3;
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf++];
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf];
					_inbytesleft -= 3;

					next_mode = UTF7_MODE_BASE64_0;
					goto handle_surrogates;
				}

				if ((base64_to_value[*_inbuf] & 15) != 0) {
					if (skip) {
						SKIP_BYTES(1);
						handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					}
					return CHARCONV_UTF_ILLEGAL;
				}
				handled = 2;
				goto switch_to_direct;


			switch_to_direct:
				if (high_surrogate != 0) {
					if (skip) {
						SKIP_BYTES(_inbuf[handled - 1] == MINUS);
						handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					}
					return CHARCONV_UTF_ILLEGAL;
				}

				handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
				(*inbytesleft) = _inbytesleft -= handled;
				(*inbuf) = (char *) (_inbuf += handled);
				if (_inbuf[-1] == MINUS)
					break;
				return _inbuf[-1];

			handle_surrogates:
				if ((codepoint & 0xdc00) == 0xdc00) {
					/* Codepoint is a low surrogate. */
					if (high_surrogate == 0) {
						if (skip)
							SKIP_BYTES(0);
						return CHARCONV_UTF_ILLEGAL;
					}

					*inbytesleft = _inbytesleft;
					*inbuf = (char *) _inbuf;
					handle->state.utf7_get_mode = next_mode;
					return (codepoint - UINT32_C(0xdc00)) + ((high_surrogate - UINT32_C(0xd800)) >> 10) + UINT32_C(0x10000);
				}

				if (high_surrogate != 0) {
					if (skip)
						SKIP_BYTES(handle->state.utf7_get_mode == UTF7_MODE_BASE64_0 ? -2 : -3);
					return CHARCONV_UTF_ILLEGAL;
				}

				handle->state.utf7_get_mode = next_mode;
				if ((codepoint & 0xdc00) == 0xd800) {
					high_surrogate = codepoint;
					break;
				}

				*inbytesleft = _inbytesleft;
				*inbuf = (char *) _inbuf;
				return codepoint;
			default:
				return CHARCONV_UTF_INTERNAL_ERROR;
		}
	}
	return CHARCONV_UTF_INCOMPLETE;

skip_non_base64:
	if (!skip)
		return CHARCONV_UTF_ILLEGAL;

	handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
	for (i = 0; i < handled; i++) {
		if (!is_base64(_inbuf[i]))
			break;
	}

	extra_skip = !is_optionally_direct(_inbuf[i]);
	*inbytesleft = _inbytesleft - i - extra_skip;
	*inbuf = (char *) (_inbuf + i + extra_skip);
	return CHARCONV_UTF_ILLEGAL;
}
