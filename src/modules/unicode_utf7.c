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

#include "unicode.h"

#define PLUS 43
#define MINUS 45

/** Check whether a character should be encoded directly, and not as base64 encoding. */
static bool is_direct(uint_fast32_t c) {
	static const uint32_t is_direct_table[128 / 32] = {
		UINT32_C(0x2600), UINT32_C(0x87fff381), UINT32_C(0x07fffffe), UINT32_C(0x07fffffe) };
	return c < 128 && ((is_direct_table[c >> 5] & (1 << (c & 31))) != 0);
}

/** Check whether a character is a valid base64 character. */
static bool is_base64(uint_fast8_t c) {
	static const uint32_t is_base64_table[256 / 32] = {
		0, UINT32_C(0x3ff8800), UINT32_C(0x7fffffe), UINT32_C(0x7fffffe), 0, 0, 0, 0};
	return (is_base64_table[c >> 5] & (1 << (c & 31))) != 0;
}

/** Check whether a character may be encoded directly, and not as base64 encoding. */
static bool is_optionally_direct(uint_fast8_t c) {
	static const uint32_t is_od_table[256 / 32] = {
		UINT32_C(0x2600), UINT32_C(0xfffff7ff), UINT32_C(0xefffffff), UINT32_C(0x3fffffff), 0, 0, 0, 0 };
	return (is_od_table[c >> 5] & (1 << (c & 31))) != 0;
}

/** Table to convert a base64 character into a value in the range 0-63. */
static const uint8_t base64_to_value[256] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0,  63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
	 0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
	 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0};

/** Table to convert a value in the range 0-63 into a base64 character. */
static const uint8_t value_to_base64[64] = {
	 65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,
	 81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  97,  98,  99, 100, 101, 102,
	103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
	119, 120, 121, 122,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  43,  47};

/** Simplification macro which returns if not enough space is left in @c outbuf. */
#define ENSURE_OUTBYTESLEFT(x) do { if ((*outbuf) + (x) > outbuflimit) return TRANSCRIPT_NO_SPACE; } while (0)

/** Simplification macro to write characters that should be encoded directly while in base64 mode. */
#define HANDLE_DIRECT_FROM_BASE64(saved_state) do { \
	if (codepoint == MINUS) { \
		ENSURE_OUTBYTESLEFT(2 + saved_state); \
		if (saved_state) { \
			*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save]; \
			handle->state.utf7_put_save = 0; \
		} \
		*(*outbuf)++ = MINUS; \
		*(*outbuf)++ = MINUS; \
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT; \
		return TRANSCRIPT_SUCCESS; \
	} else if (is_direct(codepoint)) { \
		if (is_base64(codepoint)) { \
			ENSURE_OUTBYTESLEFT(2 + saved_state); \
			if (saved_state) { \
				*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save]; \
				handle->state.utf7_put_save = 0; \
			} \
			*(*outbuf)++ = MINUS; \
			*(*outbuf)++ = codepoint; \
		} else { \
			ENSURE_OUTBYTESLEFT(1 + saved_state); \
			if (saved_state) { \
				*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save]; \
				handle->state.utf7_put_save = 0; \
			} \
			*(*outbuf)++ = codepoint; \
		} \
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT; \
		return TRANSCRIPT_SUCCESS; \
	} \
} while (0)

/** Simplification macro to write any unicode character, either in base64 or direct mode. */
#define HANDLE_UNICODE(bits_left, include_plus) do { \
	if (codepoint >= UINT32_C(0x10000)) { \
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
		handle->state.utf7_put_save = 0; \
		handle->state.utf7_put_mode = UTF7_MODE_BASE64_0; \
	} else if (bits_left == 2) { \
		*(*outbuf)++ = value_to_base64[(codepoint >> 2) & 0x3f]; \
		handle->state.utf7_put_save = (codepoint & 3) << 4; \
		handle->state.utf7_put_mode = UTF7_MODE_BASE64_4; \
	} else if (bits_left == 6) { \
		handle->state.utf7_put_save = (codepoint & 15) << 2; \
		handle->state.utf7_put_mode = UTF7_MODE_BASE64_2; \
	} \
	if (low_surrogate != 0) { \
		codepoint = low_surrogate; \
		low_surrogate = 0; \
		goto next_surrogate; \
	} \
	return TRANSCRIPT_SUCCESS; \
} while (0)

/** @internal
    @brief Write a unicode character to a buffer, using UTF-7 encoding.
*/
int _transcript_put_utf7(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	uint_fast32_t low_surrogate = 0;

next_surrogate:
	switch (handle->state.utf7_put_mode) {
		case UTF7_MODE_DIRECT:
			if (is_direct(codepoint)) {
				/* Easy case. No mode switching required. */
				ENSURE_OUTBYTESLEFT(1);
				*(*outbuf)++ = codepoint;
			} else if (codepoint == PLUS) {
				/* Plus character starts base64 mode. Append a minus character to indicate
				   that we mean a simple plus. */
				ENSURE_OUTBYTESLEFT(2);
				*(*outbuf)++ = PLUS;
				*(*outbuf)++ = MINUS;
			} else {
				HANDLE_UNICODE(6, 1);
			}
			return TRANSCRIPT_SUCCESS;
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
			return TRANSCRIPT_INTERNAL_ERROR;
	}
}

/** @internal
    @brief Flush the remaining state of the UTF-7 convertor to the output buffer.
*/
int _transcript_from_unicode_flush_utf7(convertor_state_t *handle, char **outbuf, const char const *outbuflimit) {
	switch (handle->state.utf7_put_mode) {
		case UTF7_MODE_DIRECT:
			break;
		case UTF7_MODE_BASE64_0:
			ENSURE_OUTBYTESLEFT(1);
			*(*outbuf)++ = MINUS;
			break;
		case UTF7_MODE_BASE64_2:
		case UTF7_MODE_BASE64_4:
			ENSURE_OUTBYTESLEFT(2);
			*(*outbuf)++ = value_to_base64[handle->state.utf7_put_save];
			*(*outbuf)++ = MINUS;
			break;
		default:
			return TRANSCRIPT_INTERNAL_ERROR;
	}
	return TRANSCRIPT_SUCCESS;
}

/** Simplification macro to skip a given number of bytes. */
#define SKIP_BYTES(x) do { *inbuf = (const char *) (_inbuf + (x)); } while (0)

/** @internal
    @brief Read a codepoint from a UTF-7 encoded buffer.
*/
uint_fast32_t _transcript_get_utf7(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit, bool skip) {
	uint_fast32_t codepoint, high_surrogate = 0;
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	uint_fast8_t next_mode;
	int handled, i, extra_skip;

	while (*inbuf < inbuflimit) {
		switch (handle->state.utf7_get_mode) {
			case UTF7_MODE_DIRECT:
				if (*_inbuf == PLUS) {
					/* Don't go to base64 mode immediately, because the next character
					   may be a minus or some other non-base64 character, indicating
					   that this plus was actually meant as a plus character and not a
					   mode switch. */
					handle->state.utf7_get_mode = UTF7_MODE_SWITCHED;
					*inbuf = (const char *) (++_inbuf);
					break;
				} else if (is_optionally_direct(*_inbuf)) {
					*inbuf = (const char *) (_inbuf + 1);
					return *_inbuf;
				}
				if (skip)
					SKIP_BYTES(1);
				return TRANSCRIPT_UTF_ILLEGAL;
			case UTF7_MODE_SWITCHED:
				if (*_inbuf == MINUS) {
					handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					*inbuf = (const char *) (_inbuf + 1);
					return PLUS;
				} else if (!is_base64(*_inbuf)) {
					handled = 1;
					goto skip_non_base64;
				}
				/* FALLTHROUGH */
			case UTF7_MODE_BASE64_0:
				if (is_base64(*_inbuf)) {
					if ((const char *) _inbuf + 3 > inbuflimit)
						return TRANSCRIPT_UTF_INCOMPLETE;

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

					next_mode = UTF7_MODE_BASE64_2;
					goto handle_surrogates;
				}
				handled = 1;
				goto switch_to_direct;
			case UTF7_MODE_BASE64_2:
				if ((const char *) _inbuf + 2 > inbuflimit)
					return TRANSCRIPT_UTF_INCOMPLETE;
				if (is_base64(_inbuf[1])) {
					if ((const char *) _inbuf + 4 > inbuflimit)
						return TRANSCRIPT_INCOMPLETE;

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

					next_mode = UTF7_MODE_BASE64_4;
					goto handle_surrogates;
				}

				if ((base64_to_value[*_inbuf] & 3) != 0) {
					if (skip) {
						SKIP_BYTES(1);
						handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					}
					return TRANSCRIPT_UTF_ILLEGAL;
				}
				handled = 2;
				goto switch_to_direct;

			case UTF7_MODE_BASE64_4:
				if ((const char *) _inbuf + 2 > inbuflimit)
					return TRANSCRIPT_UTF_INCOMPLETE;
				if (is_base64(_inbuf[1])) {
					if ((const char *) _inbuf + 3 > inbuflimit)
						return TRANSCRIPT_INCOMPLETE;

					if (!is_base64(_inbuf[2])) {
						handled = 3;
						goto skip_non_base64;
					}

					codepoint = base64_to_value[*_inbuf++] & 3;
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf++];
					codepoint <<= 6;
					codepoint |= base64_to_value[*_inbuf];

					next_mode = UTF7_MODE_BASE64_0;
					goto handle_surrogates;
				}

				if ((base64_to_value[*_inbuf] & 15) != 0) {
					if (skip) {
						SKIP_BYTES(1);
						handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					}
					return TRANSCRIPT_UTF_ILLEGAL;
				}
				handled = 2;
				goto switch_to_direct;


			switch_to_direct:
				if (high_surrogate != 0) {
					if (skip) {
						SKIP_BYTES(_inbuf[handled - 1] == MINUS);
						handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
					}
					return TRANSCRIPT_UTF_ILLEGAL;
				}

				handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
				(*inbuf) = (const char *) (_inbuf += handled);
				if (_inbuf[-1] == MINUS)
					break;
				return _inbuf[-1];

			handle_surrogates:
				if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xdc00)) {
					/* Codepoint is a low surrogate. */
					if (high_surrogate == 0) {
						if (skip)
							SKIP_BYTES(0);
						return TRANSCRIPT_UTF_ILLEGAL;
					}

					*inbuf = (const char *) _inbuf;
					handle->state.utf7_get_mode = next_mode;
					return (codepoint - UINT32_C(0xdc00)) + ((high_surrogate - UINT32_C(0xd800)) << 10) + UINT32_C(0x10000);
				}

				if (high_surrogate != 0) {
					if (skip)
						SKIP_BYTES(handle->state.utf7_get_mode == UTF7_MODE_BASE64_0 ? -2 : -3);
					return TRANSCRIPT_UTF_ILLEGAL;
				}

				handle->state.utf7_get_mode = next_mode;
				if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
					high_surrogate = codepoint;
					break;
				}

				*inbuf = (const char *) _inbuf;
				return codepoint;
			default:
				return TRANSCRIPT_UTF_INTERNAL_ERROR;
		}
	}
	return handle->state.utf7_get_mode == UTF7_MODE_DIRECT ? TRANSCRIPT_UTF_NO_VALUE : TRANSCRIPT_UTF_INCOMPLETE;

skip_non_base64:
	if (!skip)
		return TRANSCRIPT_UTF_ILLEGAL;

	handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
	for (i = 0; i < handled; i++) {
		if (!is_base64(_inbuf[i]))
			break;
	}

	extra_skip = !is_optionally_direct(_inbuf[i]);
	*inbuf = (const char *) (_inbuf + i + extra_skip);
	return TRANSCRIPT_UTF_ILLEGAL;
}
