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

/* This convertor is a wrapper around the functions in utf.c. */
#include <string.h>
#include <search.h>

#include "charconv.h"
#include "charconv_errors.h"
#include "charconv_internal.h"
#include "convertors.h"
#include "utf.h"


typedef struct convertor_state_t convertor_state_t;

typedef int (*put_func_t)(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
typedef uint_fast32_t (*get_func_t)(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, t3_bool skip);
typedef int (*flush_func_t)(convertor_state_t *handle, char **outbuf, size_t *outbytesleft);

typedef struct {
	const char *name;
	int utfcode;
} name_to_utfcode;

typedef struct {
	uint_fast32_t utf7_put_save;
	uint_fast8_t utf7_get_mode;
	uint_fast8_t utf7_put_mode;
} state_t;

struct convertor_state_t {
	charconv_common_t common;
	put_unicode_func_t from_unicode_put;
	get_unicode_func_t to_unicode_get;

	put_func_t from_put;
	get_func_t to_get;

	state_t state;

	charconv_t *gb18030_cct;
	int utf_type;
};

enum {
	UTF7_MODE_DIRECT,
	UTF7_MODE_SWITCHED,
	UTF7_MODE_BASE64_0,
	UTF7_MODE_BASE64_2,
	UTF7_MODE_BASE64_4
};

#define PLUS 43
#define MINUS 45

static int to_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft);
static int from_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft);
static void close_convertor(convertor_state_t *handle);


static int put_common(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
	return handle->common.put_unicode(codepoint, outbuf, outbytesleft);
}
static uint_fast32_t get_common(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, t3_bool skip) {
	return handle->common.get_unicode(inbuf, inbytesleft, skip);
}
static int put_from_unicode(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
	return handle->from_unicode_put(codepoint, outbuf, outbytesleft);
}
static uint_fast32_t get_to_unicode(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, t3_bool skip) {
	return handle->to_unicode_get(inbuf, inbytesleft, skip);
}

static t3_bool is_direct(uint_fast32_t c) {
	static const uint32_t is_direct_table[128 / 32] = {
		UINT32_C(0x2600), UINT32_C(0x87fff381), UINT32_C(0x07fffffe), UINT32_C(0x07fffffe) };
	return c < 128 && ((is_direct_table[c >> 5] & (1 << (c & 31))) != 0);
}

static t3_bool is_base64(uint_fast8_t c) {
	static const uint32_t is_base64_table[256 / 32] = {
		0, UINT32_C(0x3ff8800), UINT32_C(0x7fffffe), UINT32_C(0x7fffffe), 0, 0, 0, 0};
	return (is_base64_table[c >> 5] & (1 << (c & 31))) != 0;
}

static t3_bool is_optionally_direct(uint_fast8_t c) {
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

static int put_utf7(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
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

#define SKIP_BYTES(x) do { *inbytesleft = _inbytesleft - (x); *inbuf = (char *) (_inbuf + (x)); } while (0)

static uint_fast32_t get_utf7(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, t3_bool skip) {
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

typedef struct {
	uint_fast32_t low, high, unicode_low, unicode_high;
} gb_range_map_t;

static const gb_range_map_t gb_range_map[] = {
	{ UINT32_C(0x0334), UINT32_C(0x1ef1), UINT32_C(0x0452), UINT32_C(0x200f) },
	{ UINT32_C(0x2403), UINT32_C(0x2c40), UINT32_C(0x2643), UINT32_C(0x2e80) },
	{ UINT32_C(0x32ad), UINT32_C(0x35a9), UINT32_C(0x361b), UINT32_C(0x3917) },
	{ UINT32_C(0x396a), UINT32_C(0x3cde), UINT32_C(0x3ce1), UINT32_C(0x4055) },
	{ UINT32_C(0x3de7), UINT32_C(0x3fbd), UINT32_C(0x4160), UINT32_C(0x4336) },
	{ UINT32_C(0x4159), UINT32_C(0x42cd), UINT32_C(0x44d7), UINT32_C(0x464b) },
	{ UINT32_C(0x440a), UINT32_C(0x45c2), UINT32_C(0x478e), UINT32_C(0x4946) },
	{ UINT32_C(0x4629), UINT32_C(0x48e7), UINT32_C(0x49b8), UINT32_C(0x4c76) },
	{ UINT32_C(0x4a63), UINT32_C(0x82bc), UINT32_C(0x9fa6), UINT32_C(0xd7ff) },
	{ UINT32_C(0x830e), UINT32_C(0x93d4), UINT32_C(0xe865), UINT32_C(0xf92b) },
	{ UINT32_C(0x94be), UINT32_C(0x98c3), UINT32_C(0xfa2a), UINT32_C(0xfe2f) },
	{ UINT32_C(0x99e2), UINT32_C(0x99fb), UINT32_C(0xffe6), UINT32_C(0xffff) },
	{ UINT32_C(0x2e248), UINT32_C(0x12e247), UINT32_C(0x10000), UINT32_C(0x10ffff) }};

static int put_gb18030(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
#if UINT_FAST32_MAX == UINT32_MAX
#define _codepoint codepoint;
#else
	uint32_t _codepoint = codepoint;
#endif
	size_t codepoint_bytesleft = 4;
	char *codepoint_ptr = (char *) &_codepoint;
	size_t low, mid, high;
	uint8_t *_outbuf;

	switch (handle->gb18030_cct->convert_from(handle->gb18030_cct, &codepoint_ptr, &codepoint_bytesleft, outbuf,
			outbytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION))
	{
		case CHARCONV_SUCCESS:
			return CHARCONV_SUCCESS;
		case CHARCONV_NO_SPACE:
			return CHARCONV_NO_SPACE;
		case CHARCONV_UNASSIGNED:
			break;

		/* CHARCONV_FALLBACK
		   CHARCONV_INCOMPLETE
		   CHARCONV_PRIVATE_USE
		   CHARCONV_ILLEGAL
		   CHARCONV_ILLEGAL_END
		   CHARCONV_INTERNAL_ERROR */
		default:
			return CHARCONV_INTERNAL_ERROR;
	}

	low = 0;
	high = ARRAY_SIZE(gb_range_map);

	do {
		mid = low + ((high - low) / 2);
		if (gb_range_map[mid].unicode_high <= codepoint)
			low = mid + 1;
		else
			high = mid;
	} while (low < high);

	if (low == ARRAY_SIZE(gb_range_map) || codepoint > gb_range_map[low].unicode_high ||
			codepoint < gb_range_map[low].unicode_low)
		return CHARCONV_INTERNAL_ERROR;

	if (*outbytesleft < 4)
		return CHARCONV_NO_SPACE;

	_outbuf = (uint8_t *) *outbuf;
	codepoint = codepoint - gb_range_map[low].unicode_low + gb_range_map[low].low;
	_outbuf[3] = 0x30 + codepoint % (0x3a - 0x30);
	codepoint /= (0x3a - 0x30);
	_outbuf[2] = 0x81 + codepoint % (0xff - 0x81);
	codepoint /= (0xff - 0x81);
	_outbuf[1] = 0x30 + codepoint % (0x3a - 0x30);
	codepoint /= (0x3a - 0x30);
	_outbuf[0] = 0x81 + codepoint;
	*outbuf += 4;
	*outbytesleft -= 4;
	return CHARCONV_SUCCESS;
}

static uint_fast32_t get_gb18030(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, t3_bool skip) {
	char *codepoint_ptr;
	size_t codepoint_bytesleft;
	size_t low, mid, high;
	uint8_t *_inbuf;
	uint32_t codepoint;

	if (skip) {
		charconv_to_unicode_skip(handle->gb18030_cct, inbuf, inbytesleft);
		return 0;
	}

	codepoint_ptr = (char *) &codepoint;
	codepoint_bytesleft = 4;
	switch (handle->gb18030_cct->convert_to(handle->gb18030_cct, inbuf, inbytesleft, &codepoint_ptr,
			&codepoint_bytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_ALLOW_PRIVATE_USE | CHARCONV_NO_MN_CONVERSION))
	{
		case CHARCONV_SUCCESS:
			return codepoint;
		case CHARCONV_ILLEGAL:
			return CHARCONV_UTF_ILLEGAL;

		/* CHARCONV_FALLBACK
		   CHARCONV_ILLEGAL_END
		   CHARCONV_INTERNAL_ERROR
		   CHARCONV_PRIVATE_USE - Should not happen because we told the convertor that private use mappings are alright.
		   CHARCONV_NO_SPACE */
		default:
			return CHARCONV_UTF_INTERNAL_ERROR;

		case CHARCONV_INCOMPLETE:
			return CHARCONV_UTF_INCOMPLETE;
		case CHARCONV_UNASSIGNED:
			break;
	}

	if (*inbytesleft < 4)
		return CHARCONV_UTF_ILLEGAL;

	_inbuf = (uint8_t *) *inbuf;
	if (*_inbuf < 0x81 || *_inbuf > 0xfe)
		return CHARCONV_ILLEGAL;

	codepoint = _inbuf[0] - 0x81;
	codepoint = codepoint * (0x3a - 0x30) + _inbuf[1] - 0x30;
	codepoint = codepoint * (0xff - 0x81) + _inbuf[2] - 0x81;
	codepoint = codepoint * (0x3a - 0x30) + _inbuf[3] - 0x30;

	low = 0;
	high = ARRAY_SIZE(gb_range_map);

	do {
		mid = low + ((high - low) / 2);
		if (gb_range_map[mid].high <= codepoint)
			low = mid + 1;
		else
			high = mid;
	} while (low < high);

	if (low == ARRAY_SIZE(gb_range_map) || codepoint > gb_range_map[low].high || codepoint < gb_range_map[low].low)
		return CHARCONV_UTF_ILLEGAL;

	*inbuf += 4;
	*inbytesleft -= 4;
	return codepoint - gb_range_map[low].low + gb_range_map[low].unicode_low;
}

static int unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags, get_func_t get_unicode, put_func_t put_unicode, flush_func_t flush)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	int result;

	while (*inbytesleft > 0) {
		codepoint = get_unicode(handle, (char **) &_inbuf, &_inbytesleft, t3_false);
		switch (codepoint) {
			case CHARCONV_UTF_INTERNAL_ERROR:
				return CHARCONV_INTERNAL_ERROR;
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBSTITUTE_ALL))
						return CHARCONV_ILLEGAL_END;
					if ((result = put_unicode(handle, UINT32_C(0xfffd), outbuf, outbytesleft)) != 0)
						return result;
					*inbuf -= *inbytesleft;
					*inbytesleft = 0;
					if ((result = flush(handle, outbuf, outbytesleft)) != 0)
						return result;
					return CHARCONV_SUCCESS;
				}
				return CHARCONV_INCOMPLETE;
			default:
				break;
		}
		if ((result = put_unicode(handle, codepoint, outbuf, outbytesleft)) != 0)
			return result;
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}

	if (flags & CHARCONV_END_OF_TEXT) {
		if ((result = flush(handle, outbuf, outbytesleft)) != 0)
			return result;
	}

	return CHARCONV_SUCCESS;
}


static int to_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	if (flags & CHARCONV_FILE_START) {
		uint_fast32_t codepoint = 0;
		uint8_t *_inbuf = (uint8_t *) *inbuf;
		size_t _inbytesleft = *inbytesleft;

		if (handle->utf_type == UTF32 || handle->utf_type == UTF16) {
			codepoint = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE)(
					(char **) &_inbuf, &_inbytesleft, t3_false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE);
			} else if (codepoint == CHARCONV_ILLEGAL) {
				codepoint = get_get_unicode(handle->utf_type == UTF32 ? UTF32LE : UTF16LE)(
						(char **) &_inbuf, &_inbytesleft, t3_false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32LE : UTF16LE);
				else
					handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE);
			}
		} else {
			codepoint = handle->to_unicode_get((char **) &_inbuf, &_inbytesleft, t3_false);
		}
		/* Anything, including bad input, will simply not cause a pointer update,
		   meaning that only the BOM will be ignored. */
		if (codepoint == UINT32_C(0xFEFF)) {
			*inbuf = (char *) _inbuf;
			*inbytesleft = _inbytesleft;
		}
	}

	return unicode_conversion(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags,
		handle->to_get, put_common, to_unicode_flush);
}

static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->to_unicode_get(inbuf, inbytesleft, t3_true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

static void to_unicode_reset(convertor_state_t *handle) {
	if (handle->utf_type == UTF16)
		handle->to_unicode_get = get_get_unicode(UTF16BE);
	else if (handle->utf_type == UTF32)
		handle->to_unicode_get = get_get_unicode(UTF32BE);
	else if (handle->utf_type == UTF7)
		handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
}

static int to_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft) {
	(void) outbuf;
	(void) outbytesleft;

	to_unicode_reset(handle);
	return CHARCONV_SUCCESS;
}

static int from_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	if (inbuf == NULL || *inbuf == NULL)
		return CHARCONV_SUCCESS;

	if (flags & CHARCONV_FILE_START) {
		switch (handle->utf_type) {
			case UTF32:
			case UTF16:
			case UTF8_BOM:
				if (handle->from_unicode_put(UINT32_C(0xFEFF), outbuf, outbytesleft) == CHARCONV_NO_SPACE)
					return CHARCONV_NO_SPACE;
				break;
			default:
				break;
		}
	}

	return unicode_conversion(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags,
		get_common, handle->from_put, from_unicode_flush);
}

static void from_unicode_reset(convertor_state_t *handle) {
	if (handle->utf_type == UTF7) {
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT;
		handle->state.utf7_put_save = 0;
	}
}

static int from_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft) {
	if (handle->utf_type == UTF7) {
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
		to_unicode_reset(handle);
	}
	return CHARCONV_SUCCESS;
}

static void save_state(convertor_state_t *handle, void *state) {
	memcpy(state, &handle->state, sizeof(state_t));
}

static void load_state(convertor_state_t *handle, void *state) {
	memcpy(&handle->state, state, sizeof(state_t));
}

void *open_unicode_convertor(const char *name, int flags, int *error) {
	static const name_to_utfcode map[] = {
		{ "UTF-8", UTF8_LOOSE },
		{ "UTF-8_BOM", UTF8_BOM },
		{ "UTF-16", UTF16 },
		{ "UTF-16BE", UTF16BE },
		{ "UTF-16LE", UTF16LE },
		{ "UTF-32", UTF32 },
		{ "UTF-32BE", UTF32BE },
		{ "UTF-32LE", UTF32LE },
		{ "CESU-8", CESU8 },
		{ "GB-18030", GB18030 },
		{ "SCSU", SCSU },
		{ "UTF-7", UTF7 }
	};

	convertor_state_t *retval;
	name_to_utfcode *ptr;
	size_t array_size = ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(name_to_utfcode), element_strcmp)) == NULL) {
		if (error != NULL)
			*error = T3_ERR_TERMINFODB_NOT_FOUND;
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = T3_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_convertor;
	retval->common.save = (save_func_t) save_state;
	retval->common.load = (load_func_t) load_state;

	switch (ptr->utfcode) {
		case UTF16:
			retval->to_unicode_get = get_get_unicode(UTF16BE);
			retval->from_unicode_put = get_put_unicode(UTF16BE);
			break;
		case UTF32:
			retval->to_unicode_get = get_get_unicode(UTF32BE);
			retval->from_unicode_put = get_put_unicode(UTF32BE);
			break;
		case GB18030:
		case SCSU:
		case UTF7:
			break;
		default:
			retval->to_unicode_get = get_get_unicode(ptr->utfcode);
			retval->from_unicode_put = get_put_unicode(ptr->utfcode);
			break;
	}
	switch (ptr->utfcode) {
		case GB18030:
			if ((retval->gb18030_cct = fill_utf(open_cct_convertor_internal("gb18030", flags, error, t3_true), UTF32)) == NULL) {
				free(retval);
				return NULL;
			}
			retval->to_get = get_gb18030;
			retval->from_put = put_gb18030;
			break;
		case SCSU:
			break;
		case UTF7:
			retval->state.utf7_get_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_save = 0;
			retval->to_get = get_utf7;
			retval->from_put = put_utf7;
			break;
		default:
			retval->to_get = get_to_unicode;
			retval->from_put = put_from_unicode;
			break;
	}

	retval->utf_type = ptr->utfcode;
	return retval;
}

static void close_convertor(convertor_state_t *handle) {
	free(handle);
}

size_t get_unicode_saved_state_size(void) {
	return sizeof(state_t);
}
