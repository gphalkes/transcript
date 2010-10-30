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

/* Get and put routines for GB-18030. This uses the internal gb18030.cct tables. */

#include "charconv_internal.h"
#include "utf.h"
#include "unicode_convertor.h"

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

int _charconv_put_gb18030(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
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

uint_fast32_t _charconv_get_gb18030(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip) {
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

