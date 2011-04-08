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

#include "transcript_internal.h"
#include "utf.h"
#include "unicode_convertor.h"

/** @internal
    @struct gb_range_map_t
    @brief A structure to hold a mapping from a range in GB-18030 format to a Unicode range.
*/
typedef struct {
	uint_fast32_t low, high, unicode_low, unicode_high;
} gb_range_map_t;

/** Mappings from ranges in GB-18030 format to Unicode ranges. */
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

/** @internal
    @brief Write a Unicode codepoint in GB-18030 encoding to a buffer.
*/
int _transcript_put_gb18030(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
#if UINT_FAST32_MAX == UINT32_MAX
#define _codepoint codepoint;
#else
	uint32_t _codepoint = codepoint;
#endif
	const char *codepoint_ptr = (const char *) &_codepoint;
	size_t low, mid, high;
	uint8_t *_outbuf;

	switch (handle->gb18030_cct->convert_from(handle->gb18030_cct, &codepoint_ptr, codepoint_ptr + 4, outbuf,
			outbuflimit, TRANSCRIPT_SINGLE_CONVERSION | TRANSCRIPT_NO_1N_CONVERSION))
	{
		case TRANSCRIPT_SUCCESS:
			return TRANSCRIPT_SUCCESS;
		case TRANSCRIPT_NO_SPACE:
			return TRANSCRIPT_NO_SPACE;
		case TRANSCRIPT_UNASSIGNED:
			break;

		/* TRANSCRIPT_FALLBACK
		   TRANSCRIPT_INCOMPLETE
		   TRANSCRIPT_PRIVATE_USE
		   TRANSCRIPT_ILLEGAL
		   TRANSCRIPT_ILLEGAL_END
		   TRANSCRIPT_INTERNAL_ERROR */
		default:
			return TRANSCRIPT_INTERNAL_ERROR;
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
		return TRANSCRIPT_INTERNAL_ERROR;

	if ((*outbuf) + 4 > outbuflimit)
		return TRANSCRIPT_NO_SPACE;

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
	return TRANSCRIPT_SUCCESS;
}

/** @internal
    @brief Read a Unicode codepoint in GB-18030 encoding from a buffer.
*/
uint_fast32_t _transcript_get_gb18030(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit, bool skip) {
	char *codepoint_ptr;
	size_t low, mid, high;
	const uint8_t *_inbuf;
	uint32_t codepoint;

	if (skip) {
		transcript_to_unicode_skip(handle->gb18030_cct, inbuf, inbuflimit);
		return 0;
	}

	codepoint_ptr = (char *) &codepoint;
	switch (handle->gb18030_cct->convert_to(handle->gb18030_cct, inbuf, inbuflimit, &codepoint_ptr,
			codepoint_ptr + 4, TRANSCRIPT_SINGLE_CONVERSION | TRANSCRIPT_ALLOW_PRIVATE_USE | TRANSCRIPT_NO_1N_CONVERSION))
	{
		case TRANSCRIPT_SUCCESS:
			return codepoint;
		case TRANSCRIPT_ILLEGAL:
			return TRANSCRIPT_UTF_ILLEGAL;

		/* TRANSCRIPT_FALLBACK - There should be no fallback mappings in the GB-18030 table.
		   TRANSCRIPT_ILLEGAL_END - As we do not include the TRANSCRIPT_END_OF_TEXT flag, this should be impossible.
		   TRANSCRIPT_INTERNAL_ERROR
		   TRANSCRIPT_PRIVATE_USE - Should not happen because we told the convertor that private use mappings are alright.
		   TRANSCRIPT_NO_SPACE - We provided enough space for the single character. */
		default:
			return TRANSCRIPT_UTF_INTERNAL_ERROR;

		case TRANSCRIPT_INCOMPLETE:
			return TRANSCRIPT_UTF_INCOMPLETE;
		case TRANSCRIPT_UNASSIGNED:
			break;
	}

	if ((*inbuf) + 4 > inbuflimit)
		return TRANSCRIPT_UTF_ILLEGAL;

	_inbuf = (const uint8_t *) *inbuf;
	if (*_inbuf < 0x81 || *_inbuf > 0xfe)
		return TRANSCRIPT_ILLEGAL;

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
		return TRANSCRIPT_UTF_ILLEGAL;

	*inbuf += 4;
	return codepoint - gb_range_map[low].low + gb_range_map[low].unicode_low;
}

