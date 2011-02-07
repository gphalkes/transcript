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
#ifdef UTF_ENDIAN_H_VERSION
#define __ALT(x, y) x ## y
#define _ALT(x, y) __ALT(x, y)
#define ALT(x) _ALT(x, UTF_ENDIAN_H_VERSION)

/* clang (correctly) complains about increased alignment in casts here, but we
   ignore those. We ask the user to make sure instead. */
#pragma GCC diagnostic ignored "-Wcast-align"

static charconv_error_t ALT(put_utf16)(uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	uint16_t *_outbuf = (uint16_t *) *outbuf;

	CHECK_CODEPOINT_RANGE();
	if (codepoint < UINT32_C(0xffff)) {
		CHECK_OUTBYTESLEFT(2);
		*_outbuf = ALT(swaps)(codepoint);
		*outbuf += 2;
	} else {
		CHECK_OUTBYTESLEFT(4);
		codepoint -= UINT32_C(0x10000);
		*_outbuf++ = ALT(swaps)(UINT32_C(0xd800) + (codepoint >> 10));
		*_outbuf = ALT(swaps)(UINT32_C(0xdc00) + (codepoint & 0x3ff));
		*outbuf += 4;
	}
	return CHARCONV_SUCCESS;
}

static charconv_error_t ALT(put_utf32)(uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	uint32_t *_outbuf = (uint32_t *) *outbuf;
	CHECK_CODEPOINT_RANGE();

	CHECK_OUTBYTESLEFT(4);
	*_outbuf = ALT(swapl)(codepoint);
	*outbuf += 4;
	return CHARCONV_SUCCESS;
}

static uint_fast32_t ALT(get_utf16)(const char **inbuf, const char const *inbuflimit, bool skip) {
	uint_fast32_t codepoint, masked_codepoint;

	if ((*inbuf) + 2 > inbuflimit)
		return CHARCONV_UTF_INCOMPLETE;

	codepoint = ALT(swaps)(*(const uint16_t *) *inbuf);
	masked_codepoint = codepoint & UINT32_C(0xfc00);

	if (masked_codepoint == UINT32_C(0xd800)) {
		uint_fast32_t next_codepoint;
		/* Codepoint is high surrogate. */
		if ((*inbuf) + 4 > inbuflimit)
			return CHARCONV_UTF_INCOMPLETE;

		next_codepoint = ALT(swaps)(((const uint16_t *) *inbuf)[1]);
		if ((next_codepoint & UINT32_C(0xfc00)) != UINT32_C(0xdc00)) {
			/* Next codepoint is not a low surrogate. */
			if (!skip)
				return CHARCONV_UTF_ILLEGAL;

			/* Only skip the high surrogate. */
			*inbuf += 2;
			return codepoint;
		}
		codepoint -= UINT32_C(0xd800);
		codepoint <<= 10;
		codepoint += next_codepoint - UINT32_C(0xdc00);

		if (!skip)
			CHECK_CODEPOINT_ILLEGAL();
		*inbuf += 4;
		return codepoint;
	}

	if (!skip) {
		if (masked_codepoint == UINT32_C(0xdc00)) {
			/* Codepoint is a low surrogate. */
			return CHARCONV_UTF_ILLEGAL;
		}
		CHECK_CODEPOINT_ILLEGAL();
	}

	*inbuf += 2;
	return codepoint;
}

static uint_fast32_t ALT(get_utf32)(const char **inbuf, const char const *inbuflimit, bool skip) {
	uint_fast32_t codepoint;

	if ((*inbuf) + 4 > inbuflimit)
		return CHARCONV_UTF_INCOMPLETE;

	codepoint = ALT(swapl)(*(const uint32_t *) *inbuf);
	if (!skip) {
		CHECK_CODEPOINT_ILLEGAL();
		CHECK_CODEPOINT_SURROGATES();
	}

	*inbuf += 4;
	return codepoint;
}

#undef ALT
#undef _ALT
#undef __ALT
#endif
