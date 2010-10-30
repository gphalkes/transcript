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

int ALT(put_utf16)(uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
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

static int ALT(put_utf32)(uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
	uint32_t *_outbuf = (uint32_t *) *outbuf;
	CHECK_CODEPOINT_RANGE();

	CHECK_OUTBYTESLEFT(4);
	*_outbuf = ALT(swapl)(codepoint);
	*outbuf += 4;
	*outbytesleft += 4;
	return CHARCONV_SUCCESS;
}

static uint_fast32_t ALT(get_utf16)(char **inbuf, size_t *inbytesleft, bool skip) {
	uint_fast32_t codepoint;

	if (*inbytesleft < 2)
		return CHARCONV_UTF_INCOMPLETE;

	codepoint = ALT(swaps)(*(uint16_t *) *inbuf);

	if (codepoint >= UINT32_C(0xd800) && codepoint < UINT32_C(0xdc00)) {
		uint_fast32_t next_codepoint;
		/* Codepoint is high surrogate. */
		if (*inbytesleft < 2)
			return CHARCONV_UTF_INCOMPLETE;

		next_codepoint = ALT(swaps)(((uint16_t *) *inbuf)[1]);
		if (!(next_codepoint >= UINT32_C(0xdc00) && next_codepoint <= UINT32_C(0xdfff))) {
			/* Next codepoint is not a low surrogate. */
			if (!skip)
				return CHARCONV_UTF_ILLEGAL;

			/* Only skip the high surrogate. */
			*inbuf += 2;
			*inbytesleft -= 2;
			return codepoint;
		}
		codepoint -= UINT32_C(0xd800);
		codepoint <<= 10;
		codepoint += next_codepoint - UINT32_C(0xdc00);

		if (!skip)
			CHECK_CODEPOINT_ILLEGAL();
		*inbuf += 4;
		*inbytesleft -= 4;
		return codepoint;
	} else if (!skip && codepoint >= UINT32_C(0xdc00) && codepoint <= UINT32_C(0xdfff)) {
		/* Codepoint is a low surrogate. */
		return CHARCONV_UTF_ILLEGAL;
	}

	if (!skip)
		CHECK_CODEPOINT_ILLEGAL();

	*inbuf += 2;
	*inbytesleft -= 2;
	return codepoint;
}

static uint_fast32_t ALT(get_utf32)(char **inbuf, size_t *inbytesleft, bool skip) {
	uint_fast32_t codepoint;

	if (*inbytesleft < 4)
		return CHARCONV_UTF_INCOMPLETE;

	codepoint = ALT(swapl)(*(uint32_t *) *inbuf);
	if (!skip) {
		CHECK_CODEPOINT_ILLEGAL();
		CHECK_CODEPOINT_SURROGATES();
	}

	*inbuf += 4;
	*inbytesleft -= 4;
	return codepoint;
}
#undef ALT
#undef _ALT
#undef __ALT
#endif
