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
//FIXME: may require netinet/inet.h instead of arpa/inet.h
#include <arpa/inet.h>

#include "charconv.h"
#include "utf.h"

#define CHECK_CODEPOINT_RANGE() do { if (codepoint > UINT32_C(0x10ffff) || \
	(codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdfff))) return CHARCONV_INTERNAL_ERROR; } while (0)

#if __GNUC__ > 4 || (__GNUC__ == 4 &&  __GNUC_MINOR__ >= 3)
#define swapl(value) __builtin_bswap32(value)
#else
static inline uint32_t swapl(uint32_t value) {
	return swaps(value) << 16 | swaps(value >> 16);
}
#endif
/* FIXME: it is probably faster to use htons/htonl on little endian machines because that
   is usually a compilter builtin */
static inline uint16_t swaps(uint16_t value) {
	return (value << 8) | (value >> 8);
}

static int put_utf8(uint_fast32_t codepoint, char **outbuf, size_t *outbytes_left) {
	uint8_t *_outbuf = (uint8_t *) *outbuf;
	size_t count;
	uint8_t base_byte;

	CHECK_CODEPOINT_RANGE();

	if (codepoint < 0x7f) {
		count = 1;
		base_byte = 0;
	} else if (codepoint < 0x7ff) {
		count = 2;
		base_byte = 0xc0;
	} else if (codepoint < 0xffff) {
		count = 3;
		base_byte = 0xe0;
	} else {
		count = 4;
		base_byte = 0xf0;
	}

	if (*outbytes_left < count)
		return CHARCONV_NO_SPACE;

	*outbuf += count;
	*outbytes_left -= count;

	for (; count-- > 1;) {
		_outbuf[count] = 0x80 | (codepoint & 0x3f);
		codepoint >>= 6;
	}
	*_outbuf = base_byte | codepoint;

	return CHARCONV_SUCCESS;
}

static int put_utf16(uint_fast32_t codepoint, char **outbuf, size_t *outbytes_left) {
	uint16_t *_outbuf = (uint16_t *) *outbuf;

	CHECK_CODEPOINT_RANGE();
	if (codepoint < UINT32_C(0xffff)) {
		if (*outbytes_left < 2)
			return CHARCONV_NO_SPACE;
		*_outbuf = codepoint;
		*outbuf += 2;
		*outbytes_left -= 2;
	} else {
		if (*outbytes_left < 4)
			return CHARCONV_NO_SPACE;
		codepoint -= UINT32_C(0x10000);
		*_outbuf++ = UINT32_C(0xd800) + (codepoint >> 10);
		*_outbuf = UINT32_C(0xdc00) + (codepoint & 0x3ff);
		*outbuf += 4;
		*outbytes_left -= 4;
	}
	return CHARCONV_SUCCESS;
}

static int put_utf16swap(uint_fast32_t codepoint, char **outbuf, size_t *outbytes_left) {
	uint16_t *_outbuf = (uint16_t *) *outbuf;

	CHECK_CODEPOINT_RANGE();
	if (codepoint < UINT32_C(0xffff)) {
		if (*outbytes_left < 2)
			return CHARCONV_NO_SPACE;
		*_outbuf = swaps(codepoint);
		*outbuf += 2;
		*outbytes_left -= 2;
	} else {
		if (*outbytes_left < 4)
			return CHARCONV_NO_SPACE;
		codepoint -= UINT32_C(0x10000);
		*_outbuf++ = swaps(UINT32_C(0xd800) + (codepoint >> 10));
		*_outbuf = swaps(UINT32_C(0xdc00) + (codepoint & 0x3ff));
		*outbuf += 4;
		*outbytes_left -= 4;
	}
	return CHARCONV_SUCCESS;
}

static int put_utf32(uint_fast32_t codepoint, char **outbuf, size_t *outbytes_left) {
	uint32_t *_outbuf = (uint32_t *) *outbuf;
	CHECK_CODEPOINT_RANGE();

	if (*outbytes_left < 4)
		return CHARCONV_NO_SPACE;
	*_outbuf = codepoint;
	*outbuf += 4;
	*outbytes_left += 4;
	return CHARCONV_SUCCESS;
}

static int put_utf32swap(uint_fast32_t codepoint, char **outbuf, size_t *outbytes_left) {
	uint32_t *_outbuf = (uint32_t *) *outbuf;
	CHECK_CODEPOINT_RANGE();

	if (*outbytes_left < 4)
		return CHARCONV_NO_SPACE;
	*_outbuf = swapl(codepoint);
	*outbuf += 4;
	*outbytes_left += 4;
	return CHARCONV_SUCCESS;
}

put_unicode_func_t get_put_unicode(int type) {
	switch (type) {
		case UTF8:
			return put_utf8;
		case UTF16:
			return put_utf16;
		case UTF16BE:
			return htons(1) == 1 ? put_utf16 : put_utf16swap;
		case UTF16LE:
			return htons(1) == 1 ? put_utf16swap : put_utf16;
		case UTF32:
			return put_utf32;
		case UTF32BE:
			return htons(1) == 1 ? put_utf32 : put_utf32swap;
		case UTF32LE:
			return htons(1) == 1 ? put_utf32swap : put_utf32;
		default:
			/* Can't return NULL, because that will screw up later calls. */
			return put_utf8;
	}
}
