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
#ifndef UTF_H
#define UTF_H

#define CHARCONV_UTF_ILLEGAL UINT32_C(0xffffffff)
#define CHARCONV_UTF_INCOMPLETE UINT32_C(0xfffffffe)
/* CHARCONV_UTF_INTERNAL_ERROR can _not_ be returned from the UTF-8/16/32 convertors, only
   from UTF-7/GB-18030/SCSU/BOCU-1 decoders. */
#define CHARCONV_UTF_INTERNAL_ERROR UINT32_C(0xfffffffd)

enum {
	UTF8,
	UTF16,
	UTF32,
	UTF16BE,
	UTF16LE,
	UTF32BE,
	UTF32LE,

	UTF8_LOOSE,
	UTF8_BOM,
	CESU8,
	GB18030,
	SCSU,
	UTF7
};

put_unicode_func_t get_put_unicode(int type);
get_unicode_func_t get_get_unicode(int type);
uint_fast32_t get_utf32_no_check(char **inbuf, size_t *inbytesleft, cc_bool skip);
#endif
