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

#include "transcript_internal.h"

#define TRANSCRIPT_UTF_ILLEGAL UINT32_C(0xffffffff)
#define TRANSCRIPT_UTF_INCOMPLETE UINT32_C(0xfffffffe)
/* TRANSCRIPT_UTF_INTERNAL_ERROR can _not_ be returned from the UTF-8/16/32 convertors, only
   from UTF-7/GB-18030/SCSU/BOCU-1 decoders. */
#define TRANSCRIPT_UTF_INTERNAL_ERROR UINT32_C(0xfffffffd)

enum {
	UTF8_LOOSE = _TRANSCRIPT_UTFLAST,
	UTF8_BOM,
	CESU8,
	GB18030,
	SCSU,
	UTF7
};

TRANSCRIPT_LOCAL put_unicode_func_t _transcript_get_put_unicode(transcript_utf_t type);
TRANSCRIPT_LOCAL get_unicode_func_t _transcript_get_get_unicode(transcript_utf_t type);
TRANSCRIPT_LOCAL uint_fast32_t _transcript_get_utf32_no_check(const char **inbuf, const char const *inbuflimit, bool skip);
TRANSCRIPT_LOCAL transcript_error_t _transcript_put_utf16_no_check(uint_fast32_t codepoint, char **outbuf);
#endif
