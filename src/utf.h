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

enum {
	UTF8,
	UTF8_BOM,
	UTF8_STRICT,
	UTF8_STRICT_BOM,
	UTF16,
	UTF16BE,
	UTF16LE,
	UTF16ME, /* Machine endian version */
	UTF32,
	UTF32BE,
	UTF32LE,
	UTF32ME /* Machine endian version */
};
put_unicode_func_t get_put_unicode(int type);
get_unicode_func_t get_get_unicode(int type);

int put_utf16(uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
#endif
