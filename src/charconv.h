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
#ifndef CHARCONV_H
#define CHARCONV_H

//FIXME: do we want to somehow communicate counts of fallbacks/substitutes etc?
typedef int (*conversion_func_t)(void *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags);
typedef int (*reset_func_t)(void *handle);
typedef int (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, size_t *outbytes_left);

typedef struct {
	conversion_func_t convert;
	reset_func_t reset;
	put_unicode_func_t put_unicode;
	//FIXME: skip function
	int flags;
} charconv_basic_t;

enum {
	CHARCONV_ALLOW_FALLBACK = (1<<0), // Include fallback characters in the conversion
	CHARCONV_SUBSTITUTE = (1<<1), // Automatically replace unmappable characters by substitute characters
	CHARCONV_SUBSTITUTE_ALL = (1<<2), // Automatically replace everything that is not a perfect transition
	CHARCONV_ALLOW_PRIVATE_USE = (1<<3)
};

enum {
	CHARCONV_FILE_START = (1<<0), // The begining of the input buffer is the begining of a file and a BOM should be expected/generated
	CHARCONV_END_OF_TEXT = (1<<1) // The end of the input buffer is the end of the text
};

enum {
	CHARCONV_SUCCESS,
	CHARCONV_FALLBACK,
	CHARCONV_UNMAPPED,
	CHARCONV_ILLEGAL,
	CHARCONV_INTERNAL_ERROR,
	CHARCONV_PRIVATE_USE,
	CHARCONV_NO_SPACE
};

#endif
