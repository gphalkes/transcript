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

#include "charconv_api.h"

//FIXME: do we want to somehow communicate counts of fallbacks/substitutes etc?
typedef int (*conversion_func_t)(void *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags);
typedef int (*skip_func_t)(void *handle, char **inbuf, size_t *inbytesleft);
typedef int (*reset_func_t)(void *handle);
typedef int (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
typedef uint_fast32_t (*get_unicode_func_t)(char **inbuf, size_t *inbytesleft, t3_bool skip);

typedef struct {
	conversion_func_t convert;
	skip_func_t skip;
	reset_func_t reset;
	union {
		put_unicode_func_t put_unicode;
		get_unicode_func_t get_unicode;
	} unicode_func;
	int flags;
} charconv_common_t;

enum {
	CHARCONV_ALLOW_FALLBACK = (1<<0), /* Include fallback characters in the conversion */
	CHARCONV_SUBSTITUTE = (1<<1), /* Automatically replace unmappable characters by substitute characters */
	CHARCONV_SUBSTITUTE_ALL = (1<<2), /* Automatically replace everything that is not a perfect transition */
	CHARCONV_ALLOW_PRIVATE_USE = (1<<3) /* Allow private-use mappings. If not allowed, they are handled like unassigned sequences, with the exception that they return a different error. */
};

enum {
	CHARCONV_FILE_START = (1<<0), /* The begining of the input buffer is the begining of a file and a BOM should be expected/generated */
	CHARCONV_END_OF_TEXT = (1<<1), /* The end of the input buffer is the end of the text */
	CHARCONV_SINGLE_CONVERSION = (1<<2) /* Only convert the next character, then return (useful for handling fallback/unassigned characters etc.) */
};

enum {
	CHARCONV_SUCCESS, /* All OK */
	CHARCONV_FALLBACK, /* The next character to convert is a fallback mapping */
	CHARCONV_UNASSIGNED, /* The next character to convert is an unassigned sequence */
	CHARCONV_ILLEGAL, /* The input is an illegal sequence */
	CHARCONV_ILLEGAL_END, /* The end of the input does not form a valid sequence */
	CHARCONV_INTERNAL_ERROR, /* The charconv library screwed up; no recovery possible */
	CHARCONV_PRIVATE_USE, /* The next character to convert maps to a private use codepoint */
	CHARCONV_NO_SPACE, /* There was no space left in the output buffer */
	CHARCONV_INCOMPLETE /* The buffer ended with an incomplete sequence, or more data was needed to verify a M:N conversion */
};

#define CHARCONV_UTF_ILLEGAL UINT32_C(0xffffffff)
#define CHARCONV_UTF_INCOMPLETE UINT32_C(0xfffffffe)

#endif
