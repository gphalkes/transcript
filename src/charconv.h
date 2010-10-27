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

#include <stdlib.h>
#include <stdint.h>
#include "charconv_api.h"

typedef struct charconv_common_t charconv_t;

//FIXME: do we want to somehow communicate counts of fallbacks/substitutes etc?
typedef int (*conversion_func_t)(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags);
typedef int (*skip_func_t)(charconv_t *handle, char **inbuf, size_t *inbytesleft);
typedef int (*reset_func_t)(charconv_t *handle);
typedef int (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
typedef void (*close_func_t)(charconv_t *handle);
typedef uint_fast32_t (*get_unicode_func_t)(char **inbuf, size_t *inbytesleft, t3_bool skip);
typedef void (*save_func_t)(charconv_t *handle, void *state);
typedef void (*load_func_t)(charconv_t *handle, void *state);

typedef struct charconv_common_t {
	conversion_func_t convert_to;
	conversion_func_t convert_from;
	skip_func_t skip_to;
	/* skip_func_t skip_from; */ // The same for all convertors!
	put_unicode_func_t put_unicode;
	get_unicode_func_t get_unicode;
	reset_func_t reset_to;
	reset_func_t reset_from;
	close_func_t close;
	save_func_t save;
	load_func_t load;
	int flags;
	int utf_type;
} charconv_common_t;

enum {
	CHARCONV_ALLOW_FALLBACK = (1<<0), /* Include fallback characters in the conversion */
	CHARCONV_SUBSTITUTE = (1<<1), /* Automatically replace unmappable characters by substitute characters */
	CHARCONV_SUBSTITUTE_ALL = (1<<2), /* Automatically replace everything that is not a perfect transition */
	CHARCONV_ALLOW_PRIVATE_USE = (1<<3), /* Allow private-use mappings. If not allowed, they are handled like unassigned sequences, with the exception that they return a different error. */

	/* These are only valid as argument to charconv_from_unicode and charconv_to_unicode. */
	CHARCONV_FILE_START = (1<<8), /* The begining of the input buffer is the begining of a file and a BOM should be expected/generated */
	CHARCONV_END_OF_TEXT = (1<<9), /* The end of the input buffer is the end of the text */
	CHARCONV_SINGLE_CONVERSION = (1<<10) /* Only convert the next character, then return (useful for handling fallback/unassigned characters etc.) */
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


#ifndef DB_DIRECTORY
#define DB_DIRECTORY "/usr/local/share/libcharconv"
#endif

charconv_t *charconv_open_convertor(const char *name, int utf_type, int flags, int *error);
void charconv_close_convertor(charconv_t *handle);
int charconv_to_unicode(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags);
int charconv_from_unicode(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags);
int charconv_to_unicode_skip(charconv_t *handle, char **inbuf, size_t *inbytesleft);
int charconv_from_unicode_skip(charconv_t *handle, char **inbuf, size_t *inbytesleft);
void charconv_to_unicode_reset(charconv_t *handle);
void charconv_from_unicode_reset(charconv_t *handle);
size_t charconv_get_saved_state_size(void);
void charconv_save_state(charconv_t *handle, void *state);
void charconv_load_state(charconv_t *handle, void *state);

#if defined(CHARCONV_ICONV_API) || defined(CHARCONV_ICONV)

typedef struct {
	charconv_t *from, *to;
} *cc_iconv_t;

cc_iconv_t cc_iconv_open(const char *tocode, const char *fromcode);
int cc_iconv_close(cc_iconv_t cd);
size_t cc_iconv(cc_iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);

#ifdef CHARCONV_ICONV
typedef cc_iconv_t iconv_t;
#define iconv(_a, _b, _c, _d, _e) cc_iconv((_a), (_b), (_c), (_d), (_e))
#define iconv_open(_a, _b) cc_iconv_open((_a), (_b))
#define iconv_close(_a) cc_iconv_close(_a)
#endif
#endif

#endif
