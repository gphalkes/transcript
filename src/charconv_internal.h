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
#ifndef CHARCONV_INTERNAL_H
#define CHARCONV_INTERNAL_H

#define ARRAY_SIZE(name) (sizeof(name) / sizeof(name[0]))

#ifndef DB_DIRECTORY
#define DB_DIRECTORY "/usr/local/share/libcharconv"
#endif

/* Define a bool type if not already defined (C++ and C99 do)*/
#if !(defined(__cplusplus) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 19990601L))
typedef enum {false, true} bool;
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 19990601L
#include <stdbool.h>
#endif

typedef int (*conversion_func_t)(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags);
typedef int (*skip_func_t)(charconv_t *handle, char **inbuf, size_t *inbytesleft);
typedef int (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
typedef uint_fast32_t (*get_unicode_func_t)(char **inbuf, size_t *inbytesleft, bool skip);
typedef int (*reset_func_t)(charconv_t *handle);
typedef void (*close_func_t)(charconv_t *handle);
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

struct _cc_iconv_t {
	charconv_t *from, *to;
};

charconv_t *fill_utf(charconv_t *handle, int utf_type);
int element_strcmp(const void *a, const void *b);

#endif
