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

#include <stdio.h>
#include "charconv.h"

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

#define NORMALIZE_NAME_MAX 160
#ifdef HAS_INLINE
#define _CHARCONV_INLINE inline
#else
#define _CHARCONV_INLINE
#endif

#ifdef HAS_STRDUP
#define _charconv_strdup strdup
#else
CHARCONV_LOCAL char *_charconv_strdup(const char *str);
#endif

#ifdef WITHOUT_PTHREAD
#define PTHREAD_ONLY(_x)
#else
#define PTHREAD_ONLY(_x) do { _x; } while(0)
#endif

enum {
	CHARCONV_PROBE_ONLY = (1<<15)
};

typedef charconv_error_t (*conversion_func_t)(charconv_t *handle, const char **inbuf, const char *inbuflimit,
	char **outbuf, const char *outbuflimit, int flags);
typedef charconv_error_t (*flush_func_t)(charconv_t *handle, char **outbuf, const char *outbuflimit);
typedef charconv_error_t (*skip_func_t)(charconv_t *handle, const char **inbuf, const char *inbuflimit);
typedef charconv_error_t (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, const char *outbuflimit);
typedef uint_fast32_t (*get_unicode_func_t)(const char **inbuf, const char *inbuflimit, bool skip);
typedef int (*reset_func_t)(charconv_t *handle);
typedef void (*close_func_t)(charconv_t *handle);
typedef void (*save_func_t)(charconv_t *handle, void *state);
typedef void (*load_func_t)(charconv_t *handle, void *state);

typedef struct charconv_common_t {
	conversion_func_t convert_to;
	conversion_func_t convert_from;
	/* flush_func_t flush_to; */ /* The same for all convertors! */
	flush_func_t flush_from;
	skip_func_t skip_to;
	/* skip_func_t skip_from; */ /* The same for all convertors! */
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

typedef struct charconv_alias_name_t {
	char *name;
	struct charconv_alias_name_t *next;
} charconv_alias_name_t;

#define NAME_DESC_FLAG_HAS_DISPNAME (1<<0)

typedef struct charconv_name_desc_t {
	char *real_name;
	char *name;
	charconv_alias_name_t *aliases;
	struct charconv_name_desc_t *next;
	int flags;
} charconv_name_desc_t;


CHARCONV_LOCAL charconv_t *_charconv_fill_utf(charconv_t *handle, charconv_utf_t utf_type);

CHARCONV_LOCAL void _charconv_log(const char *fmt, ...);

CHARCONV_LOCAL charconv_name_desc_t *_charconv_get_name_desc(const char *name, int need_normalization);

CHARCONV_LOCAL void _charconv_init(void);
CHARCONV_LOCAL FILE *_charconv_db_open(const char *name, const char *ext, charconv_error_t *error);
CHARCONV_LOCAL int _charconv_probe_convertor(const char *name);

CHARCONV_LOCAL int _charconv_isalnum(int c);
CHARCONV_LOCAL int _charconv_isdigit(int c);
CHARCONV_LOCAL int _charconv_isspace(int c);
CHARCONV_LOCAL int _charconv_isidchr(int c);
CHARCONV_LOCAL int _charconv_tolower(int c);
CHARCONV_LOCAL void _charconv_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max);

CHARCONV_LOCAL void _charconv_init_aliases_from_file(void);
CHARCONV_LOCAL charconv_error_t _charconv_handle_unassigned(charconv_t *handle, uint32_t codepoint, char **outbuf,
		const char *outbuflimit, int flags);

#define HANDLE_UNASSIGNED(_code) \
	switch (_charconv_handle_unassigned((charconv_t *) handle, codepoint, outbuf, outbuflimit, flags)) { \
		case CHARCONV_UNASSIGNED: \
			_code \
			break; \
		case CHARCONV_SUCCESS: \
			break; \
		case CHARCONV_NO_SPACE: \
			return CHARCONV_NO_SPACE; \
		case CHARCONV_FALLBACK: \
			return CHARCONV_FALLBACK; \
		default: \
			return CHARCONV_INTERNAL_ERROR; \
	}

#endif
