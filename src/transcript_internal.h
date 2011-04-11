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
#ifndef TRANSCRIPT_INTERNAL_H
#define TRANSCRIPT_INTERNAL_H

#include <stdio.h>
#include "transcript.h"
#include "moduledefs.h"

#define ARRAY_SIZE(name) (sizeof(name) / sizeof(name[0]))

#ifndef DB_DIRECTORY
#define DB_DIRECTORY "/usr/local/share/libtranscript"
#endif

/* Define a bool type if not already defined (C++ and C99 do)*/
#if !(defined(__cplusplus) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 19990601L))
typedef enum {false, true} bool;
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 19990601L
#include <stdbool.h>
#endif

#define NORMALIZE_NAME_MAX 160
#ifdef HAS_INLINE
#define _TRANSCRIPT_INLINE inline
#else
#define _TRANSCRIPT_INLINE
#endif

#ifdef HAS_STRDUP
#define _transcript_strdup strdup
#else
TRANSCRIPT_LOCAL char *_transcript_strdup(const char *str);
#endif

#ifdef WITHOUT_PTHREAD
#define PTHREAD_ONLY(_x)
#else
#define PTHREAD_ONLY(_x) do { _x; } while(0)
#endif

enum {
	TRANSCRIPT_PROBE_ONLY = (1<<15)
};

typedef transcript_error_t (*conversion_func_t)(transcript_t *handle, const char **inbuf, const char *inbuflimit,
	char **outbuf, const char *outbuflimit, int flags);
typedef transcript_error_t (*flush_func_t)(transcript_t *handle, char **outbuf, const char *outbuflimit);
typedef transcript_error_t (*skip_func_t)(transcript_t *handle, const char **inbuf, const char *inbuflimit);
typedef transcript_error_t (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, const char *outbuflimit);
typedef uint_fast32_t (*get_unicode_func_t)(const char **inbuf, const char *inbuflimit, bool skip);
typedef int (*reset_func_t)(transcript_t *handle);
typedef void (*close_func_t)(transcript_t *handle);
typedef void (*save_func_t)(transcript_t *handle, void *state);
typedef void (*load_func_t)(transcript_t *handle, void *state);

typedef struct transcript_common_t {
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
} transcript_common_t;

struct _transcript_iconv_t {
	transcript_t *from, *to;
};

typedef struct transcript_alias_name_t {
	char *name;
	struct transcript_alias_name_t *next;
} transcript_alias_name_t;

#define NAME_DESC_FLAG_HAS_DISPNAME (1<<0)

typedef struct transcript_name_desc_t {
	char *real_name;
	char *name;
	transcript_alias_name_t *aliases;
	struct transcript_name_desc_t *next;
	int flags;
} transcript_name_desc_t;

/* FIXME: some of these should be exported for use in convertors. */
TRANSCRIPT_LOCAL transcript_t *_transcript_open_convertor(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error);
TRANSCRIPT_LOCAL transcript_t *_transcript_fill_utf(transcript_t *handle, transcript_utf_t utf_type);

TRANSCRIPT_LOCAL void _transcript_log(const char *fmt, ...);

TRANSCRIPT_LOCAL transcript_name_desc_t *_transcript_get_name_desc(const char *name, int need_normalization);

TRANSCRIPT_LOCAL void _transcript_init(void);
TRANSCRIPT_LOCAL FILE *_transcript_db_open(const char *name, const char *ext, transcript_error_t *error);
TRANSCRIPT_LOCAL int _transcript_probe_convertor(const char *name);

TRANSCRIPT_LOCAL int _transcript_isalnum(int c);
TRANSCRIPT_LOCAL int _transcript_isdigit(int c);
TRANSCRIPT_LOCAL int _transcript_isspace(int c);
TRANSCRIPT_LOCAL int _transcript_isidchr(int c);
TRANSCRIPT_LOCAL int _transcript_tolower(int c);
TRANSCRIPT_LOCAL void _transcript_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max);

TRANSCRIPT_LOCAL void _transcript_init_aliases_from_file(void);
TRANSCRIPT_LOCAL transcript_error_t _transcript_handle_unassigned(transcript_t *handle, uint32_t codepoint, char **outbuf,
		const char *outbuflimit, int flags);

#define HANDLE_UNASSIGNED(_code) \
	switch (_transcript_handle_unassigned((transcript_t *) handle, codepoint, outbuf, outbuflimit, flags)) { \
		case TRANSCRIPT_UNASSIGNED: \
			_code \
			break; \
		case TRANSCRIPT_SUCCESS: \
			break; \
		case TRANSCRIPT_NO_SPACE: \
			return TRANSCRIPT_NO_SPACE; \
		case TRANSCRIPT_FALLBACK: \
			return TRANSCRIPT_FALLBACK; \
		default: \
			return TRANSCRIPT_INTERNAL_ERROR; \
	}

#endif
