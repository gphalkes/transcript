/* Copyright (C) 2011,2013 G.P. Halkes
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

#include <pthread.h>
#include <stdio.h>

#include "moduledefs.h"
#include "transcript.h"

#ifndef DB_DIRECTORY
#define DB_DIRECTORY "/usr/local/lib/transcript"
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

#define ACQUIRE_LOCK() pthread_mutex_lock(&_transcript_lock);
#define RELEASE_LOCK() pthread_mutex_unlock(&_transcript_lock);

TRANSCRIPT_LOCAL extern void (*_transcript_acquire_lock)(void *);
TRANSCRIPT_LOCAL extern void (*_transcript_release_lock)(void *);
TRANSCRIPT_LOCAL extern pthread_mutex_t _transcript_lock;

struct _transcript_iconv_t {
  transcript_t *from, *to;
};

typedef struct transcript_alias_name_t {
  char *name;
  struct transcript_alias_name_t *next;
} transcript_alias_name_t;

#define NAME_DESC_FLAG_HAS_DISPNAME (1 << 0)
#define NAME_DESC_FLAG_DISABLED (1 << 1)
#define NAME_DESC_FLAG_PROBE_LOAD (1 << 2)

typedef struct transcript_name_desc_t {
  char *real_name;
  char *name;
  transcript_alias_name_t *aliases;
  struct transcript_name_desc_t *next;
  int flags;
} transcript_name_desc_t;

typedef void *(*open_func_t)(const char *);

TRANSCRIPT_LOCAL transcript_t *_transcript_fill_utf(transcript_t *handle,
                                                    transcript_utf_t utf_type);

TRANSCRIPT_LOCAL void _transcript_log(const char *fmt, ...);

TRANSCRIPT_LOCAL transcript_name_desc_t *_transcript_get_name_desc(const char *name,
                                                                   int need_normalization);

TRANSCRIPT_LOCAL void *_transcript_db_open(const char *name, const char *ext, open_func_t open_func,
                                           transcript_error_t *error);

TRANSCRIPT_LOCAL int _transcript_isalnum(int c);
TRANSCRIPT_LOCAL int _transcript_isdigit(int c);
TRANSCRIPT_LOCAL int _transcript_isspace(int c);
TRANSCRIPT_LOCAL int _transcript_isidchr(int c);
TRANSCRIPT_LOCAL int _transcript_tolower(int c);

TRANSCRIPT_LOCAL void _transcript_init_aliases_from_file(void);
TRANSCRIPT_LOCAL void _transcript_free_aliases(void);
TRANSCRIPT_LOCAL void *_transcript_open_state_table_converter(const converter_tables_v1_t *tables,
                                                              int flags, transcript_error_t *error);
TRANSCRIPT_LOCAL void *_transcript_open_sbcs_table_converter(const sbcs_converter_v1_t *tables,
                                                             int flags, transcript_error_t *error);

TRANSCRIPT_LOCAL extern const char **_transcript_search_path;
TRANSCRIPT_LOCAL extern int _transcript_initialized_count;
#endif
