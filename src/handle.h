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
#ifndef TRANSCRIPT_HANDLE_H
#define TRANSCRIPT_HANDLE_H
#include <transcript/bool.h>

typedef transcript_error_t (*conversion_func_t)(transcript_t *handle, const char **inbuf, const char *inbuflimit,
	char **outbuf, const char *outbuflimit, int flags);
typedef transcript_error_t (*flush_func_t)(transcript_t *handle, char **outbuf, const char *outbuflimit);
typedef transcript_error_t (*skip_func_t)(transcript_t *handle, const char **inbuf, const char *inbuflimit);
typedef transcript_error_t (*put_unicode_func_t)(uint_fast32_t codepoint, char **outbuf, const char *outbuflimit);
typedef uint_fast32_t (*get_unicode_func_t)(const char **inbuf, const char *inbuflimit, bool_t skip);
typedef void (*reset_func_t)(transcript_t *handle);
typedef void (*close_func_t)(transcript_t *handle);
typedef void (*save_load_func_t)(transcript_t *handle, void *state);

struct transcript_t {
	conversion_func_t convert_to;
	conversion_func_t convert_from;
	/* flush_func_t flush_to; */ /* The same for all converters! */
	flush_func_t flush_from;
	skip_func_t skip_to;
	/* skip_func_t skip_from; */ /* The same for all converters! */
	put_unicode_func_t put_unicode;
	get_unicode_func_t get_unicode;
	reset_func_t reset_to;
	reset_func_t reset_from;
	close_func_t close;
	save_load_func_t save;
	save_load_func_t load;
	void *library_handle;
	int flags;
};

/* FIXME: rename! */
TRANSCRIPT_API transcript_t *transcript_open_converter_nolock(const char *name, transcript_utf_t utf_type,
	int flags, transcript_error_t *error);

#endif
