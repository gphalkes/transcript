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
#ifndef UNICODE_CONVERTOR_H
#define UNICODE_CONVERTOR_H

#include "charconv_internal.h"

typedef struct convertor_state_t convertor_state_t;

typedef int (*put_func_t)(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
typedef uint_fast32_t (*get_func_t)(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip);
typedef int (*flush_func_t)(convertor_state_t *handle, char **outbuf, size_t *outbytesleft);

typedef struct {
	uint_fast32_t utf7_put_save;
	uint_fast8_t utf7_get_mode;
	uint_fast8_t utf7_put_mode;
} state_t;

struct convertor_state_t {
	charconv_common_t common;
	put_unicode_func_t from_unicode_put;
	get_unicode_func_t to_unicode_get;

	put_func_t from_put;
	get_func_t to_get;

	state_t state;

	charconv_t *gb18030_cct;
	int utf_type;
};

enum {
	UTF7_MODE_DIRECT,
	UTF7_MODE_SWITCHED,
	UTF7_MODE_BASE64_0,
	UTF7_MODE_BASE64_2,
	UTF7_MODE_BASE64_4
};

int put_utf7(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
uint_fast32_t get_utf7(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip);
int from_unicode_flush_utf7(convertor_state_t *handle, char **outbuf, size_t *inbytesleft);

int put_gb18030(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft);
uint_fast32_t get_gb18030(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip);

#endif
