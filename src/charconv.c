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
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include "charconv.h"
#include "charconv_errors.h"
#include "utf.h"

//FIXME: move these to a separate header
void *open_cct_convertor(const char *name, int utf_type, int flags, int *error);
size_t get_cct_saved_state_size(void);
void *open_unicode_convertor(const char *name, int utf_type, int flags, int *error);
size_t get_unicode_saved_state_size(void);

typedef struct {
	const char *squashed_name;
	const char *convertor_name;
	void *(*open)(const char *name, int utf_type, int flags, int *error);
} name_mapping;

//FIXME: we need a list of known convertors and aliases! i.e. read convrtrs.txt
static name_mapping convertors[] = {
	{ "ibm437", "ibm-437_p100-1995", open_cct_convertor },
	{ "ibm437p100", "ibm-437_p100-1995", open_cct_convertor },
	{ "ibm437p1001995", "ibm-437_p100-1995", open_cct_convertor },
	{ "utf8", "UTF-8", open_unicode_convertor },
	{ "utf8bom", "UTF-8BOM", open_unicode_convertor },
	{ "utf16", "UTF-16", open_unicode_convertor },
	{ "utf16be", "UTF-16BE", open_unicode_convertor },
	{ "utf16le", "UTF-16LE", open_unicode_convertor },
	{ "ucs2", "UTF-16", open_unicode_convertor },
	{ "ucs2be", "UTF-16BE", open_unicode_convertor },
	{ "ucs2le", "UTF-16LE", open_unicode_convertor },
	{ "utf32", "UTF-32", open_unicode_convertor },
	{ "utf32be", "UTF-32BE", open_unicode_convertor },
	{ "utf32le", "UTF-32LE", open_unicode_convertor },
	{ "ucs4", "UTF-32", open_unicode_convertor },
	{ "ucs4be", "UTF-32BE", open_unicode_convertor },
	{ "ucs4le", "UTF-32LE", open_unicode_convertor }};



charconv_t *charconv_open_convertor(const char *name, int utf_type, int flags, int *error) {
	char name_buffer[128];
	const char *ptr;
	size_t i, store_idx;
	t3_bool last_was_digit = t3_false;

	if (utf_type < 0 || utf_type >= UTFMAX) {
		if (error != NULL)
			*error = T3_ERR_BAD_ARG;
		return NULL;
	}

	/*FIXME: replace tolower, isalnum and isdigit by appropriate versions that are not locale dependent? */
	for (ptr = name; *ptr != 0 && store_idx < 127; ptr++) {
		if (!isalnum(*ptr)) {
			last_was_digit = t3_false;
		} else {
			if (!last_was_digit && *ptr == '0')
				continue;
			name_buffer[store_idx++] = tolower(*ptr);
			last_was_digit = isdigit(*ptr);
		}
	}
	name_buffer[store_idx] = 0;

	//FIXME use sorted list instead!!
	for (i = 0; i < sizeof(convertors) / sizeof(convertors[0]); i++) {
		if (strcmp(name_buffer, convertors[i].squashed_name) == 0) {
			if (convertors[i].open != NULL)
				return convertors[i].open(convertors[i].convertor_name, utf_type, flags, error);
			name = convertors[i].convertor_name;
		}
	}

	return open_cct_convertor(name, utf_type, flags, error);
}

void charconv_close_convertor(charconv_t *handle) {
	if (handle != NULL)
		handle->close(handle);
}

int charconv_to_unicode(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags) {
	return handle->convert_to(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags | (handle->flags & 0xff));
}

int charconv_from_unicode(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags) {
	return handle->convert_from(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags | (handle->flags & 0xff));
}

int charconv_to_unicode_skip(charconv_t *handle, char **inbuf, size_t *inbytesleft) {
	return handle->skip_to(handle, inbuf, inbytesleft);
}

int charconv_from_unicode_skip(charconv_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->get_unicode(inbuf, inbytesleft, t3_true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

void charconv_to_unicode_reset(charconv_t *handle) {
	handle->reset_to(handle);
}

void charconv_from_unicode_reset(charconv_t *handle) {
	handle->reset_from(handle);
}

size_t charconv_get_saved_state_size(void) {
	//FIXME: return max of all possible values (and cache)
	return get_cct_saved_state_size();
}

void charconv_save_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

void charconv_load_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

