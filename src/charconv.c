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
#include <search.h>

#include "charconv.h"
#include "charconv_internal.h"
#include "utf.h"

#include "convertors.h"

typedef struct {
	const char *squashed_name;
	const char *convertor_name;
	void *(*open)(const char *name, int flags, int *error);
} name_mapping;

//FIXME: we need a list of known convertors and aliases! i.e. read convrtrs.txt
static name_mapping convertors[] = {
	{ "ibm437", "ibm-437_P100-1995", open_cct_convertor },
	{ "ibm437p100", "ibm-437_P100-1995", open_cct_convertor },
	{ "ibm437p1001995", "ibm-437_P100-1995", open_cct_convertor },
	{ "iso88591", "ISO-8859-1", open_iso8859_1_convertor },
	{ "utf8", "UTF-8", open_unicode_convertor },
	{ "utf8bom", "UTF-8_BOM", open_unicode_convertor },
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
	{ "ucs4le", "UTF-32LE", open_unicode_convertor },
	{ "cesu8", "CESU-8", open_unicode_convertor },
	{ "utf7", "UTF-7", open_unicode_convertor },
	{ "gb18030", "GB-18030", open_unicode_convertor }
};

/*================ API functions ===============*/

charconv_t *charconv_open_convertor(const char *name, int utf_type, int flags, int *error) {
	cc_bool last_was_digit = cc_false;
	name_mapping *convertor;
	char name_buffer[128];
	size_t store_idx = 0;
	size_t array_size = ARRAY_SIZE(convertors);
	const char *ptr;

	if (utf_type < 0 || utf_type > UTF32LE) {
		if (error != NULL)
			*error = CHARCONV_BAD_ARG;
		return NULL;
	}

	/*FIXME: replace tolower, isalnum and isdigit by appropriate versions that are not locale dependent? */
	for (ptr = name; *ptr != 0 && store_idx < 127; ptr++) {
		if (!isalnum(*ptr)) {
			last_was_digit = cc_false;
		} else {
			if (!last_was_digit && *ptr == '0')
				continue;
			name_buffer[store_idx++] = tolower(*ptr);
			last_was_digit = isdigit(*ptr);
		}
	}
	name_buffer[store_idx] = 0;

	if ((convertor = lfind(name_buffer, convertors, &array_size, sizeof(name_mapping), element_strcmp)) != NULL) {
		if (convertor->open != NULL)
			return fill_utf(convertor->open(convertor->convertor_name, flags, error), utf_type);
		name = convertor->convertor_name;
	}

	return fill_utf(open_cct_convertor(name, flags, error), utf_type);
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
	if (handle->get_unicode(inbuf, inbytesleft, cc_true) == CHARCONV_UTF_INCOMPLETE)
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
	static size_t cached = 0;
	if (cached == 0) {
		cached = get_unicode_saved_state_size();
		if (get_cct_saved_state_size() > cached)
			cached = get_cct_saved_state_size();
	}
	return cached;
}

void charconv_save_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

void charconv_load_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

/*================ Internal functions ===============*/

charconv_t *fill_utf(charconv_t *handle, int utf_type) {
	if (handle == NULL)
		return NULL;
	handle->get_unicode = get_get_unicode(utf_type);
	handle->put_unicode = get_put_unicode(utf_type);
	return handle;
}

int element_strcmp(const void *a, const void *b) {
	return strcmp((const char *) a, *(char * const *) b);
}
