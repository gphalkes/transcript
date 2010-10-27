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

/* This convertor is a wrapper around the functions in utf.c. */
#include <string.h>
#include "charconv.h"
#include "charconv_errors.h"
#include "utf.h"

typedef struct {
	const char *name;
	int utfcode;
} name_to_utfcode;

typedef struct {
	charconv_common_t common;
	put_unicode_func_t from_unicode_put;
	get_unicode_func_t to_unicode_get;
} convertor_state_t;

static void close_unicode_convertor(convertor_state_t *handle);

//FIXME: there is too much overlap in the code not to merge to and from unicode conversion

static int to_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;

	//FIXME: do BOM stuff

	while (*inbytesleft > 0) {
		codepoint = handle->to_unicode_get((char **) &_inbuf, &_inbytesleft, t3_false);
		switch (codepoint) {
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBSTITUTE_ALL))
						return CHARCONV_ILLEGAL_END;
					if (handle->common.put_unicode(UINT32_C(0xfffd), outbuf, outbytesleft) == CHARCONV_NO_SPACE)
						return CHARCONV_NO_SPACE;
					*inbuf -= *inbytesleft;
					*inbytesleft = 0;
					return CHARCONV_SUCCESS;
				}
				return CHARCONV_INCOMPLETE;
			default:
				break;
		}
		if (handle->common.put_unicode(codepoint, outbuf, outbytesleft) == CHARCONV_NO_SPACE)
			return CHARCONV_NO_SPACE;
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}

static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->to_unicode_get(inbuf, inbytesleft, t3_true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

static int from_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;

	//FIXME: do BOM stuff

	while (*inbytesleft > 0) {
		codepoint = handle->common.get_unicode((char **) &_inbuf, &_inbytesleft, t3_false);
		switch (codepoint) {
			case CHARCONV_UTF_ILLEGAL:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBSTITUTE_ALL))
						return CHARCONV_ILLEGAL_END;
					if (handle->common.put_unicode(UINT32_C(0xfffd), outbuf, outbytesleft) == CHARCONV_NO_SPACE)
						return CHARCONV_NO_SPACE;
					*inbuf -= *inbytesleft;
					*inbytesleft = 0;
					return CHARCONV_SUCCESS;
				}
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				return CHARCONV_INCOMPLETE;
			default:
				break;
		}
		if (handle->from_unicode_put(codepoint, outbuf, outbytesleft) == CHARCONV_NO_SPACE)
			return CHARCONV_NO_SPACE;
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}

	return CHARCONV_SUCCESS;
}

static void reset_nop(convertor_state_t *handle) {
	(void) handle;
}

static void save_load_nop(convertor_state_t *handle, void *state) {
	(void) handle;
	(void) state;
}

void *open_unicode_convertor(const char *name, int utf_type, int flags, int *error) {
	static const name_to_utfcode map[] = {
		{ "UTF-8", UTF8 },
		{ "UTF-8BOM", UTF8_BOM },
		{ "UTF-16", UTF16 },
		{ "UTF-16BE", UTF16BE },
		{ "UTF-16LE", UTF16LE },
		{ "UTF-32", UTF32 },
		{ "UTF-32BE", UTF32BE },
		{ "UTF-32LE", UTF32LE }
	};

	convertor_state_t *retval;
	size_t i;

	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		if (strcmp(name, map[i].name) == 0)
			break;
	}

	if (i == sizeof(map) / sizeof(map[0])) {
		if (error != NULL)
			*error = T3_ERR_TERMINFODB_NOT_FOUND;
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = T3_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.get_unicode = get_get_unicode(utf_type);
	retval->common.reset_from = (reset_func_t) reset_nop;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.put_unicode = get_put_unicode(utf_type);
	retval->common.reset_to = (reset_func_t) reset_nop;
	retval->common.flags = flags;
	retval->common.utf_type = utf_type;
	retval->common.close = (close_func_t) close_unicode_convertor;
	retval->common.save = (save_func_t) save_load_nop;
	retval->common.load = (load_func_t) save_load_nop;
	return retval;
}

static void close_unicode_convertor(convertor_state_t *handle) {
	free(handle);
}

size_t get_unicode_saved_state_size(void) {
	return 0;
}
