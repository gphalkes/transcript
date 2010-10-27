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
	int utf_type;
} convertor_state_t;

static void close_unicode_convertor(convertor_state_t *handle);

static int unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags, get_unicode_func_t get_unicode, put_unicode_func_t put_unicode)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;

	while (*inbytesleft > 0) {
		codepoint = get_unicode((char **) &_inbuf, &_inbytesleft, t3_false);
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
		if (put_unicode(codepoint, outbuf, outbytesleft) == CHARCONV_NO_SPACE)
			return CHARCONV_NO_SPACE;
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}


static int to_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	if (flags & CHARCONV_FILE_START) {
		uint_fast32_t codepoint = 0;
		uint8_t *_inbuf = (uint8_t *) *inbuf;
		size_t _inbytesleft = *inbytesleft;

		if (handle->utf_type == UTF32 || handle->utf_type == UTF16) {
			codepoint = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE)(
					(char **) &_inbuf, &_inbytesleft, t3_false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE);
			} else if (codepoint == CHARCONV_ILLEGAL) {
				codepoint = get_get_unicode(handle->utf_type == UTF32 ? UTF32LE : UTF16LE)(
						(char **) &_inbuf, &_inbytesleft, t3_false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32LE : UTF16LE);
				else
					handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE);
			}
		} else {
			codepoint = handle->to_unicode_get((char **) &_inbuf, &_inbytesleft, t3_false);
		}
		/* Anything, including bad input, will simply not cause a pointer update,
		   meaning that only the BOM will be ignored. */
		if (codepoint == UINT32_C(0xFEFF)) {
			*inbuf = (char *) _inbuf;
			*inbytesleft = _inbytesleft;
		}
	}

	return unicode_conversion(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags,
		handle->to_unicode_get, handle->common.put_unicode);
}

static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->to_unicode_get(inbuf, inbytesleft, t3_true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

static void to_unicode_reset(convertor_state_t *handle) {
	if (handle->utf_type == UTF16)
		handle->to_unicode_get = get_get_unicode(UTF16BE);
	else if (handle->utf_type == UTF32)
		handle->to_unicode_get = get_get_unicode(UTF32BE);
}

static int from_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	if (inbuf == NULL || *inbuf == NULL)
		return CHARCONV_SUCCESS;

	if (flags & CHARCONV_FILE_START) {
		switch (handle->utf_type) {
			case UTF32:
			case UTF16:
			case UTF8_BOM:
				if (handle->from_unicode_put(UINT32_C(0xFEFF), outbuf, outbytesleft) == CHARCONV_NO_SPACE)
					return CHARCONV_NO_SPACE;
				break;
			default:
				break;
		}
	}

	return unicode_conversion(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags,
		handle->common.get_unicode, handle->from_unicode_put);
}

static void from_unicode_reset(convertor_state_t *handle) {
	(void) handle;
}

static void save_load_nop(convertor_state_t *handle, void *state) {
	(void) handle;
	(void) state;
}

void *open_unicode_convertor(const char *name, int flags, int *error) {
	static const name_to_utfcode map[] = {
		{ "UTF-8", UTF8_LOOSE },
		{ "UTF-8_BOM", UTF8_BOM },
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
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_unicode_convertor;
	retval->common.save = (save_func_t) save_load_nop;
	retval->common.load = (load_func_t) save_load_nop;
	if (map[i].utfcode == UTF16) {
		retval->to_unicode_get = get_get_unicode(UTF16BE);
		retval->from_unicode_put = get_put_unicode(UTF16BE);
	} else if (map[i].utfcode == UTF32) {
		retval->to_unicode_get = get_get_unicode(UTF32BE);
		retval->from_unicode_put = get_put_unicode(UTF32BE);
	} else {
		retval->to_unicode_get = get_get_unicode(map[i].utfcode);
		retval->from_unicode_put = get_put_unicode(map[i].utfcode);
	}
	retval->utf_type = map[i].utfcode;
	return retval;
}

static void close_unicode_convertor(convertor_state_t *handle) {
	free(handle);
}

size_t get_unicode_saved_state_size(void) {
	return 0;
}
