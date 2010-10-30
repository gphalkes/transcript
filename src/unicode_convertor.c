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

/* This convertor is a wrapper around the functions in utf.c and other get/put
   functions for unicode encodings, such as UTF-7 and GB-18030. */
#include <string.h>
#include <search.h>

#include "charconv.h"
#include "charconv_internal.h"
#include "unicode_convertor.h"
#include "convertors.h"
#include "utf.h"


typedef struct {
	const char *name;
	int utf_type;
} name_to_utftype;


static int to_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft);
static int from_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft);
static void close_convertor(convertor_state_t *handle);


static int put_common(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
	return handle->common.put_unicode(codepoint, outbuf, outbytesleft);
}
static uint_fast32_t get_common(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip) {
	return handle->common.get_unicode(inbuf, inbytesleft, skip);
}
static int put_from_unicode(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, size_t *outbytesleft) {
	return handle->from_unicode_put(codepoint, outbuf, outbytesleft);
}
static uint_fast32_t get_to_unicode(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip) {
	return handle->to_unicode_get(inbuf, inbytesleft, skip);
}


static int unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags, get_func_t get_unicode, put_func_t put_unicode, flush_func_t flush)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	int result;

	while (*inbytesleft > 0) {
		codepoint = get_unicode(handle, (char **) &_inbuf, &_inbytesleft, false);
		switch (codepoint) {
			case CHARCONV_UTF_INTERNAL_ERROR:
				return CHARCONV_INTERNAL_ERROR;
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBST_ILLEGAL))
						return CHARCONV_ILLEGAL_END;
					if ((result = put_unicode(handle, UINT32_C(0xfffd), outbuf, outbytesleft)) != 0)
						return result;
					*inbuf -= *inbytesleft;
					*inbytesleft = 0;
					if ((result = flush(handle, outbuf, outbytesleft)) != 0)
						return result;
					return CHARCONV_SUCCESS;
				}
				return CHARCONV_INCOMPLETE;
			default:
				break;
		}
		if ((result = put_unicode(handle, codepoint, outbuf, outbytesleft)) != 0)
			return result;
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}

	if (flags & CHARCONV_END_OF_TEXT) {
		if ((result = flush(handle, outbuf, outbytesleft)) != 0)
			return result;
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
					(char **) &_inbuf, &_inbytesleft, false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE);
			} else if (codepoint == CHARCONV_ILLEGAL) {
				codepoint = get_get_unicode(handle->utf_type == UTF32 ? UTF32LE : UTF16LE)(
						(char **) &_inbuf, &_inbytesleft, false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32LE : UTF16LE);
				else
					handle->to_unicode_get = get_get_unicode(handle->utf_type == UTF32 ? UTF32BE : UTF16BE);
			}
		} else {
			codepoint = handle->to_unicode_get((char **) &_inbuf, &_inbytesleft, false);
		}
		/* Anything, including bad input, will simply not cause a pointer update,
		   meaning that only the BOM will be ignored. */
		if (codepoint == UINT32_C(0xFEFF)) {
			*inbuf = (char *) _inbuf;
			*inbytesleft = _inbytesleft;
		}
	}

	return unicode_conversion(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags,
		handle->to_get, put_common, to_unicode_flush);
}

static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->to_unicode_get(inbuf, inbytesleft, true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

static void to_unicode_reset(convertor_state_t *handle) {
	switch (handle->utf_type) {
		case UTF16:
			handle->to_unicode_get = get_get_unicode(UTF16BE);
			break;
		case UTF32:
			handle->to_unicode_get = get_get_unicode(UTF32BE);
			break;
		case UTF7:
			handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
			break;
		default:
			break;
	}
}

static int to_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft) {
	(void) outbuf;
	(void) outbytesleft;

	to_unicode_reset(handle);
	return CHARCONV_SUCCESS;
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
		get_common, handle->from_put, from_unicode_flush);
}

static void from_unicode_reset(convertor_state_t *handle) {
	if (handle->utf_type == UTF7) {
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT;
		handle->state.utf7_put_save = 0;
	}
}

static int from_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft) {
	if (handle->utf_type == UTF7) {
		int result;
		if ((result = from_unicode_flush(handle, outbuf, outbytesleft)) != CHARCONV_SUCCESS)
			return result;
	}
	from_unicode_reset(handle);
	return CHARCONV_SUCCESS;
}

static void save_state(convertor_state_t *handle, void *state) {
	memcpy(state, &handle->state, sizeof(state_t));
}

static void load_state(convertor_state_t *handle, void *state) {
	memcpy(&handle->state, state, sizeof(state_t));
}

void *open_unicode_convertor(const char *name, int flags, charconv_error_t *error) {
	static const name_to_utftype map[] = {
		{ "UTF-8", UTF8_LOOSE },
		{ "UTF-8_BOM", UTF8_BOM },
		{ "UTF-16", UTF16 },
		{ "UTF-16BE", UTF16BE },
		{ "UTF-16LE", UTF16LE },
		{ "UTF-32", UTF32 },
		{ "UTF-32BE", UTF32BE },
		{ "UTF-32LE", UTF32LE },
		{ "CESU-8", CESU8 },
		{ "GB-18030", GB18030 },
		{ "SCSU", SCSU },
		{ "UTF-7", UTF7 }
	};

	convertor_state_t *retval;
	name_to_utftype *ptr;
	size_t array_size = ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(name_to_utftype), element_strcmp)) == NULL) {
		if (error != NULL)
			*error = CHARCONV_INTERNAL_ERROR;
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		return NULL;
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_convertor;
	retval->common.save = (save_func_t) save_state;
	retval->common.load = (load_func_t) load_state;

	retval->utf_type = ptr->utf_type;
	switch (retval->utf_type) {
		case UTF16:
			retval->to_unicode_get = get_get_unicode(UTF16BE);
			retval->from_unicode_put = get_put_unicode(UTF16BE);
			break;
		case UTF32:
			retval->to_unicode_get = get_get_unicode(UTF32BE);
			retval->from_unicode_put = get_put_unicode(UTF32BE);
			break;
		case GB18030:
		case SCSU:
		case UTF7:
			break;
		default:
			retval->to_unicode_get = get_get_unicode(retval->utf_type);
			retval->from_unicode_put = get_put_unicode(retval->utf_type);
			break;
	}
	switch (retval->utf_type) {
		case GB18030:
			if ((retval->gb18030_cct = fill_utf(open_cct_convertor_internal("gb18030", flags, error, true), UTF32)) == NULL) {
				free(retval);
				return NULL;
			}
			retval->gb18030_cct->get_unicode = get_utf32_no_check;
			retval->to_get = get_gb18030;
			retval->from_put = put_gb18030;
			break;
		case SCSU:
			break;
		case UTF7:
			retval->state.utf7_get_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_save = 0;
			retval->to_get = get_utf7;
			retval->from_put = put_utf7;
			break;
		default:
			retval->to_get = get_to_unicode;
			retval->from_put = put_from_unicode;
			break;
	}

	return retval;
}

static void close_convertor(convertor_state_t *handle) {
	free(handle);
}

size_t get_unicode_saved_state_size(void) {
	return sizeof(state_t);
}
