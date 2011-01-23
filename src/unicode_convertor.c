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

#include "charconv_internal.h"
#include "unicode_convertor.h"
#include "convertors.h"
#include "utf.h"


typedef struct {
	const char *name;
	int utf_type;
} name_to_utftype;


static void close_convertor(convertor_state_t *handle);


static int put_common(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	return handle->common.put_unicode(codepoint, outbuf, outbuflimit);
}
static uint_fast32_t get_common(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit, bool skip) {
	return handle->common.get_unicode(inbuf, inbuflimit, skip);
}
static int put_from_unicode(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	return handle->from_unicode_put(codepoint, outbuf, outbuflimit);
}
static uint_fast32_t get_to_unicode(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit, bool skip) {
	return handle->to_unicode_get(inbuf, inbuflimit, skip);
}


static charconv_error_t unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags, get_func_t get_unicode, put_func_t put_unicode)
{
	uint_fast32_t codepoint;
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	int result;

	while (*inbuf < inbuflimit) {
		codepoint = get_unicode(handle, (const char **) &_inbuf, inbuflimit, false);
		switch (codepoint) {
			case CHARCONV_UTF_INTERNAL_ERROR:
				return CHARCONV_INTERNAL_ERROR;
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBST_ILLEGAL))
						return CHARCONV_ILLEGAL_END;
					if ((result = put_unicode(handle, UINT32_C(0xfffd), outbuf, outbuflimit)) != 0)
						return result;
					*inbuf = inbuflimit;
					return CHARCONV_SUCCESS;
				}
				return CHARCONV_INCOMPLETE;
			default:
				break;
		}
		if ((result = put_unicode(handle, codepoint, outbuf, outbuflimit)) != 0)
			return result;
		*inbuf = (const char *) _inbuf;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}


static charconv_error_t to_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	if (flags & CHARCONV_FILE_START) {
		uint_fast32_t codepoint = 0;
		const uint8_t *_inbuf = (const uint8_t *) *inbuf;

		if (handle->utf_type == CHARCONV_UTF32 || handle->utf_type == CHARCONV_UTF16) {
			codepoint = _charconv_get_get_unicode(handle->utf_type == CHARCONV_UTF32 ? CHARCONV_UTF32BE : CHARCONV_UTF16BE)(
					(const char **) &_inbuf, inbuflimit, false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->to_unicode_get = _charconv_get_get_unicode(handle->utf_type == CHARCONV_UTF32 ? CHARCONV_UTF32BE : CHARCONV_UTF16BE);
			} else if (codepoint == CHARCONV_ILLEGAL) {
				codepoint = _charconv_get_get_unicode(handle->utf_type == CHARCONV_UTF32 ? CHARCONV_UTF32LE : CHARCONV_UTF16LE)(
						(const char **) &_inbuf, inbuflimit, false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->to_unicode_get = _charconv_get_get_unicode(handle->utf_type == CHARCONV_UTF32 ? CHARCONV_UTF32LE : CHARCONV_UTF16LE);
				else
					handle->to_unicode_get = _charconv_get_get_unicode(handle->utf_type == CHARCONV_UTF32 ? CHARCONV_UTF32BE : CHARCONV_UTF16BE);
			}
		} else {
			codepoint = handle->to_unicode_get((const char **) &_inbuf, inbuflimit, false);
		}
		/* Anything, including bad input, will simply not cause a pointer update,
		   meaning that only the BOM will be ignored. */
		if (codepoint == UINT32_C(0xFEFF))
			*inbuf = (const char *) _inbuf;
	}

	return unicode_conversion(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags, handle->to_get, put_common);
}

static charconv_error_t to_unicode_skip(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit) {
	if (handle->to_unicode_get(inbuf, inbuflimit, true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

static void to_unicode_reset(convertor_state_t *handle) {
	switch (handle->utf_type) {
		case CHARCONV_UTF16:
			handle->to_unicode_get = _charconv_get_get_unicode(CHARCONV_UTF16BE);
			break;
		case CHARCONV_UTF32:
			handle->to_unicode_get = _charconv_get_get_unicode(CHARCONV_UTF32BE);
			break;
		case UTF7:
			handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
			break;
		default:
			break;
	}
}

static int from_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	if (inbuf == NULL || *inbuf == NULL)
		return CHARCONV_SUCCESS;

	if (flags & CHARCONV_FILE_START) {
		switch (handle->utf_type) {
			case CHARCONV_UTF32:
			case CHARCONV_UTF16:
			case UTF8_BOM:
				if (handle->from_unicode_put(UINT32_C(0xFEFF), outbuf, outbuflimit) == CHARCONV_NO_SPACE)
					return CHARCONV_NO_SPACE;
				break;
			default:
				break;
		}
	}

	return unicode_conversion(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags,
		get_common, handle->from_put);
}

static void from_unicode_reset(convertor_state_t *handle) {
	if (handle->utf_type == UTF7) {
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT;
		handle->state.utf7_put_save = 0;
	}
}

static charconv_error_t from_unicode_flush(convertor_state_t *handle, char **outbuf, const char const *outbuflimit) {
	if (handle->utf_type == UTF7)
		return _charconv_from_unicode_flush_utf7(handle, outbuf, outbuflimit);
	return CHARCONV_SUCCESS;
}

static void save_state(convertor_state_t *handle, void *state) {
	memcpy(state, &handle->state, sizeof(state_t));
}

static void load_state(convertor_state_t *handle, void *state) {
	memcpy(&handle->state, state, sizeof(state_t));
}

void *_charconv_open_unicode_convertor(const char *name, int flags, charconv_error_t *error) {
	static const name_to_utftype map[] = {
		{ "utf8", UTF8_LOOSE },
		{ "utf8,bom", UTF8_BOM },
		{ "utf16", CHARCONV_UTF16 },
		{ "utf16be", CHARCONV_UTF16BE },
		{ "utf16le", CHARCONV_UTF16LE },
		{ "utf32", CHARCONV_UTF32 },
		{ "utf32be", CHARCONV_UTF32BE },
		{ "utf32le", CHARCONV_UTF32LE },
		{ "cesu8", CESU8 },
		{ "gb18030", GB18030 },
		/* Disabled for now { "scsu", SCSU }, */
		{ "utf7", UTF7 }
	};

	convertor_state_t *retval;
	name_to_utftype *ptr;
	size_t array_size = ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(name_to_utftype), _charconv_element_strcmp)) == NULL) {
		if (error != NULL)
			*error = CHARCONV_INTERNAL_ERROR;
		return NULL;
	}

	if (flags & CHARCONV_PROBE_ONLY) {
		if (ptr->utf_type == GB18030) {
			FILE *file;
			if ((file = _charconv_db_open("gb18030", ".cct", NULL)) == NULL)
				return NULL;
			fclose(file);
		}
		return (void *) 1;
	}


	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		return NULL;
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = (flush_func_t) from_unicode_flush;
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
		case CHARCONV_UTF16:
			retval->to_unicode_get = _charconv_get_get_unicode(CHARCONV_UTF16BE);
			retval->from_unicode_put = _charconv_get_put_unicode(CHARCONV_UTF16BE);
			break;
		case CHARCONV_UTF32:
			retval->to_unicode_get = _charconv_get_get_unicode(CHARCONV_UTF32BE);
			retval->from_unicode_put = _charconv_get_put_unicode(CHARCONV_UTF32BE);
			break;
		case GB18030:
		case SCSU:
		case UTF7:
			break;
		default:
			retval->to_unicode_get = _charconv_get_get_unicode(retval->utf_type);
			retval->from_unicode_put = _charconv_get_put_unicode(retval->utf_type);
			break;
	}
	switch (retval->utf_type) {
		case GB18030:
			if ((retval->gb18030_cct = _charconv_fill_utf(
					_charconv_open_cct_convertor_internal("gb18030", flags, error, true), CHARCONV_UTF32)) == NULL) {
				free(retval);
				return NULL;
			}
			retval->gb18030_cct->get_unicode = _charconv_get_utf32_no_check;
			retval->to_get = _charconv_get_gb18030;
			retval->from_put = _charconv_put_gb18030;
			break;
		case SCSU:
			break;
		case UTF7:
			retval->state.utf7_get_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_save = 0;
			retval->to_get = _charconv_get_utf7;
			retval->from_put = _charconv_put_utf7;
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
