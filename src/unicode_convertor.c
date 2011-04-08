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

#include "transcript_internal.h"
#include "unicode_convertor.h"
#include "convertors.h"
#include "utf.h"
#include "static_assert.h"

static_assert(sizeof(state_t) <= TRANSCRIPT_SAVE_STATE_SIZE);

/** @internal
    @struct name_to_utftype
    @brief Struct to hold mappings from strings to numeric type description for Unicode convertors.
*/
typedef struct {
	const char *name;
	int utf_type;
} name_to_utftype;


static void close_convertor(convertor_state_t *handle);

/** Wrapper routine for @c handle->common.put_unicode to provide a uniform interface across all @c put_xxx routines. */
static int put_common(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	return handle->common.put_unicode(codepoint, outbuf, outbuflimit);
}
/** Wrapper routine for @c handle->common.get_unicode to provide a uniform interface across all @c get_xxx routines. */
static uint_fast32_t get_common(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit, bool skip) {
	return handle->common.get_unicode(inbuf, inbuflimit, skip);
}
/** Wrapper routine for @c handle->from_unicode_put to provide a uniform interface across all @c put_xxx routines. */
static int put_from_unicode(convertor_state_t *handle, uint_fast32_t codepoint, char **outbuf, const char const *outbuflimit) {
	return handle->from_unicode_put(codepoint, outbuf, outbuflimit);
}
/** Wrapper routine for @c handle->to_unicode_get to provide a uniform interface across all @c get_xxx routines. */
static uint_fast32_t get_to_unicode(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit, bool skip) {
	return handle->to_unicode_get(inbuf, inbuflimit, skip);
}

/** Base Unicode to Unicode conversion function.
    @param handle &nbsp;
    @param inbuf &nbsp;
    @param inbuflimit &nbsp;
    @param outbuf &nbsp;
    @param outbuflimit &nbsp;
    @param flags &nbsp;
    @param get_unicode The function to retrieve a Unicode codepoint from @a inbuf.
    @param put_unicode The function to write a Unicode codepoint to @a outbuf.

    This is used both for @c to_unicode and @c from_unicode.
*/
static transcript_error_t unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags, get_func_t get_unicode, put_func_t put_unicode)
{
	uint_fast32_t codepoint;
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	int result;

	while (*inbuf < inbuflimit) {
		codepoint = get_unicode(handle, (const char **) &_inbuf, inbuflimit, false);
		switch (codepoint) {
			case TRANSCRIPT_UTF_INTERNAL_ERROR:
				return TRANSCRIPT_INTERNAL_ERROR;
			case TRANSCRIPT_UTF_ILLEGAL:
				return TRANSCRIPT_ILLEGAL;
			case TRANSCRIPT_UTF_INCOMPLETE:
				if (flags & TRANSCRIPT_END_OF_TEXT) {
					if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
						return TRANSCRIPT_ILLEGAL_END;
					if ((result = put_unicode(handle, UINT32_C(0xfffd), outbuf, outbuflimit)) != 0)
						return result;
					*inbuf = inbuflimit;
					return TRANSCRIPT_SUCCESS;
				}
				return TRANSCRIPT_INCOMPLETE;
			default:
				break;
		}
		if ((result = put_unicode(handle, codepoint, outbuf, outbuflimit)) != 0)
			return result;
		*inbuf = (const char *) _inbuf;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}
	return TRANSCRIPT_SUCCESS;
}

/** convert_to implementation for Unicode convertors. */
static transcript_error_t to_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	if (flags & TRANSCRIPT_FILE_START) {
		uint_fast32_t codepoint = 0;
		const uint8_t *_inbuf = (const uint8_t *) *inbuf;

		if (handle->utf_type == TRANSCRIPT_UTF32 || handle->utf_type == TRANSCRIPT_UTF16) {
			codepoint = _transcript_get_get_unicode(handle->utf_type == TRANSCRIPT_UTF32 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF16BE)(
					(const char **) &_inbuf, inbuflimit, false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->to_unicode_get = _transcript_get_get_unicode(handle->utf_type == TRANSCRIPT_UTF32 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF16BE);
			} else if (codepoint == TRANSCRIPT_ILLEGAL) {
				codepoint = _transcript_get_get_unicode(handle->utf_type == TRANSCRIPT_UTF32 ? TRANSCRIPT_UTF32LE : TRANSCRIPT_UTF16LE)(
						(const char **) &_inbuf, inbuflimit, false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->to_unicode_get = _transcript_get_get_unicode(handle->utf_type == TRANSCRIPT_UTF32 ? TRANSCRIPT_UTF32LE : TRANSCRIPT_UTF16LE);
				else
					handle->to_unicode_get = _transcript_get_get_unicode(handle->utf_type == TRANSCRIPT_UTF32 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF16BE);
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

/** skip_to implementation for Unicode convertors. */
static transcript_error_t to_unicode_skip(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit) {
	if (handle->to_unicode_get(inbuf, inbuflimit, true) == TRANSCRIPT_UTF_INCOMPLETE)
		return TRANSCRIPT_INCOMPLETE;
	return TRANSCRIPT_SUCCESS;
}

/** reset_to implementation for Unicode convertors. */
static void to_unicode_reset(convertor_state_t *handle) {
	switch (handle->utf_type) {
		case TRANSCRIPT_UTF16:
			handle->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF16BE);
			break;
		case TRANSCRIPT_UTF32:
			handle->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF32BE);
			break;
		case UTF7:
			handle->state.utf7_get_mode = UTF7_MODE_DIRECT;
			break;
		default:
			break;
	}
}

/** convert_from implementation for Unicode convertors. */
static int from_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	if (inbuf == NULL || *inbuf == NULL)
		return TRANSCRIPT_SUCCESS;

	if (flags & TRANSCRIPT_FILE_START) {
		switch (handle->utf_type) {
			case TRANSCRIPT_UTF32:
			case TRANSCRIPT_UTF16:
			case UTF8_BOM:
				if (handle->from_unicode_put(UINT32_C(0xFEFF), outbuf, outbuflimit) == TRANSCRIPT_NO_SPACE)
					return TRANSCRIPT_NO_SPACE;
				break;
			default:
				break;
		}
	}

	return unicode_conversion(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags,
		get_common, handle->from_put);
}

/** reset_from implementation for Unicode convertors. */
static void from_unicode_reset(convertor_state_t *handle) {
	if (handle->utf_type == UTF7) {
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT;
		handle->state.utf7_put_save = 0;
	}
}

/** flush_from implementation for Unicode convertors. */
static transcript_error_t from_unicode_flush(convertor_state_t *handle, char **outbuf, const char const *outbuflimit) {
	if (handle->utf_type == UTF7)
		return _transcript_from_unicode_flush_utf7(handle, outbuf, outbuflimit);
	return TRANSCRIPT_SUCCESS;
}

/** save implementation for Unicode convertors. */
static void save_state(convertor_state_t *handle, void *state) {
	memcpy(state, &handle->state, sizeof(state_t));
}

/** load implementation for Unicode convertors. */
static void load_state(convertor_state_t *handle, void *state) {
	memcpy(&handle->state, state, sizeof(state_t));
}

/** @internal
    @brief Create a convertor handle for a Unicode convertor
    @param name The name of the convertor.
    @param flags Flags for the convertor.
    @param error The location to store an error.
*/
void *_transcript_open_unicode_convertor(const char *name, int flags, transcript_error_t *error) {
	static const name_to_utftype map[] = {
		{ "utf8", UTF8_LOOSE },
		{ "utf8,bom", UTF8_BOM },
		{ "utf16", TRANSCRIPT_UTF16 },
		{ "utf16be", TRANSCRIPT_UTF16BE },
		{ "utf16le", TRANSCRIPT_UTF16LE },
		{ "utf32", TRANSCRIPT_UTF32 },
		{ "utf32be", TRANSCRIPT_UTF32BE },
		{ "utf32le", TRANSCRIPT_UTF32LE },
		{ "cesu8", CESU8 },
		{ "gb18030", GB18030 },
		/* Disabled for now { "scsu", SCSU }, */
		{ "utf7", UTF7 }
	};

	convertor_state_t *retval;
	name_to_utftype *ptr;
	size_t array_size = ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(name_to_utftype), (int (*)(const void *, const void *)) strcmp)) == NULL) {
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_ERROR;
		return NULL;
	}

	if (flags & TRANSCRIPT_PROBE_ONLY) {
		if (ptr->utf_type == GB18030) {
			FILE *file;
			if ((file = _transcript_db_open("_gb18030", ".cct", NULL)) == NULL)
				return NULL;
			fclose(file);
		}
		return (void *) 1;
	}


	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
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
		case TRANSCRIPT_UTF16:
			retval->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF16BE);
			retval->from_unicode_put = _transcript_get_put_unicode(TRANSCRIPT_UTF16BE);
			break;
		case TRANSCRIPT_UTF32:
			retval->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF32BE);
			retval->from_unicode_put = _transcript_get_put_unicode(TRANSCRIPT_UTF32BE);
			break;
		case GB18030:
		case SCSU:
		case UTF7:
			break;
		default:
			retval->to_unicode_get = _transcript_get_get_unicode(retval->utf_type);
			retval->from_unicode_put = _transcript_get_put_unicode(retval->utf_type);
			break;
	}
	switch (retval->utf_type) {
		case GB18030:
			if ((retval->gb18030_cct = _transcript_fill_utf(
					_transcript_open_cct_convertor_internal("_gb18030", flags, error, true), TRANSCRIPT_UTF32)) == NULL) {
				free(retval);
				return NULL;
			}
			retval->gb18030_cct->get_unicode = _transcript_get_utf32_no_check;
			retval->to_get = _transcript_get_gb18030;
			retval->from_put = _transcript_put_gb18030;
			break;
		case SCSU:
			break;
		case UTF7:
			retval->state.utf7_get_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_mode = UTF7_MODE_DIRECT;
			retval->state.utf7_put_save = 0;
			retval->to_get = _transcript_get_utf7;
			retval->from_put = _transcript_put_utf7;
			break;
		default:
			retval->to_get = get_to_unicode;
			retval->from_put = put_from_unicode;
			break;
	}

	return retval;
}

/** close implementation for Unicode convertors. */
static void close_convertor(convertor_state_t *handle) {
	free(handle);
}
