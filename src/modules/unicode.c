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

#include <transcript/static_assert.h>
#include "unicode.h"

static_assert(sizeof(state_t) <= TRANSCRIPT_SAVE_STATE_SIZE);

/** @internal
    @struct name_to_utftype
    @brief Struct to hold mappings from strings to numeric type description for Unicode convertors.
*/
typedef struct {
	const char *name;
	int utf_type;
} name_to_utftype;

/* Mapping from name to integer constant. */
static const name_to_utftype map[] = {
	{ "utf8", _TRANSCRIPT_UTF8_LOOSE },
	{ "utf8bom", _TRANSCRIPT_UTF8_BOM },
	{ "utf16", TRANSCRIPT_UTF16 },
	{ "utf16be", TRANSCRIPT_UTF16BE },
	{ "utf16le", TRANSCRIPT_UTF16LE },
	{ "utf16nobom", _TRANSCRIPT_UTF16_NOBOM },
	{ "utf16bebom", _TRANSCRIPT_UTF16BE_BOM },
	{ "utf16lebom", _TRANSCRIPT_UTF16LE_BOM },
	{ "utf32", TRANSCRIPT_UTF32 },
	{ "utf32be", TRANSCRIPT_UTF32BE },
	{ "utf32le", TRANSCRIPT_UTF32LE },
	{ "utf32nobom", _TRANSCRIPT_UTF32_NOBOM },
	{ "utf32bebom", _TRANSCRIPT_UTF32BE_BOM },
	{ "utf32lebom", _TRANSCRIPT_UTF32LE_BOM },
	{ "cesu8", _TRANSCRIPT_CESU8 },
	{ "gb18030", _TRANSCRIPT_GB18030 },
	/* Disabled for now { "scsu", _TRANSCRIPT_SCSU }, */
	{ "utf7", _TRANSCRIPT_UTF7 }
};

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
		/* FIXME: do we really want to check this on output as well? For now we
		   assume we do, because writing private use characters is not really
		   something one should do. Other programs will have no idea what the
		   character is supposed to be. */
		if (((codepoint >= UINT32_C(0xe000) && codepoint <= UINT32_C(0xf8ff)) ||
				/* The code point is valid, so we can summarize the two ranges from
				   0xf0000-0xffffd and 0x100000-0x10fffd. Furthermore, we don't have
				   to check for the end of the Unicode range either. */
				codepoint >= UINT32_C(0xf0000)) && !(flags & TRANSCRIPT_ALLOW_PRIVATE_USE))
			return TRANSCRIPT_PRIVATE_USE;

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

		if (handle->utf_type == TRANSCRIPT_UTF32 || handle->utf_type == TRANSCRIPT_UTF16 ||
				handle->utf_type == _TRANSCRIPT_UTF32_NOBOM || handle->utf_type == _TRANSCRIPT_UTF16_NOBOM)
		{
			get_unicode_func_t get_le, get_be;

			if (handle->utf_type == TRANSCRIPT_UTF32 || handle->utf_type == _TRANSCRIPT_UTF32_NOBOM) {
				get_be = _transcript_get_get_unicode(TRANSCRIPT_UTF32BE);
				get_le = _transcript_get_get_unicode(TRANSCRIPT_UTF32LE);
			} else {
				get_be = _transcript_get_get_unicode(TRANSCRIPT_UTF16BE);
				get_le = _transcript_get_get_unicode(TRANSCRIPT_UTF16LE);
			}

			codepoint = get_be((const char **) &_inbuf, inbuflimit, false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->to_unicode_get = get_be;
			} else if (codepoint == TRANSCRIPT_ILLEGAL) {
				codepoint = get_le((const char **) &_inbuf, inbuflimit, false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->to_unicode_get = get_le;
				else
					handle->to_unicode_get = get_be;
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
		case _TRANSCRIPT_UTF16_NOBOM:
			handle->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF16BE);
			break;
		case TRANSCRIPT_UTF32:
		case _TRANSCRIPT_UTF32_NOBOM:
			handle->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF32BE);
			break;
		case _TRANSCRIPT_UTF7:
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
			case _TRANSCRIPT_UTF16BE_BOM:
			case _TRANSCRIPT_UTF16LE_BOM:
			case _TRANSCRIPT_UTF32BE_BOM:
			case _TRANSCRIPT_UTF32LE_BOM:
			case _TRANSCRIPT_UTF8_BOM:
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
	if (handle->utf_type == _TRANSCRIPT_UTF7) {
		handle->state.utf7_put_mode = UTF7_MODE_DIRECT;
		handle->state.utf7_put_save = 0;
	}
}

/** save implementation for Unicode convertors. */
static void save_state(convertor_state_t *handle, void *state) {
	memcpy(state, &handle->state, sizeof(state_t));
}

/** load implementation for Unicode convertors. */
static void load_state(convertor_state_t *handle, void *state) {
	memcpy(&handle->state, state, sizeof(state_t));
}

/** Compare function for lfind. */
static int compare(const char *key, const name_to_utftype *ptr) {
	return strcmp(key, ptr->name);
}

/** @internal
    @brief Create a convertor handle for a Unicode convertor
    @param name The name of the convertor.
    @param flags Flags for the convertor.
    @param error The location to store an error.
*/
TRANSCRIPT_EXPORT transcript_t *transcript_open_unicode(const char *name, int flags, transcript_error_t *error) {
	convertor_state_t *retval;
	name_to_utftype *ptr;
	size_t array_size = TRANSCRIPT_ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(map[0]),
			(int (*)(const void *, const void *)) compare)) == NULL)
	{
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_ERROR;
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
		return NULL;
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = NULL;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = NULL;
	retval->common.save = NULL;
	retval->common.load = NULL;

	retval->utf_type = ptr->utf_type;

	switch (retval->utf_type) {
		case TRANSCRIPT_UTF16:
		case _TRANSCRIPT_UTF16_NOBOM:
			retval->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF16BE);
			retval->from_unicode_put = _transcript_get_put_unicode(TRANSCRIPT_UTF16BE);
			break;
		case TRANSCRIPT_UTF32:
		case _TRANSCRIPT_UTF32_NOBOM:
			retval->to_unicode_get = _transcript_get_get_unicode(TRANSCRIPT_UTF32BE);
			retval->from_unicode_put = _transcript_get_put_unicode(TRANSCRIPT_UTF32BE);
			break;
		case _TRANSCRIPT_GB18030:
		case _TRANSCRIPT_SCSU:
		case _TRANSCRIPT_UTF7:
			break;
		default:
			retval->to_unicode_get = _transcript_get_get_unicode(retval->utf_type);
			retval->from_unicode_put = _transcript_get_put_unicode(retval->utf_type);
			break;
	}
	switch (retval->utf_type) {
		case _TRANSCRIPT_GB18030:
			if ((retval->gb18030_table_conv = transcript_open_convertor_nolock("gb18030table", TRANSCRIPT_UTF32, flags | TRANSCRIPT_INTERNAL, error)) == NULL) {
				free(retval);
				return NULL;
			}
			retval->common.close = (close_func_t) close_convertor;
			retval->gb18030_table_conv->get_unicode = _transcript_get_get_unicode(_TRANSCRIPT_UTF32_NO_CHECK);
			retval->to_get = _transcript_get_gb18030;
			retval->from_put = _transcript_put_gb18030;
			break;
		case _TRANSCRIPT_SCSU:
			break;
		case _TRANSCRIPT_UTF7:
			retval->common.flush_from = _transcript_from_unicode_flush_utf7;
			retval->common.save = (save_load_func_t) save_state;
			retval->common.load = (save_load_func_t) load_state;
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

	return (transcript_t *) retval;
}

TRANSCRIPT_EXPORT bool transcript_probe_unicode(const char *name) {
	name_to_utftype *ptr;
	size_t array_size = TRANSCRIPT_ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(map[0]),
			(int (*)(const void *, const void *)) compare)) == NULL)
		return false;

	if (ptr->utf_type == _TRANSCRIPT_GB18030)
		return transcript_probe_convertor_nolock("gb18030table");

	return true;
}

/** close implementation for Unicode convertors. */
static void close_convertor(convertor_state_t *handle) {
	transcript_close_convertor(handle->gb18030_table_conv);
}

TRANSCRIPT_EXPORT int transcript_get_iface_unicode(void) { return TRANSCRIPT_FULL_MODULE_V1; }
TRANSCRIPT_EXPORT const char * const *transcript_namelist_unicode(void) {
	static const char * const namelist[] = {
		"UTF-8", "UTF-8-BOM", "UTF-16", "UTF-16-NoBOM", "UTF-16BE", "UTF-16LE"
		"UTF-32", "UTF-32-NOBOM", "UTF-32BE", "UTF-32LE", "UTF-16BE-BOM",
		"UTF-16LE-BOM", "UTF-32BE-BOM", "UTF-32LE-BOM", "UTF-7", "SCSU", "CESU-8",
		"GB18030", NULL
	};
	return namelist;
}
