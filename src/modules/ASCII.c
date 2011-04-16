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

/* This convertor implements the ISO-8859-1 and ASCII codepages. */
#include <string.h>
#include <transcript/moduledefs.h>

/** @struct convertor_state_t
    @brief Struct holding the state for the ISO-8859-1/ASCII convertor.
*/
typedef struct {
	transcript_t common;
	unsigned int charmax;
} convertor_state_t;

/** convert_to implementation for ISO-8859-1/ASCII convertors. */
static transcript_error_t to_unicode_conversion(convertor_state_t *handle, char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;

	while ((*inbuf) < inbuflimit) {
		codepoint = *(uint8_t *) *inbuf;
		/* This is the only difference for ISO-8859-1 and ASCII: the value of charmax. */
		if (codepoint > handle->charmax) {
			if (flags & TRANSCRIPT_SUBST_ILLEGAL)
				codepoint = 0x1a;
			else
				return TRANSCRIPT_ILLEGAL;
		}
		if (handle->common.put_unicode(codepoint, outbuf, outbuflimit) == TRANSCRIPT_NO_SPACE)
			return TRANSCRIPT_NO_SPACE;
		(*inbuf)++;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}
	return TRANSCRIPT_SUCCESS;
}

/** skip_to implementation for ISO-8859-1/ASCII convertors. */
static transcript_error_t to_unicode_skip(transcript_t*handle, char **inbuf, const char const *inbuflimit) {
	(void) handle;

	if ((*inbuf) >= inbuflimit)
		return TRANSCRIPT_INCOMPLETE;
	(*inbuf)++;
	return TRANSCRIPT_SUCCESS;
}

/** convert_from implementation for ISO-8859-1/ASCII convertors. */
static transcript_error_t from_unicode_conversion(convertor_state_t *handle, char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;

	while ((*inbuf) < inbuflimit) {
		codepoint = handle->common.get_unicode((const char **) &_inbuf, inbuflimit, false);
		switch (codepoint) {
			case TRANSCRIPT_UTF_ILLEGAL:
				return TRANSCRIPT_ILLEGAL;
			case TRANSCRIPT_UTF_INCOMPLETE:
				if (flags & TRANSCRIPT_END_OF_TEXT) {
					if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
						return TRANSCRIPT_ILLEGAL_END;
					codepoint = 0x1a;
					break;
				}
				return TRANSCRIPT_INCOMPLETE;
			default:
				/* This is the only difference for ISO-8859-1 and ASCII: the value of charmax. */
				if (codepoint > handle->charmax) {
					if ((codepoint = transcript_get_generic_fallback(codepoint)) <= handle->charmax) {
						if (!(flags & TRANSCRIPT_ALLOW_FALLBACK))
							return TRANSCRIPT_FALLBACK;
					} else if (flags & TRANSCRIPT_SUBST_UNASSIGNED) {
						codepoint = 0x1a;
					} else {
						return TRANSCRIPT_UNASSIGNED;
					}
				}
				break;
		}

		if ((*outbuf) >= outbuflimit)
			return TRANSCRIPT_NO_SPACE;
		**outbuf = codepoint;
		(*outbuf)++;

		*inbuf = (char *) _inbuf;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}
	return TRANSCRIPT_SUCCESS;
}

/** @internal
    @brief Open an ISO-8859-1/ASCII convertor.
*/
static void *open_ascii(const char *name, int flags, transcript_error_t *error) {
	convertor_state_t *retval;

	if (strcmp(name, "iso88591") != 0 && strcmp(name, "ascii") != 0) {
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
	retval->common.reset_from = NULL;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = NULL;
	retval->common.flags = flags;
	retval->common.close = NULL;
	retval->common.save = NULL;
	retval->common.load = NULL;
	retval->charmax = strcmp(name, "ascii") == 0 ? 0x7f : 0xff;
	return retval;
}

TRANSCRIPT_ALIAS_OPEN(open_ascii, ascii)
TRANSCRIPT_ALIAS_OPEN(open_ascii, iso88591)
TRANSCRIPT_EXPORT int transcript_get_iface_ascii(void) { return TRANSCRIPT_FULL_MODULE_V1; }
TRANSCRIPT_EXPORT int transcript_get_iface_iso88591(void) { return TRANSCRIPT_FULL_MODULE_V1; }

TRANSCRIPT_EXPORT const char * const *transcript_namelist_ascii(void) {
	static const char * const namelist[] = { "ASCII", "ISO-8859-1", NULL };
	return namelist;
}
