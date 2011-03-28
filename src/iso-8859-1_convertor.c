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
#include "charconv_internal.h"
#include "utf.h"
#include "generic_fallbacks.h"

typedef struct {
	charconv_common_t common;
	unsigned int charmax;
} convertor_state_t;

static void close_convertor(charconv_common_t *handle);

static charconv_error_t to_unicode_conversion(convertor_state_t *handle, char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;

	while ((*inbuf) < inbuflimit) {
		codepoint = *(uint8_t *) *inbuf;
		if (codepoint > handle->charmax) {
			if (flags & CHARCONV_SUBST_ILLEGAL)
				codepoint = 0x1a;
			else
				return CHARCONV_ILLEGAL;
		}
		if (handle->common.put_unicode(codepoint, outbuf, outbuflimit) == CHARCONV_NO_SPACE)
			return CHARCONV_NO_SPACE;
		(*inbuf)++;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}

static charconv_error_t to_unicode_skip(charconv_common_t *handle, char **inbuf, const char const *inbuflimit) {
	(void) handle;

	if ((*inbuf) >= inbuflimit)
		return CHARCONV_INCOMPLETE;
	(*inbuf)++;
	return CHARCONV_SUCCESS;
}

static charconv_error_t from_unicode_conversion(convertor_state_t *handle, char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;

	while ((*inbuf) < inbuflimit) {
		codepoint = handle->common.get_unicode((const char **) &_inbuf, inbuflimit, false);
		switch (codepoint) {
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBST_ILLEGAL))
						return CHARCONV_ILLEGAL_END;
					codepoint = 0x1a;
					break;
				}
				return CHARCONV_INCOMPLETE;
			default:
				if (codepoint > handle->charmax) {
					if ((codepoint = get_generic_fallback(codepoint)) <= handle->charmax) {
						if (!(flags & CHARCONV_ALLOW_FALLBACK))
							return CHARCONV_FALLBACK;
					} else if (flags & CHARCONV_SUBST_UNASSIGNED) {
						codepoint = 0x1a;
					} else {
						return CHARCONV_UNASSIGNED;
					}
				}
				break;
		}

		if ((*outbuf) >= outbuflimit)
			return CHARCONV_NO_SPACE;
		**outbuf = codepoint;
		(*outbuf)++;

		*inbuf = (char *) _inbuf;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}


static charconv_error_t flush_nop(charconv_t *handle, char **outbuf, const char *outbuflimit) {
	(void) handle;
	(void) outbuf;
	(void) outbuflimit;

	return CHARCONV_SUCCESS;
}

static void reset_nop(charconv_common_t *handle) {
	(void) handle;
}

static void save_load_nop(charconv_common_t *handle, void *state) {
	(void) handle;
	(void) state;
}

void *_charconv_open_iso8859_1_convertor(const char *name, int flags, int *error) {
	convertor_state_t *retval;

	if (strcmp(name, "iso88591") != 0 && strcmp(name, "ascii") != 0) {
		if (error != NULL)
			*error = CHARCONV_INTERNAL_ERROR;
		return NULL;
	}

	if (flags & CHARCONV_PROBE_ONLY)
		return (void *) 1;

	if ((retval = malloc(sizeof(convertor_state_t))) == 0) {
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		return NULL;
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = (flush_func_t) flush_nop;
	retval->common.reset_from = (reset_func_t) reset_nop;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) reset_nop;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_convertor;
	retval->common.save = (save_func_t) save_load_nop;
	retval->common.load = (load_func_t) save_load_nop;
	retval->charmax = strcmp(name, "ascii") == 0 ? 0x7f : 0xff;
	return retval;
}

static void close_convertor(charconv_common_t *handle) {
	free(handle);
}

size_t get_iso8859_1_saved_state_size(void) {
	return 0;
}
