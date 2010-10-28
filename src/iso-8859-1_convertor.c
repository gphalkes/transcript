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

/* This convertor implements the ISO-8859-1 codepage. */
#include <string.h>
#include "charconv.h"
#include "charconv_errors.h"
#include "charconv_internal.h"
#include "utf.h"

static void close_convertor(charconv_common_t *handle);

static int to_unicode_conversion(charconv_common_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint_fast32_t codepoint;

	while (*inbytesleft > 0) {
		codepoint = **inbuf;
		if (handle->put_unicode(codepoint, outbuf, outbytesleft) == CHARCONV_NO_SPACE)
			return CHARCONV_NO_SPACE;
		(*inbuf)++;
		(*inbytesleft)--;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}

static int to_unicode_skip(charconv_common_t *handle, char **inbuf, size_t *inbytesleft) {
	(void) handle;

	if (*inbytesleft == 0)
		return CHARCONV_INCOMPLETE;
	(*inbuf)++;
	(*inbytesleft)--;
	return CHARCONV_SUCCESS;
}

static int from_unicode_conversion(charconv_common_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint_fast32_t codepoint;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;

	while (*inbytesleft > 0) {
		codepoint = handle->get_unicode((char **) &_inbuf, &_inbytesleft, t3_false);
		switch (codepoint) {
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBSTITUTE_ALL))
						return CHARCONV_ILLEGAL_END;
					codepoint = 0x1a;
					break;
				}
				return CHARCONV_INCOMPLETE;
			default:
				if (codepoint > 0xff) {
					if (flags & CHARCONV_SUBSTITUTE)
						codepoint = 0x1a;
					else
						return CHARCONV_UNASSIGNED;
				}
				break;
		}

		if (*outbytesleft == 0)
			return CHARCONV_NO_SPACE;
		**outbuf = codepoint;
		(*outbuf)++;
		(*outbytesleft)--;

		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}

static void reset_nop(charconv_common_t *handle) {
	(void) handle;
}

static void save_load_nop(charconv_common_t *handle, void *state) {
	(void) handle;
	(void) state;
}

void *open_iso8859_1_convertor(const char *name, int utf_type, int flags, int *error) {
	charconv_common_t *retval;

	(void) name;

	if ((retval = malloc(sizeof(charconv_common_t))) == 0) {
		if (error != NULL)
			*error = T3_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	retval->convert_from = (conversion_func_t) from_unicode_conversion;
	retval->reset_from = (reset_func_t) reset_nop;
	retval->convert_to = (conversion_func_t) to_unicode_conversion;
	retval->skip_to = (skip_func_t) to_unicode_skip;
	retval->reset_to = (reset_func_t) reset_nop;
	retval->flags = flags;
	retval->close = (close_func_t) close_convertor;
	retval->save = (save_func_t) save_load_nop;
	retval->load = (load_func_t) save_load_nop;
	fill_utf(retval, utf_type);
	return retval;
}

static void close_convertor(charconv_common_t *handle) {
	free(handle);
}

size_t get_iso8859_1_saved_state_size(void) {
	return 0;
}
