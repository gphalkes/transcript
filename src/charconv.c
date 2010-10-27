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

#define CHARCONV_ICONV_API
#include "charconv.h"
#include "charconv_errors.h"
#include "utf.h"

void *open_cct_convertor(const char *name, int utf_type, int flags, int *error);
size_t get_cct_saved_state_size(void);

void *charconv_open_convertor(const char *name, int utf_type, int flags, int *error) {
	if (utf_type < 0 || utf_type >= UTFMAX) {
		if (error != NULL)
			*error = T3_ERR_BAD_ARG;
		return NULL;
	}

	//FIXME: for now we only have cct based convertors, but we have to handle the others as well!
	return open_cct_convertor(name, utf_type, flags, error);
}

void charconv_close_convertor(charconv_t *handle) {
	if (handle != NULL)
		handle->close(handle);
}

int charconv_to_unicode(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags) {
	return handle->convert_to(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags);
}

int charconv_from_unicode(charconv_t *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags) {
	return handle->convert_from(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags);
}

int charconv_to_unicode_skip(charconv_t *handle, char **inbuf, size_t *inbytesleft) {
	return handle->skip_to(handle, inbuf, inbytesleft);
}

int charconv_from_unicode_skip(charconv_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->get_unicode(inbuf, inbytesleft, t3_true) == CHARCONV_UTF_INCOMPLETE)
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
	//FIXME: return max of all possible values (and cache)
	return get_cct_saved_state_size();
}

void charconv_save_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

void charconv_load_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

/* iconv compatible interface */
#define ERROR(err) do { errno = err; goto end_error; } while (0)
cc_iconv_t cc_iconv_open(const char *tocode, const char *fromcode) {
	cc_iconv_t retval = NULL;
	int error;

	if ((retval = malloc(sizeof(*retval))) == NULL) {
		ERROR(ENOMEM);
		return (cc_iconv_t) -1;
	}
	retval->from = NULL;
	retval->to = NULL;

	if ((retval->from = charconv_open_convertor(fromcode, UTF32ME, 0, &error)) == NULL) {
		if (error == T3_ERR_OUT_OF_MEMORY)
			ERROR(ENOMEM);
		else if (error == T3_ERR_ERRNO)
			ERROR(errno);
		ERROR(EINVAL);
	}

	if ((retval->to = charconv_open_convertor(tocode, UTF32ME, 0, &error)) == NULL) {
		if (error == T3_ERR_OUT_OF_MEMORY)
			ERROR(ENOMEM);
		else if (error == T3_ERR_ERRNO)
			ERROR(errno);
		ERROR(EINVAL);
	}
	return retval;

end_error:
	if (retval == NULL)
		return (cc_iconv_t) -1;

	charconv_close_convertor(retval->from);
	charconv_close_convertor(retval->to);
	return (cc_iconv_t) -1;
}

int cc_iconv_close(cc_iconv_t cd) {
	if (cd == NULL)
		return 0;
	charconv_close_convertor(cd->from);
	charconv_close_convertor(cd->to);
	free(cd);
	return 0;
}


size_t cc_iconv(cc_iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft) {
	size_t result = 0;

	char *_inbuf;
	size_t _inbytesleft;
	char saved_state[charconv_get_saved_state_size()];

	uint32_t codepoint;
	char *codepoint_ptr;
	size_t codepoint_bytesleft;
	t3_bool fallback;

	if (inbuf == NULL || *inbuf == NULL) {
		charconv_to_unicode_reset(cd->from);
		if (outbuf == NULL || *outbuf == NULL)
			charconv_from_unicode_reset(cd->to);
		else
			charconv_from_unicode(cd->to, NULL, NULL, outbuf, outbytesleft, 0);
		return 0;
	}

	_inbuf = *inbuf;
	_inbytesleft = *inbytesleft;

	while (*inbytesleft > 0) {
		charconv_save_state(cd->from, saved_state);
		fallback = t3_false;
		codepoint_ptr = (char *) &codepoint;
		codepoint_bytesleft = 4;
		switch (charconv_to_unicode(cd->from, &_inbuf, &_inbytesleft, &codepoint_ptr,
				&codepoint_bytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_END_OF_TEXT))
		{
			case CHARCONV_ILLEGAL_END:
			case CHARCONV_INCOMPLETE:
				ERROR(EINVAL);
			case CHARCONV_FALLBACK:
				charconv_to_unicode(cd->from, &_inbuf, &_inbytesleft, &codepoint_ptr, &codepoint_bytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_END_OF_TEXT | CHARCONV_ALLOW_FALLBACK);
				fallback = t3_true;
				break;
			case CHARCONV_PRIVATE_USE:
			case CHARCONV_UNASSIGNED:
				codepoint = 0xFFFD;
				charconv_to_unicode_skip(cd->from, &_inbuf, &_inbytesleft);
				fallback = t3_true;
				break;
			case CHARCONV_ILLEGAL:
				ERROR(EILSEQ);
			case CHARCONV_SUCCESS:
				break;
			case CHARCONV_NO_SPACE:
			case CHARCONV_INTERNAL_ERROR:
			default:
				ERROR(EBADF);
		}

		codepoint_ptr = (char *) &codepoint;
		codepoint_bytesleft = 4;
		switch (charconv_from_unicode(cd->to, &codepoint_ptr, &codepoint_bytesleft, outbuf,
				outbytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_END_OF_TEXT))
		{
			case CHARCONV_SUCCESS:
				break;
			case CHARCONV_FALLBACK:
				charconv_from_unicode(cd->from, &codepoint_ptr, &codepoint_bytesleft, outbuf, outbytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_END_OF_TEXT | CHARCONV_ALLOW_FALLBACK);
				fallback = t3_true;
				break;
			case CHARCONV_UNASSIGNED:
			case CHARCONV_PRIVATE_USE:
				charconv_from_unicode(cd->from, &codepoint_ptr, &codepoint_bytesleft, outbuf, outbytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_END_OF_TEXT | CHARCONV_SUBSTITUTE | CHARCONV_SUBSTITUTE_ALL);
				fallback = t3_true;
				break;
			case CHARCONV_ILLEGAL:
			case CHARCONV_ILLEGAL_END:
			case CHARCONV_INTERNAL_ERROR:
			case CHARCONV_INCOMPLETE:
			default:
				ERROR(EBADF);

			case CHARCONV_NO_SPACE:
				ERROR(E2BIG);
		}

		if (fallback)
			result++;
		*inbuf = _inbuf;
		*inbytesleft = _inbytesleft;
	}

	return result;
end_error:
	charconv_load_state(cd->from, saved_state);
	return (size_t) -1;
}
#undef ERROR
