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
#include "charconv_internal.h"
#include "utf.h"

/* iconv compatible interface */
#define ERROR(err) do { errno = err; goto end_error; } while (0)
cc_iconv_t cc_iconv_open(const char *tocode, const char *fromcode) {
	cc_iconv_t retval = NULL;
	charconv_error_t error;

	if ((retval = malloc(sizeof(*retval))) == NULL) {
		ERROR(ENOMEM);
		return (cc_iconv_t) -1;
	}
	retval->from = NULL;
	retval->to = NULL;

	if ((retval->from = charconv_open_convertor(fromcode, UTF32, 0, &error)) == NULL) {
		if (error == CHARCONV_OUT_OF_MEMORY)
			ERROR(ENOMEM);
		else if (error == CHARCONV_ERRNO)
			ERROR(errno);
		ERROR(EINVAL);
	}

	if ((retval->to = charconv_open_convertor(tocode, UTF32, 0, &error)) == NULL) {
		if (error == CHARCONV_OUT_OF_MEMORY)
			ERROR(ENOMEM);
		else if (error == CHARCONV_ERRNO)
			ERROR(errno);
		ERROR(EINVAL);
	}
	/* Because we don't use the M:N conversions, we don't have to perform any checks
	   when retrieving the UTF-32 character in the from_unicode conversion. */
	retval->to->get_unicode = get_utf32_no_check;

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
	/* To implement a compatible interface, we have to convert
	   character-by-character. This is what iconv does as well and otherwise
	   we have to save the intermediate results as well. */
	size_t result = 0;

	char *_inbuf;
	size_t _inbytesleft;
	char saved_state[CHARCONV_SAVE_STATE_SIZE];

	uint32_t codepoint;
	char *codepoint_ptr;
	size_t codepoint_bytesleft;
	bool fallback;

	if (inbuf == NULL || *inbuf == NULL) {
		/* There is no need to convert the input buffer, because even if it had an incomplete
		   seqeunce at the end, that would have been reported on the previous call. A reset
		   is necessary however. */
		charconv_to_unicode_reset(cd->from);

		if (outbuf == NULL || *outbuf == NULL) {
			/* If the user only asks for a reset, make it so. */
			charconv_from_unicode_reset(cd->to);
			return 0;
		}

		codepoint_ptr = (char *) &codepoint;
		codepoint_bytesleft = 0;
		switch (charconv_from_unicode(cd->to, &codepoint_ptr, &codepoint_bytesleft, outbuf, outbytesleft,
				CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION | CHARCONV_END_OF_TEXT))
		{
			case CHARCONV_SUCCESS:
				break;
			case CHARCONV_NO_SPACE:
				ERROR(E2BIG);
			default:
				ERROR(EBADF);
		}
		return 0;
	}

	_inbuf = *inbuf;
	_inbytesleft = *inbytesleft;

	while (*inbytesleft > 0) {
		charconv_save_state(cd->from, saved_state);
		fallback = false;
		codepoint_ptr = (char *) &codepoint;
		codepoint_bytesleft = 4;
		switch (charconv_to_unicode(cd->from, &_inbuf, &_inbytesleft, &codepoint_ptr,
				&codepoint_bytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION))
		{
			case CHARCONV_ILLEGAL_END:
			case CHARCONV_INCOMPLETE:
				ERROR(EINVAL);
			case CHARCONV_FALLBACK:
				charconv_to_unicode(cd->from, &_inbuf, &_inbytesleft, &codepoint_ptr, &codepoint_bytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION | CHARCONV_ALLOW_FALLBACK);
				fallback = true;
				break;
			case CHARCONV_PRIVATE_USE:
			case CHARCONV_UNASSIGNED:
				codepoint = 0xFFFD;
				charconv_to_unicode_skip(cd->from, &_inbuf, &_inbytesleft);
				fallback = true;
				break;
			case CHARCONV_ILLEGAL:
				ERROR(EILSEQ);
			case CHARCONV_SUCCESS:
				break;
			/* These should not happen, but we need to handle them anyway. Thus we
			   return EBADF, which is what gconv returns on internal errors as well. */
			case CHARCONV_NO_SPACE:
			case CHARCONV_INTERNAL_ERROR:
			default:
				ERROR(EBADF);
		}

		codepoint_ptr = (char *) &codepoint;
		codepoint_bytesleft = 4;
		switch (charconv_from_unicode(cd->to, &codepoint_ptr, &codepoint_bytesleft, outbuf,
				outbytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION))
		{
			case CHARCONV_SUCCESS:
				break;
			case CHARCONV_FALLBACK:
				charconv_from_unicode(cd->from, &codepoint_ptr, &codepoint_bytesleft, outbuf, outbytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION | CHARCONV_ALLOW_FALLBACK);
				fallback = true;
				break;
			case CHARCONV_UNASSIGNED:
			case CHARCONV_PRIVATE_USE:
				charconv_from_unicode(cd->from, &codepoint_ptr, &codepoint_bytesleft, outbuf, outbytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION | CHARCONV_SUBST_UNASSIGNED | CHARCONV_SUBST_ILLEGAL);
				fallback = true;
				break;
			case CHARCONV_NO_SPACE:
				ERROR(E2BIG);
			/* None of the other errors should happen, as we feed it only valid codepoints. So
			   we handle all of them as internal errors. */
			default:
				ERROR(EBADF);
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
