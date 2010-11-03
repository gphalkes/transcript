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
#include "charconv_internal.h"
#include "utf.h"

/* iconv compatible interface */
#define ERROR(err) do { errno = err; goto end_error; } while (0)
cc_iconv_t cc_iconv_open(const char *tocode, const char *fromcode) {
	cc_iconv_t retval = NULL;
	charconv_error_t error;

	if ((error = charconv_init()) != CHARCONV_SUCCESS)
		ERROR(EBADF); /* Use EBADF as "internal error" */

	if ((retval = malloc(sizeof(*retval))) == NULL)
		ERROR(ENOMEM);

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

	uint32_t codepoints[20];
	char *codepoint_ptr;
	size_t codepoint_bytesleft;
	bool non_reversible;

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

		switch (charconv_from_unicode_flush(cd->to, outbuf, outbytesleft))
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
		non_reversible = false;
		codepoint_ptr = (char *) &codepoints;
		codepoint_bytesleft = sizeof(codepoints);
		/* Convert a single character of the input, by forcing a single conversion. */
		switch (charconv_to_unicode(cd->from, &_inbuf, &_inbytesleft, &codepoint_ptr,
				&codepoint_bytesleft, CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION))
		{
			case CHARCONV_ILLEGAL_END:
			case CHARCONV_INCOMPLETE:
				ERROR(EINVAL);
			case CHARCONV_FALLBACK:
				charconv_to_unicode(cd->from, &_inbuf, &_inbytesleft, &codepoint_ptr, &codepoint_bytesleft,
						CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_MN_CONVERSION | CHARCONV_ALLOW_FALLBACK);
				non_reversible = true;
				break;
			case CHARCONV_PRIVATE_USE:
			case CHARCONV_UNASSIGNED:
				codepoints[0] = 0xFFFD;
				codepoint_bytesleft = sizeof(codepoints) - sizeof(codepoints[0]);
				charconv_to_unicode_skip(cd->from, &_inbuf, &_inbytesleft);
				non_reversible = true;
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

		/* Only try to convert if the previous conversion yielded any codepoints. */
		if (codepoint_bytesleft < sizeof(codepoints)) {

			/* If the previous conversion yielded more than one codepoint, the
			   conversion is definately non_reversible. */
			if (codepoint_bytesleft < sizeof(codepoints) - sizeof(codepoints[0]))
				non_reversible = true;

			codepoint_ptr = (char *) &codepoints;
			codepoint_bytesleft = sizeof(codepoints) - codepoint_bytesleft;
		try_again:
			/* Try to convert. If so far the conversion is reversible, try without substitutions and fallbacks first. */
			switch (charconv_from_unicode(cd->to, &codepoint_ptr, &codepoint_bytesleft, outbuf,
					outbytesleft, CHARCONV_NO_1N_CONVERSION |
					(non_reversible ? CHARCONV_SUBST_UNASSIGNED | CHARCONV_SUBST_ILLEGAL | CHARCONV_ALLOW_FALLBACK : 0)))
			{
				case CHARCONV_SUCCESS:
					break;
				case CHARCONV_FALLBACK:
				case CHARCONV_UNASSIGNED:
				case CHARCONV_PRIVATE_USE:
					/* Apparently, we couldn't convert (all) the characters, so this counts as
					   as a non-reversible conversion. */
					if (non_reversible)
						/* We shouldn't be able to get here! Return "internal error". */
						ERROR(EBADF);
					non_reversible = true;
					goto try_again;
				case CHARCONV_NO_SPACE:
					ERROR(E2BIG);
				/* None of the other errors should happen, as we feed it only valid codepoints. So
				   we handle all of them as internal errors. */
				default:
					ERROR(EBADF);
			}
		}

		if (non_reversible) {
			result++;
			non_reversible = false;
		}
		*inbuf = _inbuf;
		*inbytesleft = _inbytesleft;
	}

	return result;
end_error:
	charconv_load_state(cd->from, saved_state);
	return (size_t) -1;
}
#undef ERROR
