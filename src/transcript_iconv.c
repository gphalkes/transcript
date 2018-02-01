/* Copyright (C) 2011-2012 G.P. Halkes
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

/** @file */

#include <errno.h>

#define TRANSCRIPT_ICONV_API
#include "transcript_internal.h"
#include "utf.h"

/* iconv compatible interface */
#define ERROR(err)  \
  do {              \
    errno = err;    \
    goto end_error; \
  } while (0)

/** @addtogroup transcript_iconv */
/** @{ */

/** Open a converter (iconv compatibility interface).
    @param tocode Name of the character set to convert to.
    @param fromcode Name of the character set to convert from.
    @return A handle for the conversion state, or @c (transcript_iconv_t) @c -1 on error. On
        error, @c errno is set appropriately.
*/
transcript_iconv_t transcript_iconv_open(const char *tocode, const char *fromcode) {
  transcript_iconv_t retval = NULL;
  transcript_error_t error;

  if ((retval = malloc(sizeof(*retval))) == NULL) ERROR(ENOMEM);

  retval->from = NULL;
  retval->to = NULL;

  /* We need to be sure that transcript_init is called before anything else,
     so we simply call it here. There is no harm in calling it more than once. */
  transcript_init();

  if ((retval->from = transcript_open_converter(fromcode, TRANSCRIPT_UTF32, 0, &error)) == NULL) {
    if (error == TRANSCRIPT_OUT_OF_MEMORY)
      ERROR(ENOMEM);
    else if (error == TRANSCRIPT_ERRNO)
      ERROR(errno);
    ERROR(EINVAL);
  }

  if ((retval->to = transcript_open_converter(tocode, TRANSCRIPT_UTF32, 0, &error)) == NULL) {
    if (error == TRANSCRIPT_OUT_OF_MEMORY)
      ERROR(ENOMEM);
    else if (error == TRANSCRIPT_ERRNO)
      ERROR(errno);
    ERROR(EINVAL);
  }
  return retval;

end_error:
  if (retval == NULL) return (transcript_iconv_t)-1;

  transcript_close_converter(retval->from);
  transcript_close_converter(retval->to);
  return (transcript_iconv_t)-1;
}

/** Close a converter (iconv compatibility interface).
    @param cd The conversion state handle to clean up.
    @return @c 0 on success, @c -1 on failure (sets @c errno).
*/
int transcript_iconv_close(transcript_iconv_t cd) {
  if (cd == NULL) return 0;
  transcript_close_converter(cd->from);
  transcript_close_converter(cd->to);
  free(cd);
  return 0;
}

/** Perform conversion (iconv compatibility interface).
    @param cd The conversion state handle to use.
    @param inbuf A double pointer to the input buffer.
    @param inbytesleft A pointer to the number of bytes left in the input buffer.
    @param outbuf A double pointer to the output buffer.
    @param outbytesleft A pointer to the number of bytes left in the output buffer.
    @return The number of non-reversible conversions, or @c (size_t) @c -1 on
        failure in which case it sets @c errno.

    When @a inbuf is not @c NULL, this function tries to convert the bytes in
    the input buffer. For each character converted, it updates @a inbuf, @a
    inbytesleft, @a outbuf and @a outbytesleft. @c errno may be set to @c E2BIG
    if there is not enough space in @a outbuf to convert all the bytes, @c EILSEQ
    if an illegal sequence is encoutered in @a inbuf, or @c EINVAL if the buffer
    ends with an incomplete sequence.

    If @a inbuf is @c NULL, the converter is reset to its initial state. If
    @a outbuf is not @c NULL in this case, the converter writes the finishing
    bytes to the output to ensure a complete and legal conversion.
*/
size_t transcript_iconv(transcript_iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf,
                        size_t *outbytesleft) {
  /* To implement a compatible interface, we have to convert
     character-by-character. This is what iconv does as well and otherwise
     we have to save the intermediate results as well. */
  size_t result = 0;

  char *_inbuf;
  char saved_state[TRANSCRIPT_SAVE_STATE_SIZE];

  uint32_t codepoints[20];
  char *codepoint_ptr;
  bool_t non_reversible;

  const char *inbuflimit, *outbuflimit;

  if (inbuf == NULL || *inbuf == NULL) {
    /* There is no need to convert the input buffer, because even if it had an incomplete
       seqeunce at the end, that would have been reported on the previous call. A reset
       is necessary however. */
    transcript_to_unicode_reset(cd->from);

    if (outbuf == NULL || *outbuf == NULL) {
      /* If the user only asks for a reset, make it so. */
      transcript_from_unicode_reset(cd->to);
      return 0;
    }

    outbuflimit = (*outbuf) + (*outbytesleft);
    switch (transcript_from_unicode_flush(cd->to, outbuf, outbuflimit)) {
      case TRANSCRIPT_SUCCESS:
        break;
      case TRANSCRIPT_NO_SPACE:
        ERROR(E2BIG);
      default:
        ERROR(EBADF);
    }
    return 0;
  }

  _inbuf = *inbuf;
  inbuflimit = (*inbuf) + (*inbytesleft);
  outbuflimit = (*outbuf) + (*outbytesleft);

  while (_inbuf < inbuflimit) {
    transcript_save_state(cd->from, saved_state);
    non_reversible = FALSE;
    codepoint_ptr = (char *)&codepoints;
    /* Convert a single character of the input, by forcing a single conversion. */
    switch (transcript_to_unicode(cd->from, (const char **)&_inbuf, inbuflimit, &codepoint_ptr,
                                  (const char *)&codepoints + 20 * 4,
                                  TRANSCRIPT_SINGLE_CONVERSION | TRANSCRIPT_NO_MN_CONVERSION)) {
      case TRANSCRIPT_ILLEGAL_END:
      case TRANSCRIPT_INCOMPLETE:
        ERROR(EINVAL);
      case TRANSCRIPT_FALLBACK:
        transcript_to_unicode(
            cd->from, (const char **)&_inbuf, inbuflimit, &codepoint_ptr,
            (const char *)codepoints + 20 * sizeof(codepoints[0]),
            TRANSCRIPT_SINGLE_CONVERSION | TRANSCRIPT_NO_MN_CONVERSION | TRANSCRIPT_ALLOW_FALLBACK);
        non_reversible = TRUE;
        break;
      case TRANSCRIPT_PRIVATE_USE:
      case TRANSCRIPT_UNASSIGNED:
        codepoints[0] = 0xFFFD;
        transcript_to_unicode_skip(cd->from, (const char **)&_inbuf, inbuflimit);
        non_reversible = TRUE;
        break;
      case TRANSCRIPT_ILLEGAL:
        ERROR(EILSEQ);
      case TRANSCRIPT_SUCCESS:
        break;
      /* These should not happen, but we need to handle them anyway. Thus we
         return EBADF, which is what gconv returns on internal errors as well. */
      case TRANSCRIPT_NO_SPACE:
      case TRANSCRIPT_INTERNAL_ERROR:
      default:
        ERROR(EBADF);
    }

    /* Only try to convert if the previous conversion yielded any codepoints. */
    if (codepoint_ptr > (char *)codepoints) {
      /* If the previous conversion yielded more than one codepoint, the
         conversion is definately non_reversible. */
      if (codepoint_ptr > (char *)codepoints + sizeof(codepoints[0])) non_reversible = TRUE;

      codepoint_ptr = (char *)&codepoints;
    try_again:
      /* Try to convert. If so far the conversion is reversible, try without substitutions and
       * fallbacks first. */
      switch (transcript_from_unicode(
          cd->to, (const char **)&codepoint_ptr,
          (const char *)codepoints + 20 * sizeof(codepoints[0]), outbuf, outbuflimit,
          TRANSCRIPT_NO_1N_CONVERSION |
              (non_reversible
                   ? TRANSCRIPT_SUBST_UNASSIGNED | TRANSCRIPT_SUBST_ILLEGAL |
                         TRANSCRIPT_ALLOW_FALLBACK
                   : 0))) {
        case TRANSCRIPT_SUCCESS:
          break;
        case TRANSCRIPT_FALLBACK:
        case TRANSCRIPT_UNASSIGNED:
        case TRANSCRIPT_PRIVATE_USE:
          /* Apparently, we couldn't convert (all) the characters, so this counts as
             as a non-reversible conversion. */
          if (non_reversible) /* We shouldn't be able to get here! Return "internal error". */
            ERROR(EBADF);
          non_reversible = TRUE;
          goto try_again;
        case TRANSCRIPT_NO_SPACE:
          ERROR(E2BIG);
        /* None of the other errors should happen, as we feed it only valid codepoints. So
           we handle all of them as internal errors. */
        default:
          ERROR(EBADF);
      }
    }

    if (non_reversible) {
      result++;
      non_reversible = FALSE;
    }
    *inbuf = _inbuf;
  }

  return result;
end_error:
  transcript_load_state(cd->from, saved_state);
  return (size_t)-1;
}
#undef ERROR
