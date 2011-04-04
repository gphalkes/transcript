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

/** @file */

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <search.h>
#ifndef WITHOUT_PTHREAD
#include <pthread.h>
#endif
#include <limits.h>
#include <locale.h>
#ifdef HAS_NL_LANGINFO
#include <langinfo.h>
#endif

#include "charconv_internal.h"
#include "utf.h"
#include "generic_fallbacks.h"

#include "convertors.h"

#ifdef USE_GETTEXT
#include <libintl.h>
#define _(x) dgettext("libcharconv", x)
#else
#define _(x) x
#endif

/** @addtogroup charconv */
/** @{ */

/** @internal */
#define IS_ALNUM (1<<0)
/** @internal */
#define IS_DIGIT (1<<1)
/** @internal */
#define IS_UPPER (1<<2)
/** @internal */
#define IS_SPACE (1<<3)
/** @internal */
#define IS_IDCHR_EXTRA (1<<4)
static char char_info[CHAR_MAX];

static charconv_t *try_convertors(const char *normalized_name, const char *real_name, int flags, charconv_error_t *error);

/*================ API functions ===============*/
/** Check if a named convertor is available.
    @param name The name of the convertor to check.
	@return 1 if the convertor is avaible, 0 otherwise.
*/
int charconv_probe_convertor(const char *name) {
	_charconv_init();
	return _charconv_probe_convertor(name);
}

/** Open a convertor.
    @param name The name of the convertor to open.
    @param utf_type The UTF type to use for representing Unicode codepoints.
    @param flags The default flags for the convertor (see ::charconv_flags_t for possible values).
    @param error The location to store a possible error code.

    The name of the convertor is in principle free-form. A list of known names
    can be retrieved through ::charconv_get_names. The @a name argument is
    passed through ::charconv_normalize_name first, and at most 79 characters of
    the normalized name are considered.
*/
charconv_t *charconv_open_convertor(const char *name, charconv_utf_t utf_type, int flags, charconv_error_t *error) {
	charconv_name_desc_t *convertor;
	char normalized_name[NORMALIZE_NAME_MAX];

	_charconv_init();

	if (utf_type > CHARCONV_UTF32LE || utf_type <= 0) {
		if (error != NULL)
			*error = CHARCONV_BAD_ARG;
		return NULL;
	}

	_charconv_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	if ((convertor = _charconv_get_name_desc(normalized_name)) != NULL)
		return _charconv_fill_utf(try_convertors(convertor->name, convertor->real_name, flags, error), utf_type);
	return _charconv_fill_utf(try_convertors(normalized_name, name, flags, error), utf_type);
}

/** Close a convertor.
    @param handle The convertor to close.

    This function releases all memory associated with @a handle. @a handle may
    be @c NULL.
*/
void charconv_close_convertor(charconv_t *handle) {
	if (handle != NULL)
		handle->close(handle);
}

/** Check if two names describe the same convertor.
    @param name_a
    @param name_b
    @return 1 if @a name_a and @a name_b describe the same convertor, 0 otherwise.
*/
int charconv_equal(const char *name_a, const char *name_b) {
	charconv_name_desc_t *convertor;
	char normalized_name_a[NORMALIZE_NAME_MAX], normalized_name_b[NORMALIZE_NAME_MAX];
/* FIXME: take options into account! */
	_charconv_init();
	_charconv_normalize_name(name_a, normalized_name_a, NORMALIZE_NAME_MAX);
	_charconv_normalize_name(name_b, normalized_name_b, NORMALIZE_NAME_MAX);

	if (strcmp(normalized_name_a, normalized_name_b) == 0)
		return 1;

	if ((convertor = _charconv_get_name_desc(normalized_name_a)) == NULL)
		return 0;
	return convertor == _charconv_get_name_desc(normalized_name_b);
}

/** Convert a buffer from a chararcter set to Unicode.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @param outbuf A double pointer to the start of the output buffer.
    @param outbuflimit A pointer to the end of the output buffer.
    @param flags Flags for this conversion (see ::charconv_flags_t for possible values).
    @retval ::CHARCONV_SUCCESS
	@retval ::CHARCONV_NO_SPACE
	@retval ::CHARCONV_INCOMPLETE
	@retval ::CHARCONV_FALLBACK
	@retval ::CHARCONV_UNASSIGNED
	@retval ::CHARCONV_ILLEGAL
	@retval ::CHARCONV_ILLEGAL_END
	@retval ::CHARCONV_INTERNAL_ERROR
	@retval ::CHARCONV_PRIVATE_USE &nbsp;

    This function uses the convertor indicated by @a handle to convert data from
    the character set named in opening @a handle to Unicode. The interface is
    designed to work with incomplete buffers, and may return ::CHARCONV_INCOMPLETE
	if the bytes at the end of the input buffer do not form a complete sequence.
	If the output buffer is not large enough to store all the converted data,
	::CHARCONV_NO_SPACE is returned.

	If M:N conversions are enabled, the output buffer must be able to hold at
	least 20 codepoints. This is guaranteed if the size of the output buffer is
	at least 80 (::CHARCONV_MIN_UNICODE_BUFFER_SIZE) bytes.
*/
charconv_error_t charconv_to_unicode(charconv_t *handle, const char const **inbuf, const char const *inbuflimit, char **outbuf,
		const char const *outbuflimit, int flags)
{
	return handle->convert_to(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags | (handle->flags & 0xff));
}

/** Convert a buffer from Unicode to a chararcter set.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @param outbuf A double pointer to the start of the output buffer.
    @param outbuflimit A pointer to the end of the output buffer.
    @param flags Flags for this conversion (see ::charconv_flags_t for possible values).
    @retval ::CHARCONV_SUCCESS
	@retval ::CHARCONV_NO_SPACE
	@retval ::CHARCONV_INCOMPLETE
	@retval ::CHARCONV_FALLBACK
	@retval ::CHARCONV_UNASSIGNED
	@retval ::CHARCONV_ILLEGAL
	@retval ::CHARCONV_ILLEGAL_END
	@retval ::CHARCONV_INTERNAL_ERROR
	@retval ::CHARCONV_PRIVATE_USE &nbsp;

    This function uses the convertor indicated by @a handle to convert data from
    Unicode to the character set named in opening @a handle. The interface is
    designed to work with incomplete buffers, and may return ::CHARCONV_INCOMPLETE
	if the bytes at the end of the input buffer do not form a complete sequence.
	If the output buffer is not large enough to store all the converted data,
	::CHARCONV_NO_SPACE is returned.

	If M:N conversions are enabled, the output buffer must be able to hold at
	least 32 bytes (::CHARCONV_MIN_CODEPAGE_BUFFER_SIZE).
*/
charconv_error_t charconv_from_unicode(charconv_t *handle, const char **inbuf, const char const *inbuflimit, char **outbuf,
		const char const *outbuflimit, int flags) {
	return handle->convert_from(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags | (handle->flags & 0xff));
}

/** Skip the next character in character set encoding.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @retval ::CHARCONV_SUCCESS
	@retval ::CHARCONV_INCOMPLETE
	@retval ::CHARCONV_INTERNAL_ERROR &nbsp;

    This function can be used to recover stopped to-Unicode conversions, if the
    next input character can not be converted (either because the input is
    corrupt, or the conversions are not permitted by the flag settings).
*/
charconv_error_t charconv_to_unicode_skip(charconv_t *handle, const char **inbuf, const char const *inbuflimit) {
	return handle->skip_to(handle, inbuf, inbuflimit);
}

/** Skip the next character in Unicode encoding.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @retval ::CHARCONV_SUCCESS
	@retval ::CHARCONV_INCOMPLETE
	@retval ::CHARCONV_INTERNAL_ERROR &nbsp;

    This function can be used to recover stopped from-Unicode conversions, if
    the next input character can not be converted (either because the input is
    corrupt, or the conversions are not permitted by the flag settings).
*/
charconv_error_t charconv_from_unicode_skip(charconv_t *handle, const char **inbuf, const char *inbuflimit) {
	if (handle->get_unicode(inbuf, inbuflimit, true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

/** Write out any bytes required to create a legal output in a character set.
    @param handle The convertor to use.
    @param outbuf A double pointer to the start of the output buffer.
    @param outbuflimit A pointer to the end of the output buffer.
    @retval ::CHARCONV_SUCCESS
	@retval ::CHARCONV_NO_SPACE
	@retval ::CHARCONV_INTERNAL_ERROR &nbsp;

    Some stateful encoding convertors need to store a shift sequence or some
    closing bytes at the end of the output, that can only be computed when it
    is known that there is no more input. For efficiency reasons, this is @em not
    done based on the ::CHARCONV_END_OF_TEXT flag in ::charconv_from_unicode.

    After calling this function, the from-Unicode conversion will be in the
    initial state.
*/
charconv_error_t charconv_from_unicode_flush(charconv_t *handle, char **outbuf, const char const *outbuflimit) {
	switch (handle->flush_from(handle, outbuf, outbuflimit)) {
		case CHARCONV_SUCCESS:
			break;
		case CHARCONV_NO_SPACE:
			return CHARCONV_NO_SPACE;
		default:
			return CHARCONV_INTERNAL_ERROR;
	}
	handle->reset_from(handle);
	return CHARCONV_SUCCESS;
}

/** Reset the to-Unicode conversion to its initial state.
    @param handle The convertor to reset.

    @note The to-Unicode and from-Unicode conversions are reset separately.
*/
void charconv_to_unicode_reset(charconv_t *handle) {
	handle->reset_to(handle);
}

/** Reset the from-Unicode conversion to its initial state.
    @param handle The convertor to reset.

    @note The to-Unicode and from-Unicode conversions are reset separately.
*/
void charconv_from_unicode_reset(charconv_t *handle) {
	handle->reset_from(handle);
}

/** Save a convertor's state.
    @param handle The convertor to save the state for.
    @param state A pointer to a buffer of at least ::CHARCONV_SAVE_STATE_SIZE bytes.
*/
void charconv_save_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

/** Restore a convertor's state.
    @param handle The convertor to restore the state for.
    @param state A pointer to a buffer of at least ::CHARCONV_SAVE_STATE_SIZE bytes.
*/
void charconv_load_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

/** Get a localized descriptive string for an error code.
    @param error The error code to retrieve the descriptive string for.
    @return A static string containing a localized descriptive string.
*/
const char *charconv_strerror(charconv_error_t error) {
	switch (error) {
		case CHARCONV_SUCCESS:
			return _("success");
		case CHARCONV_FALLBACK:
			return _("only a fallback mapping is available");
		case CHARCONV_UNASSIGNED:
			return _("character can not be mapped");
		case CHARCONV_ILLEGAL:
			return _("illegal sequence in input buffer");
		case CHARCONV_ILLEGAL_END:
			return _("illegal sequence at end of input buffer");
		default:
		case CHARCONV_INTERNAL_ERROR:
			return _("internal error");
		case CHARCONV_PRIVATE_USE:
			return _("character maps to a private use codepoint");
		case CHARCONV_NO_SPACE:
			return _("no space left in output buffer");
		case CHARCONV_INCOMPLETE:
			return _("incomplete character at end of input buffer");
		case CHARCONV_ERRNO:
			return strerror(errno);
		case CHARCONV_BAD_ARG:
			return _("bad argument");
		case CHARCONV_OUT_OF_MEMORY:
			return _("out of memory");
		case CHARCONV_INVALID_FORMAT:
			return _("invalid map-file format");
		case CHARCONV_TRUNCATED_MAP:
			return _("map file is truncated");
		case CHARCONV_WRONG_VERSION:
			return _("map file is of an unsupported version");
		case CHARCONV_INTERNAL_TABLE:
			return _("map file is for internal use only");
	}
}

/** Normalize a character set name.
    @param name The name to normalize.
    @param normalized_name A pointer to a buffer to store the normalized name.
    @param normalized_name_max The size of @a normalized_name.

    Any characters in @a name other than the letters 'a'-'z' (either upper or lower
    case), the numbers '0'-'9' and the punctuation characters '-', '_', '+',
    '=', ':' and ',' are ignored. The stored result will be nul terminated.
*/
void charconv_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max) {
	_charconv_init();
	_charconv_normalize_name(name, normalized_name, normalized_name_max);
}

/** Get a character string describing the current character set indicated by the environment.
    @return A pointer to a string with the current character set. This string is
        allocated statically, and may be overwritten by subsequent calls to this
        function, @c setlocale or @c nl_langinfo.

    Essentially this function does the same as @c nl_langinfo(CODESET). However,
    @c nl_langinfo may not be available. In those cases, it uses @c setlocale to
    retrieve the current value for @c LC_CTYPE, and tries to retrieve the
    character set in that. If all else fails, it returns a string representing
    the ASCII character set.
*/
const char *charconv_get_codeset(void) {
#ifdef HAS_NL_LANGINFO
	return nl_langinfo(CODESET);
#else
	const char *lc_ctype, *codeset;

	if ((lc_ctype = setlocale(LC_CTYPE, NULL)) == NULL || strcmp(lc_ctype, "POSIX") == 0 ||
			strcmp(lc_ctype, "C") == 0 || (codeset = strrchr(lc_ctype, '.')) == NULL || codeset[1] == 0)
		return "ANSI_X3.4-1968";
	return codeset + 1;
#endif
}

/*================ Internal functions ===============*/
/** @internal
    @brief Perform the action described at ::charconv_probe_convertor.

    This function does not call ::_charconv_init, which ::charconv_probe_convertor
    does. However, ::_charconv_init only needs to be called once, so if we
    know it has already been called, we don't need to check again. Therefore,
    in the library itself we use this stripped down version.
*/
int _charconv_probe_convertor(const char *name) {
	charconv_name_desc_t *convertor;
	char normalized_name[NORMALIZE_NAME_MAX];

	_charconv_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	if ((convertor = _charconv_get_name_desc(normalized_name)) != NULL)
		return try_convertors(convertor->name, convertor->real_name, CHARCONV_PROBE_ONLY, NULL) != NULL;
	return try_convertors(normalized_name, name, CHARCONV_PROBE_ONLY, NULL) != NULL;
}

/** @internal
    @brief Fill the @c get_unicode and @c put_unicode members of a ::charconv_t struct.
*/
charconv_t *_charconv_fill_utf(charconv_t *handle, charconv_utf_t utf_type) {
	if (handle == NULL)
		return NULL;
	handle->get_unicode = _charconv_get_get_unicode(utf_type);
	handle->put_unicode = _charconv_get_put_unicode(utf_type);
	return handle;
}

/** Try the different convertors to see if one of them recognizes the name. */
static charconv_t *try_convertors(const char *normalized_name, const char *real_name, int flags, charconv_error_t *error) {
	charconv_t *result;
	if ((result = _charconv_open_unicode_convertor(normalized_name, flags, error)) != NULL)
		return result;
	if ((result = _charconv_open_iso8859_1_convertor(normalized_name, flags, error)) != NULL)
		return result;
	if ((result = _charconv_open_iso2022_convertor(normalized_name, flags, error)) != NULL)
		return result;
	return _charconv_open_cct_convertor(real_name, flags, error);
}

/** Try to open a file from a database directory.
    @param name The base name of the file to open.
    @param ext The extension of the file to open.
    @param dir The directory to look in.
    @param error The location to store a possible error.
    @return A @c FILE pointer on success, or @c NULL on failure.
*/
static FILE *try_db_open(const char *name, const char *ext, const char *dir, charconv_error_t *error) {
	char *file_name = NULL;
	FILE *file = NULL;
	size_t len;

	len = strlen(dir) + strlen(name) + 2 + strlen(ext);
	if ((file_name = malloc(len)) == NULL) {
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		goto end;
	}

	strcpy(file_name, dir);
	/*FIXME: dir separator may not be / */
	strcat(file_name, "/");
	strcat(file_name, name);
	strcat(file_name, ext);

	if ((file = fopen(file_name, "r")) == NULL) {
		if (error != NULL)
			*error = CHARCONV_ERRNO;
		goto end;
	}

end:
	free(file_name);
	return file;
}

/** @internal
    @brief Open a file from the database directory.
    @param name The base name of the file to open.
    @param ext The extension of the file to open.
    @param error The location to store a possible error.
    @return A @c FILE pointer on success, or @c NULL on failure.

    This function first looks in the diretory named in the CHARCONV_PATH
    environment variable (if set), and then in the compiled in database
    directory.
*/
FILE *_charconv_db_open(const char *name, const char *ext, charconv_error_t *error) {
	FILE *result;
	const char *dir = getenv("CHARCONV_PATH");
	/*FIXME: allow colon delimited list*/
	if (dir != NULL && (result = try_db_open(name, ext, dir, error)) != NULL)
		return result;
	return try_db_open(name, ext, DB_DIRECTORY, error);
}

#ifndef HAS_STRDUP
/** @internal
    @brief Copy a string.

    This function is provided when there is no strdup function in the C library.
*/
char *_charconv_strdup(const char *str) {
	char *result;
	size_t len = strlen(str);

	if ((result = malloc(len + 1)) == NULL)
		return NULL;
	memcpy(result, str, len + 1);
	return result;
}
#endif

/* We want to make sure that a locale setting doesn't corrupt our comparison
   algorithms. So we use our own versions of isalnum, isdigit and tolower,
   rather than using the library supplied versions. */

/** @internal
    @brief Initialize the character information bitmap used for ::_charconv_isXXXXX and ::_charconv_tolower.
*/
static void init_char_info(void) {
	static const char alnum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	static const char digit[] = "0123456789";
	static const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const char space[] = " \t\f\n\r\v";
	static const char idhcr_extra[] = "-_+.:";

	const char *ptr;

	for (ptr = alnum; *ptr != 0; ptr++) char_info[(int) *ptr] |= IS_ALNUM;
	for (ptr = digit; *ptr != 0; ptr++) char_info[(int) *ptr] |= IS_DIGIT;
	for (ptr = upper; *ptr != 0; ptr++) char_info[(int) *ptr] |= IS_UPPER;
	for (ptr = space; *ptr != 0; ptr++) char_info[(int) *ptr] |= IS_SPACE;
	for (ptr = idhcr_extra; *ptr != 0; ptr++) char_info[(int) *ptr] |= IS_IDCHR_EXTRA;
}

/** @internal @brief Execution-character-set isalnum. */
int _charconv_isalnum(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_ALNUM); }
/** @internal @brief Execution-character-set isdigit. */
int _charconv_isdigit(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_DIGIT); }
/** @internal @brief Execution-character-set isspace. */
int _charconv_isspace(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_SPACE); }
/** @internal @brief Checks whether a character is considered an identifier character (used in ::_charconv_normalize_name). */
int _charconv_isidchr(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & (IS_IDCHR_EXTRA | IS_ALNUM)); }
/** @internal @brief Execution-character-set tolower. */
int _charconv_tolower(int c) { return (c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_UPPER)) ? 'a' + (c - 'A') : c; }

/** @internal
    @brief Perform the action described at ::charconv_normalize_name.

    This function does not call ::_charconv_init, which ::charconv_normalize_name
    does. However, ::_charconv_init only needs to be called once, so if we
    know it has already been called, we don't need to check again. Therefore,
    in the library itself we use this stripped down version.
*/
void _charconv_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max) {
	size_t write_idx = 0;
	bool last_was_digit = false;

	for (; *name != 0 && write_idx < normalized_name_max - 1; name++) {
		if (!_charconv_isalnum(*name) && *name != ',') {
			last_was_digit = false;
		} else {
			if (!last_was_digit && *name == '0')
				continue;
			normalized_name[write_idx++] = _charconv_tolower(*name);
			last_was_digit = _charconv_isdigit(*name);
		}
	}
	normalized_name[write_idx] = 0;
}

/** @internal
    @brief Handle an unassigned codepoint in a from-Unicode conversion.

	This function does a lookup in the generic fall-back table. If no generic
    fall-back is found, this function simply returns ::CHARCONV_UNASSIGNED.
    Otherwise, it handles conversion of the generic fall-back as if it were
    specified in the convertor table.
*/
charconv_error_t _charconv_handle_unassigned(charconv_t *handle, uint32_t codepoint, char **outbuf,
		const char *outbuflimit, int flags)
{
	get_unicode_func_t saved_get_unicode_func;
	const char *fallback_ptr;
	charconv_error_t result;

	if ((codepoint = get_generic_fallback(codepoint)) != UINT32_C(0xFFFF)) {
		if (!(flags & CHARCONV_ALLOW_FALLBACK))
			return CHARCONV_FALLBACK;
		saved_get_unicode_func = handle->get_unicode;
		handle->get_unicode = _charconv_get_utf32_no_check;
		fallback_ptr = (const char *) &codepoint;

		result = handle->convert_from(handle, &fallback_ptr, fallback_ptr + sizeof(uint32_t),
			outbuf, outbuflimit, flags | CHARCONV_SINGLE_CONVERSION | CHARCONV_NO_1N_CONVERSION);
		handle->get_unicode = saved_get_unicode_func;
		switch (result) {
			case CHARCONV_NO_SPACE:
			case CHARCONV_UNASSIGNED:
			case CHARCONV_SUCCESS:
			case CHARCONV_FALLBACK:
				return result;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}
	}
	return CHARCONV_UNASSIGNED;
}

/** @internal
    @brief Initialize the parts of the library that can not be handled in a
         thread-safe manner.

    This function initializes the gettext domain for the library, the character
    info for ::charconv_normalize_name and the list of aliases. Note that it
    does not load the availability of the aliases.
*/
void _charconv_init(void) {
	static bool initialized = false;
#ifndef WITHOUT_PTHREAD
	static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

	/* We check the initialized variable first without locking the mutex. We can
	   safely do this, because once it has been set, it will never be reset. So
	   if this check determines that the library has been initialized, it really
	   has been. On the other hand, if the test determines that the library has
	   not been initialized, this does not mean that it can safely start
	   initialization. Then we lock the mutex to ensure proper exclusion. This
	   way we avoid the (possibly expensive) mutex lock almost always, without
	   sacrificing thread-safety.
	*/
	if (!initialized) {
		PTHREAD_ONLY(pthread_mutex_lock(&init_mutex));
		if (!initialized) {
			/* Initialize aliases defined in the aliases.txt file. This does not
			   check availability, nor does it build the complete set of display
			   names. That will be done when that list is requested. */
			#ifdef USE_GETTEXT
			bindtextdomain("libcharconv", LOCALEDIR);
			#endif
			init_char_info();
			_charconv_init_aliases_from_file();
		}
		initialized = true;
		PTHREAD_ONLY(pthread_mutex_unlock(&init_mutex));
	}
}

/** @} */
