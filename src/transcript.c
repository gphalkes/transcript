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
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#ifdef HAS_NL_LANGINFO
#include <langinfo.h>
#endif
#include <ltdl.h>


#include "transcript_internal.h"
#include "utf.h"
#include "generic_fallbacks.h"

#ifdef USE_GETTEXT
#include <libintl.h>
#define _(x) dgettext("libtranscript", x)
#else
#define _(x) x
#endif

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)

/** @addtogroup transcript */
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
void (*_transcript_acquire_lock)(void *);
void (*_transcript_release_lock)(void *);
void *_transcript_lock;

static const char **search_path;
static const char path_sep[] = { LT_PATHSEP_CHAR, '\0' };

static transcript_t *open_convertor(const char *normalized_name, const char *real_name, int flags, transcript_error_t *error);

/*================ API functions ===============*/
/** Set the locking callbacks for libtranscript.
    @param acquire The function to call to acquire the lock.
    @param release The function to call to release the lock.
    @param lock The data to pass to @a acquire and @a release.

    This function should be called before calling any other function in the
    library, if the library is used in more than one thread, or if the
    dynamic linker is invoked in another thread then the functions in this
    library.

    For an environment where locking is performed using the pthread library,
    the following code provides an example of how to set the callbacks.

    @code
    #include <pthread.h>
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static void acquire_lock(void *data) { (void) data; pthread_mutex_lock(&lock); }
    static void release_lock(void *data) { (void) data; pthread_mutex_unlock(&lock); }

    transcript_set_lock_callbacks(acquire_lock, release_lock, NULL);
    @endcode
*/
void transcript_set_lock_callbacks(void (*acquire)(void *), void (*release)(void *), void *lock) {
	if (acquire == NULL || release == NULL) {
		_transcript_acquire_lock = NULL;
		_transcript_release_lock = NULL;
		_transcript_lock = NULL;
	} else {
		_transcript_acquire_lock = acquire;
		_transcript_release_lock = release;
		_transcript_lock = lock;
	}
}

/** Check if a named convertor is available.
    @param name The name of the convertor to check.
    @return 1 if the convertor is avaible, 0 otherwise.
*/
int transcript_probe_convertor(const char *name) {
	int result;

	_transcript_init();
	ACQUIRE_LOCK();
	result = transcript_probe_convertor_nolock(name);
	RELEASE_LOCK();
	return result;
}

/** Open a convertor.
    @param name The name of the convertor to open.
    @param utf_type The UTF type to use for representing Unicode codepoints.
    @param flags The default flags for the convertor (see ::transcript_flags_t for possible values).
    @param error The location to store a possible error code.

    The name of the convertor is in principle free-form. A list of known names
    can be retrieved through ::transcript_get_names. The @a name argument is
    passed through ::transcript_normalize_name first, and at most 79 characters of
    the normalized name are considered.
*/
transcript_t *transcript_open_convertor(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error) {
	transcript_t *result;

	_transcript_init();
	ACQUIRE_LOCK();
	result = transcript_open_convertor_nolock(name, utf_type, flags, error);
	RELEASE_LOCK();
	return result;
}

/** Close a convertor.
    @param handle The convertor to close.

    This function releases all memory associated with @a handle. @a handle may
    be @c NULL.
*/
void transcript_close_convertor(transcript_t *handle) {
	if (handle != NULL) {
		if (handle->close != NULL)
			handle->close(handle);
		ACQUIRE_LOCK();
		lt_dlclose(handle->library_handle);
		RELEASE_LOCK();
		free(handle);
	}
}

/** Check if two names describe the same convertor.
    @param name_a
    @param name_b
    @return 1 if @a name_a and @a name_b describe the same convertor, 0 otherwise.
*/
int transcript_equal(const char *name_a, const char *name_b) {
	transcript_name_desc_t *convertor;
	char normalized_name_a[NORMALIZE_NAME_MAX], normalized_name_b[NORMALIZE_NAME_MAX];
/* FIXME: take options into account! */
	_transcript_init();
	_transcript_normalize_name(name_a, normalized_name_a, NORMALIZE_NAME_MAX);
	_transcript_normalize_name(name_b, normalized_name_b, NORMALIZE_NAME_MAX);

	if (strcmp(normalized_name_a, normalized_name_b) == 0)
		return 1;

	if ((convertor = _transcript_get_name_desc(normalized_name_a, 0)) == NULL)
		return 0;
	return convertor == _transcript_get_name_desc(normalized_name_b, 0);
}

/** Convert a buffer from a chararcter set to Unicode.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @param outbuf A double pointer to the start of the output buffer.
    @param outbuflimit A pointer to the end of the output buffer.
    @param flags Flags for this conversion (see ::transcript_flags_t for possible values).
    @retval ::TRANSCRIPT_SUCCESS
    @retval ::TRANSCRIPT_NO_SPACE
    @retval ::TRANSCRIPT_INCOMPLETE
    @retval ::TRANSCRIPT_FALLBACK
    @retval ::TRANSCRIPT_UNASSIGNED
    @retval ::TRANSCRIPT_ILLEGAL
    @retval ::TRANSCRIPT_ILLEGAL_END
    @retval ::TRANSCRIPT_INTERNAL_ERROR
    @retval ::TRANSCRIPT_PRIVATE_USE &nbsp;

    This function uses the convertor indicated by @a handle to convert data from
    the character set named in opening @a handle to Unicode. The interface is
    designed to work with incomplete buffers, and may return ::TRANSCRIPT_INCOMPLETE
    if the bytes at the end of the input buffer do not form a complete sequence.
    If the output buffer is not large enough to store all the converted data,
    ::TRANSCRIPT_NO_SPACE is returned.

    If M:N conversions are enabled, the output buffer must be able to hold at
    least 20 codepoints. This is guaranteed if the size of the output buffer is
    at least 80 (::TRANSCRIPT_MIN_UNICODE_BUFFER_SIZE) bytes.
*/
transcript_error_t transcript_to_unicode(transcript_t *handle, const char const **inbuf, const char const *inbuflimit, char **outbuf,
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
    @param flags Flags for this conversion (see ::transcript_flags_t for possible values).
    @retval ::TRANSCRIPT_SUCCESS
    @retval ::TRANSCRIPT_NO_SPACE
    @retval ::TRANSCRIPT_INCOMPLETE
    @retval ::TRANSCRIPT_FALLBACK
    @retval ::TRANSCRIPT_UNASSIGNED
    @retval ::TRANSCRIPT_ILLEGAL
    @retval ::TRANSCRIPT_ILLEGAL_END
    @retval ::TRANSCRIPT_INTERNAL_ERROR
    @retval ::TRANSCRIPT_PRIVATE_USE &nbsp;

    This function uses the convertor indicated by @a handle to convert data from
    Unicode to the character set named in opening @a handle. The interface is
    designed to work with incomplete buffers, and may return ::TRANSCRIPT_INCOMPLETE
    if the bytes at the end of the input buffer do not form a complete sequence.
    If the output buffer is not large enough to store all the converted data,
    ::TRANSCRIPT_NO_SPACE is returned.

    If M:N conversions are enabled, the output buffer must be able to hold at
    least 32 bytes (::TRANSCRIPT_MIN_CODEPAGE_BUFFER_SIZE).
*/
transcript_error_t transcript_from_unicode(transcript_t *handle, const char **inbuf, const char const *inbuflimit, char **outbuf,
		const char const *outbuflimit, int flags) {
	return handle->convert_from(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags | (handle->flags & 0xff));
}

/** Skip the next character in character set encoding.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @retval ::TRANSCRIPT_SUCCESS
    @retval ::TRANSCRIPT_INCOMPLETE
    @retval ::TRANSCRIPT_INTERNAL_ERROR &nbsp;

    This function can be used to recover stopped to-Unicode conversions, if the
    next input character can not be converted (either because the input is
    corrupt, or the conversions are not permitted by the flag settings).
*/
transcript_error_t transcript_to_unicode_skip(transcript_t *handle, const char **inbuf, const char const *inbuflimit) {
	return handle->skip_to(handle, inbuf, inbuflimit);
}

/** Skip the next character in Unicode encoding.
    @param handle The convertor to use.
    @param inbuf A double pointer to the start of the input buffer.
    @param inbuflimit A pointer to the end of the input buffer.
    @retval ::TRANSCRIPT_SUCCESS
    @retval ::TRANSCRIPT_INCOMPLETE
    @retval ::TRANSCRIPT_INTERNAL_ERROR &nbsp;

    This function can be used to recover stopped from-Unicode conversions, if
    the next input character can not be converted (either because the input is
    corrupt, or the conversions are not permitted by the flag settings).
*/
transcript_error_t transcript_from_unicode_skip(transcript_t *handle, const char **inbuf, const char *inbuflimit) {
	if (handle->get_unicode(inbuf, inbuflimit, true) == TRANSCRIPT_UTF_INCOMPLETE)
		return TRANSCRIPT_INCOMPLETE;
	return TRANSCRIPT_SUCCESS;
}

/** Write out any bytes required to create a legal output in a character set.
    @param handle The convertor to use.
    @param outbuf A double pointer to the start of the output buffer.
    @param outbuflimit A pointer to the end of the output buffer.
    @retval ::TRANSCRIPT_SUCCESS
    @retval ::TRANSCRIPT_NO_SPACE
    @retval ::TRANSCRIPT_INTERNAL_ERROR &nbsp;

    Some stateful encoding convertors need to store a shift sequence or some
    closing bytes at the end of the output, that can only be computed when it
    is known that there is no more input. For efficiency reasons, this is @em not
    done based on the ::TRANSCRIPT_END_OF_TEXT flag in ::transcript_from_unicode.

    After calling this function, the from-Unicode conversion will be in the
    initial state.
*/
transcript_error_t transcript_from_unicode_flush(transcript_t *handle, char **outbuf, const char const *outbuflimit) {
	switch (handle->flush_from(handle, outbuf, outbuflimit)) {
		case TRANSCRIPT_SUCCESS:
			break;
		case TRANSCRIPT_NO_SPACE:
			return TRANSCRIPT_NO_SPACE;
		default:
			return TRANSCRIPT_INTERNAL_ERROR;
	}
	handle->reset_from(handle);
	return TRANSCRIPT_SUCCESS;
}

/** Reset the to-Unicode conversion to its initial state.
    @param handle The convertor to reset.

    @note The to-Unicode and from-Unicode conversions are reset separately.
*/
void transcript_to_unicode_reset(transcript_t *handle) {
	handle->reset_to(handle);
}

/** Reset the from-Unicode conversion to its initial state.
    @param handle The convertor to reset.

    @note The to-Unicode and from-Unicode conversions are reset separately.
*/
void transcript_from_unicode_reset(transcript_t *handle) {
	handle->reset_from(handle);
}

/** Save a convertor's state.
    @param handle The convertor to save the state for.
    @param state A pointer to a buffer of at least ::TRANSCRIPT_SAVE_STATE_SIZE bytes.
*/
void transcript_save_state(transcript_t *handle, void *state) {
	handle->save(handle, state);
}

/** Restore a convertor's state.
    @param handle The convertor to restore the state for.
    @param state A pointer to a buffer of at least ::TRANSCRIPT_SAVE_STATE_SIZE bytes.
*/
void transcript_load_state(transcript_t *handle, void *state) {
	handle->save(handle, state);
}

/** Get a localized descriptive string for an error code.
    @param error The error code to retrieve the descriptive string for.
    @return A static string containing a localized descriptive string.
*/
const char *transcript_strerror(transcript_error_t error) {
	switch (error) {
		case TRANSCRIPT_SUCCESS:
			return _("Success");
		case TRANSCRIPT_FALLBACK:
			return _("Only a fallback mapping is available");
		case TRANSCRIPT_UNASSIGNED:
			return _("Character can not be mapped");
		case TRANSCRIPT_ILLEGAL:
			return _("Illegal sequence in input buffer");
		case TRANSCRIPT_ILLEGAL_END:
			return _("Illegal sequence at end of input buffer");
		default:
		case TRANSCRIPT_INTERNAL_ERROR:
			return _("Internal error");
		case TRANSCRIPT_PRIVATE_USE:
			return _("Character maps to a private use codepoint");
		case TRANSCRIPT_NO_SPACE:
			return _("No space left in output buffer");
		case TRANSCRIPT_INCOMPLETE:
			return _("Incomplete character at end of input buffer");
		case TRANSCRIPT_ERRNO:
			return strerror(errno);
		case TRANSCRIPT_BAD_ARG:
			return _("Bad argument");
		case TRANSCRIPT_OUT_OF_MEMORY:
			return _("Out of memory");
		case TRANSCRIPT_INVALID_FORMAT:
			return _("Invalid map-file format");
		case TRANSCRIPT_TRUNCATED_MAP:
			return _("Map file is truncated");
		case TRANSCRIPT_WRONG_VERSION:
			return _("Map file is of an unsupported version");
		case TRANSCRIPT_INTERNAL_TABLE:
			return _("Map file is for internal use only");
		case TRANSCRIPT_DLOPEN_FAILURE:
			return _("Dynamic linker returned an error");
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
void transcript_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max) {
	_transcript_init();
	_transcript_normalize_name(name, normalized_name, normalized_name_max);
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
const char *transcript_get_codeset(void) {
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

/** Get the value of ::TRANSCRIPT_VERSION corresponding to the actually used library.
    @return The value of ::TRANSCRIPT_VERSION.

    This function can be useful to determine at runtime what version of the library
    was linked to the program. Although currently there are no known uses for this
    information, future library additions may prompt library users to want to operate
    differently depending on the available features.
*/
long transcript_get_version(void) {
	return TRANSCRIPT_VERSION;
}

/*================ Internal functions ===============*/
/** Load a suffixed symbol from a plugin. */
static void *get_sym(lt_dlhandle handle, const char *sym, const char *convertor_name) {
	char buffer[NORMALIZE_NAME_MAX + 32];
	strcpy(buffer, sym);
	strcat(buffer, convertor_name);
	return lt_dlsym(handle, buffer);
}

/** Try to open (i.e. get a file handle) a convertor.

    If the option probe=load has been set in the convertor options, then instead
    of trying to open with fopen, it will actually be dlopened and the function
    transcript_probe_<name> will be called.
*/
static bool probe_convertor(const char *name, const char *normalized_name) {
	const char *load_option;
	char base_name[NORMALIZE_NAME_MAX];

	transcript_get_option(name, base_name, NORMALIZE_NAME_MAX, NULL);

	if ((load_option = strstr(normalized_name, ",probe=load")) != NULL && (load_option[11] == 0 || load_option[11] == ',')) {
		bool (*probe)(const char *);
		lt_dlhandle handle;
		int result = 0;

		if ((handle = _transcript_db_open(base_name, "tct", (open_func_t) lt_dlopen, NULL)) == NULL)
			return 0;

		transcript_get_option(normalized_name, base_name, NORMALIZE_NAME_MAX, NULL);
		if ((probe = get_sym(handle, "transcript_probe_", base_name)) != NULL)
			result = probe(normalized_name);

		lt_dlclose(handle);
		return result;
	} else {
		FILE *handle = NULL;
		/* For most convertors it is sufficient to know that the file is readable. */
		if ((handle = _transcript_db_open(base_name, "tct", (open_func_t) fopen, NULL)) != NULL)
			fclose(handle);
		return handle != NULL;
	}
}

/** @internal
    @brief Perform the action described at ::transcript_probe_convertor.

    This function does not call ::_transcript_init, which ::transcript_probe_convertor
    does. However, ::_transcript_init only needs to be called once, so if we
    know it has already been called, we don't need to check again. Therefore,
    in the library itself we use this stripped down version.
*/
int transcript_probe_convertor_nolock(const char *name) {
	transcript_name_desc_t *convertor;
	char normalized_name[NORMALIZE_NAME_MAX];

	_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	/* FIXME: shouldn't we try to open the convertor without going through the aliases
	   table if we can't find it through the aliases table? */
	if ((convertor = _transcript_get_name_desc(normalized_name, 0)) != NULL)
		return probe_convertor(convertor->real_name, convertor->name);
	return probe_convertor(name, normalized_name);
}

/** @internal
    @brief Open a convertor.

    This function is called by ::transcript_open_convertor, after locking the
    internal mutex. This function is provided such that convertors can open
    other convertors without causing a deadlock.
*/
transcript_t *transcript_open_convertor_nolock(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error) {
	transcript_name_desc_t *convertor;
	char normalized_name[NORMALIZE_NAME_MAX];

	if (utf_type > TRANSCRIPT_UTF32LE || utf_type <= 0) {
		if (error != NULL)
			*error = TRANSCRIPT_BAD_ARG;
		return NULL;
	}

	_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	/* FIXME: shouldn't we try to open the convertor without going through the aliases
	   table if we can't find it through the aliases table? */
	if ((convertor = _transcript_get_name_desc(normalized_name, 0)) != NULL)
		return _transcript_fill_utf(open_convertor(convertor->name, convertor->real_name, flags, error), utf_type);
	return _transcript_fill_utf(open_convertor(normalized_name, name, flags, error), utf_type);
}

/** @internal
    @brief Fill the @c get_unicode and @c put_unicode members of a ::transcript_t struct.
*/
transcript_t *_transcript_fill_utf(transcript_t *handle, transcript_utf_t utf_type) {
	if (handle == NULL)
		return NULL;
	handle->get_unicode = _transcript_get_get_unicode(utf_type);
	handle->put_unicode = _transcript_get_put_unicode(utf_type);
	return handle;
}

/** Open a convertor plugin. */
static transcript_t *open_convertor(const char *normalized_name, const char *real_name, int flags, transcript_error_t *error) {
	lt_dlhandle handle = NULL;
	int (*get_iface)(void);
	transcript_t *result = NULL;
	char base_name[NORMALIZE_NAME_MAX];

	transcript_get_option(real_name, base_name, NORMALIZE_NAME_MAX, NULL);

	if ((handle = _transcript_db_open(base_name, "tct", (open_func_t) lt_dlopen, error)) == NULL) {
		FILE *test_handle;
		transcript_error_t local_error;
		if ((test_handle = _transcript_db_open(base_name, "tct", (open_func_t) fopen, &local_error)) == NULL)
			ERROR(local_error);
		ERROR(TRANSCRIPT_DLOPEN_FAILURE);
	}

	transcript_get_option(normalized_name, base_name, NORMALIZE_NAME_MAX, NULL);

	if ((get_iface = get_sym(handle, "transcript_get_iface_", base_name)) == NULL)
		ERROR(TRANSCRIPT_INVALID_FORMAT);

	switch (get_iface()) {
		case TRANSCRIPT_STATE_TABLE_V1: {
			const convertor_tables_v1_t *(*get_table)(void);
			if ((get_table = get_sym(handle, "transcript_get_table_", base_name)) == NULL)
				ERROR(TRANSCRIPT_INVALID_FORMAT);
			if ((result = _transcript_open_cct_convertor(get_table(), flags, error)) != NULL) {
				result->library_handle = handle;
				return result;
			}
			break;
		}
		case TRANSCRIPT_FULL_MODULE_V1: {
			transcript_t *(*open_convertor)(const char *, int flags, transcript_error_t *);
			if ((open_convertor = get_sym(handle, "transcript_open_", base_name)) == NULL)
				ERROR(TRANSCRIPT_INVALID_FORMAT);
			if ((result = open_convertor(normalized_name, flags, error)) != NULL) {
				result->library_handle = handle;
				return result;
			}
			break;
		}
		default:
			ERROR(TRANSCRIPT_INVALID_FORMAT);
	}

end_error:
	if (handle != NULL)
		lt_dlclose(handle);
	return result;
}

/** Reentrant version of strtok
	@param string The string to tokenise.
	@param separators The list of token separators.
	@param state A user allocated character pointer.

	This function emulates the functionality of the Un*x function strtok_r.
	Note that this function destroys the contents of @a string.
*/
static char *ts_strtok(char *string, const char *separators, char **state) {
	char *retval;
	if (string != NULL)
		*state = string;

	/* Skip to the first character that is not in 'separators' */
	while (**state != 0 && strchr(separators, **state) != NULL) (*state)++;
	retval = *state;
	if (*retval == 0)
		return NULL;
	/* Skip to the first character that IS in 'separators' */
	while (**state != 0 && strchr(separators, **state) == NULL) (*state)++;
	if (**state != 0) {
		/* Overwrite it with 0 */
		**state = 0;
		/* Advance the state pointer so we know where to start next time */
		(*state)++;
	}
	return retval;
}

/** Try to open a file from a database directory.
    @param name The base name of the file to open.
    @param ext The extension of the file to open.
    @param dir The directory to look in.
    @param error The location to store a possible error.
    @return A @c FILE pointer on success, or @c NULL on failure.
*/
static FILE *db_open(const char *name, const char *ext, const char *dir, open_func_t open_func, transcript_error_t *error) {
	char *file_name = NULL;
	void *result = NULL;
	size_t len;

	len = strlen(dir) + strlen(name) + 2 + strlen(ext) + 1;
	if ((file_name = malloc(len)) == NULL)
		ERROR(TRANSCRIPT_OUT_OF_MEMORY);

	strcpy(file_name, dir);
	strcat(file_name, "/"); /* Even on Windows, / is recognised as directory separator internally. */
	strcat(file_name, name);
	strcat(file_name, ".");
	strcat(file_name, ext);

	if ((result = open_func(file_name, "r")) == NULL)
		ERROR(TRANSCRIPT_ERRNO);

end_error:
	free(file_name);
	return result;
}

/** @internal
    @brief Open a file from the database directory.
    @param name The base name of the file to open.
    @param ext The extension of the file to open.
    @param error The location to store a possible error.
    @return A @c FILE pointer on success, or @c NULL on failure.

    This function first looks in the diretory named in the TRANSCRIPT_PATH
    environment variable (if set), and then in the compiled in database
    directory.
*/
void *_transcript_db_open(const char *name, const char *ext, open_func_t open_func, transcript_error_t *error) {
	const char **next_dir;
	FILE *result;

	for (next_dir = search_path; *next_dir != NULL; next_dir++) {
		if ((result = db_open(name, ext, *next_dir, open_func, error)) != NULL)
			return result;
	}
	return NULL;
}

#ifndef HAS_STRDUP
/** @internal
    @brief Copy a string.

    This function is provided when there is no strdup function in the C library.
*/
char *_transcript_strdup(const char *str) {
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
    @brief Initialize the character information bitmap used for ::_transcript_isXXXXX and ::_transcript_tolower.
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
int _transcript_isalnum(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_ALNUM); }
/** @internal @brief Execution-character-set isdigit. */
int _transcript_isdigit(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_DIGIT); }
/** @internal @brief Execution-character-set isspace. */
int _transcript_isspace(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_SPACE); }
/** @internal @brief Checks whether a character is considered an identifier character (used in ::_transcript_normalize_name). */
int _transcript_isidchr(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & (IS_IDCHR_EXTRA | IS_ALNUM)); }
/** @internal @brief Execution-character-set tolower. */
int _transcript_tolower(int c) { return (c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_UPPER)) ? 'a' + (c - 'A') : c; }

/** @internal
    @brief Perform the action described at ::transcript_normalize_name.

    This function does not call ::_transcript_init, which ::transcript_normalize_name
    does. However, ::_transcript_init only needs to be called once, so if we
    know it has already been called, we don't need to check again. Therefore,
    in the library itself we use this stripped down version.
*/
void _transcript_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max) {
	size_t write_idx = 0;
	bool last_was_digit = false;

	for (; *name != 0 && write_idx < normalized_name_max - 1; name++) {
		if (*name == ',') {
			for (; *name != 0 && write_idx < normalized_name_max - 1; name++)
				normalized_name[write_idx++] = _transcript_tolower(*name);
			break;
		}
		if (!_transcript_isalnum(*name)) {
			last_was_digit = false;
		} else {
			if (!last_was_digit && *name == '0')
				continue;
			normalized_name[write_idx++] = _transcript_tolower(*name);
			last_was_digit = _transcript_isdigit(*name);
		}
	}
	normalized_name[write_idx] = 0;
}

/** Get the minimum of two @c size_t values. */
static _TRANSCRIPT_INLINE size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

/** Read an option from a name into a buffer. */
bool transcript_get_option(const char *name, char *option_buffer, size_t option_buffer_max, const char *option_name) {
	const char *comma;
	size_t len;

	if (option_name == NULL) {
		if ((comma = strchr(name, ',')) == NULL) {
			strncpy(option_buffer, name, option_buffer_max - 1);
			option_buffer[option_buffer_max - 1] = 0;
		} else {
			len = min(option_buffer_max - 1, comma - name);
			strncpy(option_buffer, name, len);
			option_buffer[len] = 0;
		}
		return true;
	} else {
		len = strlen(option_name);
		comma = name;
		while ((comma = strchr(comma, ',')) != NULL) {
			comma++;
			if (strncmp(comma, option_name, len) == 0) {
				if (comma[len] == '=')
					return transcript_get_option(comma + len + 1, option_buffer, option_buffer_max, NULL);
				option_buffer[0] = 0;
				return true;
			}
		}
		return false;
	}
}

/** @internal
    @brief Get a generic fallback.
*/
uint32_t transcript_get_generic_fallback(uint32_t codepoint) {
	return get_generic_fallback(codepoint);
}

/** @internal
    @brief Handle an unassigned codepoint in a from-Unicode conversion.

    This function does a lookup in the generic fall-back table. If no generic
    fall-back is found, this function simply returns ::TRANSCRIPT_UNASSIGNED.
    Otherwise, it handles conversion of the generic fall-back as if it were
    specified in the convertor table.
*/
transcript_error_t transcript_handle_unassigned(transcript_t *handle, uint32_t codepoint, char **outbuf,
		const char *outbuflimit, int flags)
{
	get_unicode_func_t saved_get_unicode_func;
	const char *fallback_ptr;
	transcript_error_t result;

	if ((codepoint = get_generic_fallback(codepoint)) != UINT32_C(0xFFFF)) {
		if (!(flags & TRANSCRIPT_ALLOW_FALLBACK))
			return TRANSCRIPT_FALLBACK;
		saved_get_unicode_func = handle->get_unicode;
		handle->get_unicode = _transcript_get_utf32_no_check;
		fallback_ptr = (const char *) &codepoint;

		result = handle->convert_from(handle, &fallback_ptr, fallback_ptr + sizeof(uint32_t),
			outbuf, outbuflimit, flags | TRANSCRIPT_SINGLE_CONVERSION | TRANSCRIPT_NO_1N_CONVERSION);
		handle->get_unicode = saved_get_unicode_func;
		switch (result) {
			case TRANSCRIPT_NO_SPACE:
			case TRANSCRIPT_UNASSIGNED:
			case TRANSCRIPT_SUCCESS:
			case TRANSCRIPT_FALLBACK:
				return result;
			default:
				return TRANSCRIPT_INTERNAL_ERROR;
		}
	}
	return TRANSCRIPT_UNASSIGNED;
}

/** Append a directory to the search path. */
static void add_search_dir(const char *dir) {
	static int path_idx, path_size;

	if (path_idx >= path_size) {
		const char **tmp;
		if ((tmp = realloc(search_path, sizeof(search_path[0]) * (path_size + 8 + 1))) == NULL)
			return;
		search_path = tmp;
		path_size += 8;
	}
	search_path[path_idx++] = dir;
	/* Note that we always allocate one extra element for this purpose, which is
	   not accounted for in path_size. */
	search_path[path_idx] = NULL;
}

/** @internal
    @brief Initialize the parts of the library that can not be handled in a
         thread-safe manner.

    This function initializes the gettext domain for the library, the character
    info for ::transcript_normalize_name and the list of aliases. Note that it
    does not load the availability of the aliases.
*/
void _transcript_init(void) {
	static bool initialized = false;

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
		ACQUIRE_LOCK();
		if (!initialized) {
			char *transcript_path, *search_path_element, *state;
			/* Initialize aliases defined in the aliases.txt file. This does not
			   check availability, nor does it build the complete set of display
			   names. That will be done when that list is requested. */
			#ifdef USE_GETTEXT
			bindtextdomain("libtranscript", LOCALEDIR);
			#endif
			init_char_info();
			lt_dlinit();

			if ((transcript_path = getenv("TRANSCRIPT_PATH")) != NULL) {
				if ((transcript_path = _transcript_strdup(transcript_path)) != NULL) {
					for (search_path_element = ts_strtok(transcript_path, path_sep, &state);
							search_path_element != NULL; ts_strtok(NULL, path_sep, &state))
						add_search_dir(search_path_element);
				}
			}
			if ((transcript_path = getenv("HOME")) != NULL) {
				if ((search_path_element = malloc(strlen(transcript_path) + 1 + 10 + 1)) != NULL) {
					strcpy(search_path_element, transcript_path);
					strcat(search_path_element, "/"); /* Windows also recognises / as directory separator internally. */
					strcat(search_path_element, ".transcript");
					add_search_dir(search_path_element);
				}
			}
			if ((transcript_path = _transcript_strdup(DB_DIRECTORY)) != NULL) {
				for (search_path_element = ts_strtok(transcript_path, path_sep, &state);
						search_path_element != NULL; search_path_element = ts_strtok(NULL, path_sep, &state))
					add_search_dir(search_path_element);
			}
			_transcript_init_aliases_from_file();
		}
		initialized = true;
		RELEASE_LOCK();
	}
}

/** @internal
    @brief Write a log message to standard error, but only if the TRANSCRIPT_LOG
        environment variable has been set.

    Calls vfprintf internally, so all printf specifiers available on the platform
    may be used.
*/
void _transcript_log(const char *fmt, ...) {
	if (getenv("TRANSCRIPT_LOG") != NULL) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

/** @} */
