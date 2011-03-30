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

/*FIXME: use gettext for this one*/
#define _(x) x

static charconv_t *try_convertors(const char *squashed_name, const char *real_name, int flags, charconv_error_t *error);

/*================ API functions ===============*/
int _charconv_probe_convertor(const char *name) {
	charconv_name_desc_t *convertor;
	char squashed_name[SQUASH_NAME_MAX];

	_charconv_squash_name(name, squashed_name, SQUASH_NAME_MAX);

	if ((convertor = _charconv_get_name_desc(squashed_name)) != NULL)
		return try_convertors(convertor->name, convertor->real_name, CHARCONV_PROBE_ONLY, NULL) != NULL;
	return try_convertors(squashed_name, name, CHARCONV_PROBE_ONLY, NULL) != NULL;
}

int charconv_probe_convertor(const char *name) {
	_charconv_init();
	return _charconv_probe_convertor(name);
}

charconv_t *charconv_open_convertor(const char *name, charconv_utf_t utf_type, int flags, charconv_error_t *error) {
	charconv_name_desc_t *convertor;
	char squashed_name[SQUASH_NAME_MAX];

	_charconv_init();

	if (utf_type > CHARCONV_UTF32LE || utf_type <= 0) {
		if (error != NULL)
			*error = CHARCONV_BAD_ARG;
		return NULL;
	}

	_charconv_squash_name(name, squashed_name, SQUASH_NAME_MAX);

	if ((convertor = _charconv_get_name_desc(squashed_name)) != NULL)
		return _charconv_fill_utf(try_convertors(convertor->name, convertor->real_name, flags, error), utf_type);
	return _charconv_fill_utf(try_convertors(squashed_name, name, flags, error), utf_type);
}

void charconv_close_convertor(charconv_t *handle) {
	if (handle != NULL)
		handle->close(handle);
}

charconv_error_t charconv_to_unicode(charconv_t *handle, const char const **inbuf, const char const *inbuflimit, char **outbuf,
		const char const *outbuflimit, int flags)
{
	return handle->convert_to(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags | (handle->flags & 0xff));
}

charconv_error_t charconv_from_unicode(charconv_t *handle, const char **inbuf, const char const *inbuflimit, char **outbuf,
		const char const *outbuflimit, int flags) {
	return handle->convert_from(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags | (handle->flags & 0xff));
}

charconv_error_t charconv_to_unicode_skip(charconv_t *handle, const char **inbuf, const char const *inbuflimit) {
	return handle->skip_to(handle, inbuf, inbuflimit);
}

charconv_error_t charconv_from_unicode_skip(charconv_t *handle, const char **inbuf, const char *inbuflimit) {
	if (handle->get_unicode(inbuf, inbuflimit, true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}

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

void charconv_to_unicode_reset(charconv_t *handle) {
	handle->reset_to(handle);
}

void charconv_from_unicode_reset(charconv_t *handle) {
	handle->reset_from(handle);
}

void charconv_save_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

void charconv_load_state(charconv_t *handle, void *state) {
	handle->save(handle, state);
}

const char *charconv_strerror(charconv_error_t error) {
	switch (error) {
		case CHARCONV_SUCCESS:
			return _("Success");
		case CHARCONV_FALLBACK:
			return _("Only a fallback mapping is available");
		case CHARCONV_UNASSIGNED:
			return _("Character can not be mapped");
		case CHARCONV_ILLEGAL:
			return _("Illegal sequence in input buffer");
		case CHARCONV_ILLEGAL_END:
			return _("Illegal sequence at end of input buffer");
		default:
		case CHARCONV_INTERNAL_ERROR:
			return _("Internal error");
		case CHARCONV_PRIVATE_USE:
			return _("Character maps to a private use codepoint");
		case CHARCONV_NO_SPACE:
			return _("No space left in output buffer");
		case CHARCONV_INCOMPLETE:
			return _("Incomplete character at end of input buffer");
		case CHARCONV_ERRNO:
			return strerror(errno);
		case CHARCONV_BAD_ARG:
			return _("Bad argument");
		case CHARCONV_OUT_OF_MEMORY:
			return _("Out of memory");
		case CHARCONV_INVALID_FORMAT:
			return _("Invalid map-file format");
		case CHARCONV_TRUNCATED_MAP:
			return _("Map file is truncated");
		case CHARCONV_WRONG_VERSION:
			return _("Map file is of an unsupported version");
		case CHARCONV_INTERNAL_TABLE:
			return _("Map file is for internal use only");
	}
}

void charconv_squash_name(const char *name, char *squashed_name, size_t squashed_name_max) {
	_charconv_init();
	_charconv_squash_name(name, squashed_name, squashed_name_max);
}

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

charconv_t *_charconv_fill_utf(charconv_t *handle, charconv_utf_t utf_type) {
	if (handle == NULL)
		return NULL;
	handle->get_unicode = _charconv_get_get_unicode(utf_type);
	handle->put_unicode = _charconv_get_put_unicode(utf_type);
	return handle;
}

int _charconv_element_strcmp(const void *a, const void *b) {
	return strcmp((const char *) a, *(char * const *) b);
}

static charconv_t *try_convertors(const char *squashed_name, const char *real_name, int flags, charconv_error_t *error) {
	charconv_t *result;
	if ((result = _charconv_open_unicode_convertor(squashed_name, flags, error)) != NULL)
		return result;
	if ((result = _charconv_open_iso8859_1_convertor(squashed_name, flags, error)) != NULL)
		return result;
	if ((result = _charconv_open_iso2022_convertor(squashed_name, flags, error)) != NULL)
		return result;
	return _charconv_open_cct_convertor(real_name, flags, error);
}

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

FILE *_charconv_db_open(const char *name, const char *ext, charconv_error_t *error) {
	FILE *result;
	const char *dir = getenv("CHARCONV_PATH");
	/*FIXME: allow colon delimited list*/
	if (dir != NULL && (result = try_db_open(name, ext, dir, error)) != NULL)
		return result;
	return try_db_open(name, ext, DB_DIRECTORY, error);
}

#ifndef HAS_STRDUP
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
#define IS_ALNUM (1<<0)
#define IS_DIGIT (1<<1)
#define IS_UPPER (1<<2)
#define IS_SPACE (1<<3)
#define IS_IDCHR_EXTRA (1<<4)
static char char_info[CHAR_MAX];

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

int _charconv_isalnum(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_ALNUM); }
int _charconv_isdigit(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_DIGIT); }
int _charconv_isspace(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_SPACE); }
int _charconv_isidchr(int c) { return c >= 0 && c <= CHAR_MAX && (char_info[c] & (IS_IDCHR_EXTRA | IS_ALNUM)); }
int _charconv_tolower(int c) { return (c >= 0 && c <= CHAR_MAX && (char_info[c] & IS_UPPER)) ? 'a' + (c - 'A') : c; }

void _charconv_squash_name(const char *name, char *squashed_name, size_t squashed_name_max) {
	size_t write_idx = 0;
	bool last_was_digit = false;

	for (; *name != 0 && write_idx < squashed_name_max - 1; name++) {
		if (!_charconv_isalnum(*name) && *name != ',') {
			last_was_digit = false;
		} else {
			if (!last_was_digit && *name == '0')
				continue;
			squashed_name[write_idx++] = _charconv_tolower(*name);
			last_was_digit = _charconv_isdigit(*name);
		}
	}
	squashed_name[write_idx] = 0;
}

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

void _charconv_init(void) {
	static bool initialized = false;
#ifndef WITHOUT_PTHREAD
	static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

	if (!initialized) {
		PTHREAD_ONLY(pthread_mutex_lock(&init_mutex));
		if (!initialized) {
			/* Initialize aliases defined in the aliases.txt file. This does not
			   check availability, nor does it build the complete set of display
			   names. That will be done when that list is requested. */
			init_char_info();
			_charconv_init_aliases_from_file();
		}
		initialized = true;
		PTHREAD_ONLY(pthread_mutex_unlock(&init_mutex));
	}
}
