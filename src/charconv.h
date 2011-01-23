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
#ifndef CHARCONV_H
#define CHARCONV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#if defined _WIN32 || defined __CYGWIN__
	#define CHARCONV_EXPORT __declspec(dllexport)
	#define CHARCONV_IMPORT __declspec(dllimport)
	#define CHARCONV_LOCAL
#else
	#if __GNUC__ >= 4
		#define CHARCONV_EXPORT __attribute__((visibility("default")))
		#define CHARCONV_IMPORT __attribute__((visibility("default")))
		#define CHARCONV_LOCAL __attribute__((visibility("hidden")))
	#else
		#define CHARCONV_EXPORT
		#define CHARCONV_IMPORT
		#define CHARCONV_LOCAL
	#endif
#endif

#ifdef CHARCONV_BUILD_DSO
	#define CHARCONV_API CHARCONV_EXPORT
#else
	#define CHARCONV_API CHARCONV_IMPORT
#endif

typedef struct charconv_common_t charconv_t;

//FIXME: do we want to somehow communicate counts of fallbacks/substitutes etc?

enum {
	CHARCONV_ALLOW_FALLBACK = (1<<0), /**< Include fallback characters in the conversion. */
	CHARCONV_SUBST_UNASSIGNED = (1<<1), /**< Automatically replace unmappable characters by substitute characters. */
	CHARCONV_SUBST_ILLEGAL = (1<<2), /**< Automatically insert a substitution character on illegal input. */
	CHARCONV_ALLOW_PRIVATE_USE = (1<<3), /**< Allow private-use mappings. If not allowed, they are handled like unassigned sequences, with the exception that they return a different error.. */

	/* These are only valid as argument to charconv_from_unicode and charconv_to_unicode. */
	CHARCONV_FILE_START = (1<<8), /**< The begining of the input buffer is the begining of a file and a BOM should be expected/generated. */
	CHARCONV_END_OF_TEXT = (1<<9), /**< The end of the input buffer is the end of the text. */
	CHARCONV_SINGLE_CONVERSION = (1<<10), /**< Only convert the next character, then return (useful for handling fallback/unassigned characters etc.). */
	CHARCONV_NO_MN_CONVERSION = (1<<11), /**< Do not use M:N conversions. */
	CHARCONV_NO_1N_CONVERSION = (1<<12) /**< Do not use 1:N conversions. Implies ::CHARCONV_NO_MN_CONVERSION  */

	/* NOTE: internal flags are defined in charconv_internal.h. Make sure these don't overlap! */
};

typedef enum {
	CHARCONV_SUCCESS, /**< All OK. */
	CHARCONV_NO_SPACE, /**< There was no space left in the output buffer. */
	CHARCONV_INCOMPLETE, /**< The buffer ended with an incomplete sequence, or more data was needed to verify a M:N conversion. */

	CHARCONV_FALLBACK, /**< The next character to convert is a fallback mapping. */
	CHARCONV_UNASSIGNED, /**< The next character to convert is an unassigned sequence. */
	CHARCONV_ILLEGAL, /**< The input is an illegal sequence. */
	CHARCONV_ILLEGAL_END, /**< The end of the input does not form a valid sequence. */
	CHARCONV_INTERNAL_ERROR, /**< The charconv library screwed up; no recovery possible. */
	CHARCONV_PRIVATE_USE, /**< The next character to convert maps to a private use codepoint. */

	CHARCONV_ERRNO, /**< See errno for error code. */
	CHARCONV_BAD_ARG, /**< Bad argument. */
	CHARCONV_OUT_OF_MEMORY, /**< Out of memory. */
	CHARCONV_INVALID_FORMAT, /**< Invalid format while reading conversion map. */
	CHARCONV_TRUNCATED_MAP, /**< Tried to read a truncated conversion map. */
	CHARCONV_WRONG_VERSION, /**< Conversion map is of an unsupported version. */
	CHARCONV_INTERNAL_TABLE, /**< Tried to load a table that is for internal use only. */

	CHARCONV_PART_SUCCESS_MAX = CHARCONV_INCOMPLETE /**< Highest error code which indicates success or end-of-buffer. */

} charconv_error_t;

typedef enum {
	CHARCONV_UTF8 = 1,
	CHARCONV_UTF16,
	CHARCONV_UTF32,
	CHARCONV_UTF16BE,
	CHARCONV_UTF16LE,
	CHARCONV_UTF32BE,
	CHARCONV_UTF32LE,
	_CHARCONV_UTFLAST
} charconv_utf_t;


/* I would rather not define these here, but I need them for the definition of
   CHARCONV_SAVE_STATE_SIZE. */
struct _charconv_cct_state_t {
	uint8_t to, from;
};

struct _charconv_unicode_state_t {
	uint_fast32_t utf7_put_save;
	uint_fast8_t utf7_get_mode;
	uint_fast8_t utf7_put_mode;
};

struct _charconv_iso2022_cct_handle_t;

struct _charconv_iso2022_state_t {
	struct _charconv_iso2022_cct_handle_t *g_to[4]; /* Shifted-in sets. */
	struct _charconv_iso2022_cct_handle_t *g_from[4]; /* Shifted-in sets. */
	uint_fast8_t to, from;
};

#define _CHARCONV_MAX(a, b) ((a) > (b) ? (a) : (b))
#define CHARCONV_SAVE_STATE_SIZE _CHARCONV_MAX(_CHARCONV_MAX(sizeof(struct _charconv_cct_state_t), \
	sizeof(struct _charconv_unicode_state_t)), sizeof(struct _charconv_iso2022_state_t))

CHARCONV_API int charconv_probe_convertor(const char *name);
CHARCONV_API charconv_t *charconv_open_convertor(const char *name, charconv_utf_t utf_type, int flags, charconv_error_t *error);
CHARCONV_API void charconv_close_convertor(charconv_t *handle);
CHARCONV_API charconv_error_t charconv_to_unicode(charconv_t *handle, const char **inbuf,
	const char *inbuflimit, char **outbuf, const char *outbuflimit, int flags);
CHARCONV_API charconv_error_t charconv_from_unicode(charconv_t *handle, const char **inbuf,
	const char *inbuflimit, char **outbuf, const char *outbuflimit, int flags);
CHARCONV_API charconv_error_t charconv_to_unicode_skip(charconv_t *handle, const char **inbuf, const char *inbuflimit);
CHARCONV_API charconv_error_t charconv_from_unicode_skip(charconv_t *handle, const char **inbuf, const char *inbuflimit);
CHARCONV_API charconv_error_t charconv_from_unicode_flush(charconv_t *handle, char **outbuf, const char *outbuflimit);
CHARCONV_API void charconv_to_unicode_reset(charconv_t *handle);
CHARCONV_API void charconv_from_unicode_reset(charconv_t *handle);
CHARCONV_API void charconv_save_state(charconv_t *handle, void *state);
//FIXME: should we do loading (and perhaps saving) per direction?
CHARCONV_API void charconv_load_state(charconv_t *handle, void *state);
//FIXME: add a listing mechanism!
CHARCONV_API const char *charconv_strerror(charconv_error_t error);
CHARCONV_API const char const * const *charconv_get_names(int *count);

#define CHARCONV_MIN_UNICODE_BUFFER_SIZE (4*20)
#define CHARCONV_MIN_CODEPAGE_BUFFER_SIZE (32)
#define CHARCONV_MIN_BUFFER_SIZE CHARCONV_MIN_UNICODE_BUFFER_SIZE

#if defined(CHARCONV_ICONV_API) || defined(CHARCONV_ICONV)

typedef struct _cc_iconv_t *cc_iconv_t;

CHARCONV_API cc_iconv_t cc_iconv_open(const char *tocode, const char *fromcode);
CHARCONV_API int cc_iconv_close(cc_iconv_t cd);
CHARCONV_API size_t cc_iconv(cc_iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);

#ifdef CHARCONV_ICONV
typedef cc_iconv_t iconv_t;
#define iconv(_a, _b, _c, _d, _e) cc_iconv((_a), (_b), (_c), (_d), (_e))
#define iconv_open(_a, _b) cc_iconv_open((_a), (_b))
#define iconv_close(_a) cc_iconv_close(_a)
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
