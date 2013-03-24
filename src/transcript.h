/* Copyright (C) 2011,2013 G.P. Halkes
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
#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include <transcript/api.h>

/** @defgroup transcript Native transcript interface. */
/** @addtogroup transcript */
/** @{ */

/** The version of libtranscript encoded as a single integer.

    The least significant 8 bits represent the patch level.
    The second 8 bits represent the minor version.
    The third 8 bits represent the major version.

    At runtime, the value of TRANSCRIPT_VERSION can be retrieved by calling
    ::transcript_get_version.

    @internal
    The value 0 is an invalid value which should be replaced by the script
    that builds the release package.
*/
#define TRANSCRIPT_VERSION 0

/** @struct transcript_t
    An opaque structure describing a converter and its state.
*/
typedef struct transcript_t transcript_t;

/** Flags for converters and conversions. */
enum transcript_flags_t {
	TRANSCRIPT_ALLOW_FALLBACK = (1<<0), /**< Include fallback characters in the conversion.

	    This flag is only used by ::transcript_from_unicode.
	*/
	TRANSCRIPT_SUBST_UNASSIGNED = (1<<1), /**< Automatically replace unmappable characters by substitute characters. */
	TRANSCRIPT_SUBST_ILLEGAL = (1<<2), /**< Automatically insert a substitution character on illegal input. */
	TRANSCRIPT_ALLOW_PRIVATE_USE = (1<<3), /**< Allow private-use mappings. If not allowed, they are handled like unassigned sequences, with the exception that they return a different error.. */

	/* These are only valid as argument to transcript_from_unicode and transcript_to_unicode. */
	TRANSCRIPT_FILE_START = (1<<8), /**< The begining of the input buffer is the begining of a file and a BOM should be expected/generated. */
	/** The end of the input buffer is the end of the text.

	    This flag is only valid when passed to ::transcript_from_unicode or ::transcript_to_unicode.

	    @note This flag is only used to determine whether an incomplete sequence
	    at the end of the buffer is allowed or not. Clients still need to call
	    ::transcript_from_unicode_flush to properly end the output buffer.
	*/
	TRANSCRIPT_END_OF_TEXT = (1<<9),
	/** Only convert the next character, then return (useful for handling fallback/unassigned characters etc).

	    This flag is only valid when passed to ::transcript_from_unicode or ::transcript_to_unicode.
	*/
	TRANSCRIPT_SINGLE_CONVERSION = (1<<10),
	/** Do not use M:N conversions.

	    This flag is only valid when passed to ::transcript_from_unicode or ::transcript_to_unicode.
	*/
	TRANSCRIPT_NO_MN_CONVERSION = (1<<11),
	/** Do not use 1:N conversions. Implies ::TRANSCRIPT_NO_MN_CONVERSION.

	    This flag is only valid when passed to ::transcript_from_unicode or ::transcript_to_unicode.
	*/
	TRANSCRIPT_NO_1N_CONVERSION = (1<<12)

	/* NOTE: internal flags are defined in transcript_internal.h and moduledefs.h. Make sure these don't overlap! */
};

/** Error values. */
typedef enum {
	TRANSCRIPT_SUCCESS, /**< All OK. */
	TRANSCRIPT_NO_SPACE, /**< There was no space left in the output buffer. */
	TRANSCRIPT_INCOMPLETE, /**< The buffer ended with an incomplete sequence, or more data was needed to verify a M:N conversion. */

	TRANSCRIPT_FALLBACK, /**< The next character to convert is a fallback mapping. */
	TRANSCRIPT_UNASSIGNED, /**< The next character to convert is an unassigned sequence. */
	TRANSCRIPT_ILLEGAL, /**< The input is an illegal sequence. */
	TRANSCRIPT_ILLEGAL_END, /**< The end of the input does not form a valid sequence. */
	TRANSCRIPT_INTERNAL_ERROR, /**< The transcript library screwed up; no recovery possible. */
	TRANSCRIPT_PRIVATE_USE, /**< The next character to convert maps to a private use codepoint. */

	TRANSCRIPT_ERRNO, /**< See errno for error code. */
	TRANSCRIPT_BAD_ARG, /**< Bad argument. */
	TRANSCRIPT_OUT_OF_MEMORY, /**< Out of memory. */
	TRANSCRIPT_INVALID_FORMAT, /**< Invalid format while reading conversion map. */
	TRANSCRIPT_TRUNCATED_MAP, /**< Tried to read a truncated conversion map. */
	TRANSCRIPT_WRONG_VERSION, /**< Conversion map is of an unsupported version. */
	TRANSCRIPT_INTERNAL_TABLE, /**< Tried to load a table that is for internal use only. */
	TRANSCRIPT_DLOPEN_FAILURE, /**< Opening if the plugin failed. */
	TRANSCRIPT_CONVERTER_DISABLED, /**< The converter has been explicitly disabled. */
	TRANSCRIPT_PACKAGE_FILE, /**< The converter name references a converter package file, not an actual converter. */
	TRANSCRIPT_INIT_DLFCN, /**< Could not initialize dynamic module loading functionality. */
	TRANSCRIPT_NOT_INITIALIZED, /**< ::transcript_init has not been called yet. */

	TRANSCRIPT_PART_SUCCESS_MAX = TRANSCRIPT_INCOMPLETE /**< Highest error code which indicates success or end-of-buffer. */

} transcript_error_t;

typedef enum {
	TRANSCRIPT_UTF8 = 1,
	TRANSCRIPT_UTF16,
	TRANSCRIPT_UTF32,
	TRANSCRIPT_UTF16BE,
	TRANSCRIPT_UTF16LE,
	TRANSCRIPT_UTF32BE,
	TRANSCRIPT_UTF32LE,
	_TRANSCRIPT_UTFLAST
} transcript_utf_t;


#ifndef _TRANSCRIPT_CONST
#define _TRANSCRIPT_CONST const
#endif

/** @struct transcript_name_t
    A structure holding a display name and availability information about a converter.
*/
typedef struct {
	_TRANSCRIPT_CONST char *name; /**< The (display) name of the converter. */
	int available; /**< A boolean indicating whether the converter is available.

	@note If availability is indicated, a load failure may still occur if the
	conversion table is corrupt. */
} transcript_name_t;

/** Required size of a buffer for saving converter state. */
#define TRANSCRIPT_SAVE_STATE_SIZE 32

TRANSCRIPT_API transcript_error_t transcript_init(void);
TRANSCRIPT_API void transcript_finalize(void);
TRANSCRIPT_API int transcript_probe_converter(const char *name);
TRANSCRIPT_API transcript_t *transcript_open_converter(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error);
TRANSCRIPT_API void transcript_close_converter(transcript_t *handle);
TRANSCRIPT_API int transcript_equal(const char *name_a, const char *name_b);
TRANSCRIPT_API transcript_error_t transcript_to_unicode(transcript_t *handle, const char **inbuf,
	const char *inbuflimit, char **outbuf, const char *outbuflimit, int flags);
TRANSCRIPT_API transcript_error_t transcript_from_unicode(transcript_t *handle, const char **inbuf,
	const char *inbuflimit, char **outbuf, const char *outbuflimit, int flags);
TRANSCRIPT_API transcript_error_t transcript_to_unicode_skip(transcript_t *handle, const char **inbuf, const char *inbuflimit);
TRANSCRIPT_API transcript_error_t transcript_from_unicode_skip(transcript_t *handle, const char **inbuf, const char *inbuflimit);
TRANSCRIPT_API transcript_error_t transcript_from_unicode_flush(transcript_t *handle, char **outbuf, const char *outbuflimit);
TRANSCRIPT_API void transcript_to_unicode_reset(transcript_t *handle);
TRANSCRIPT_API void transcript_from_unicode_reset(transcript_t *handle);
TRANSCRIPT_API void transcript_save_state(transcript_t *handle, void *state);
/*FIXME: should we do loading (and perhaps saving) per direction?*/
TRANSCRIPT_API void transcript_load_state(transcript_t *handle, void *state);
TRANSCRIPT_API const char *transcript_strerror(transcript_error_t error);
TRANSCRIPT_API const transcript_name_t *transcript_get_names(int *count);
TRANSCRIPT_API void transcript_normalize_name(const char *name, char *normalized_name, size_t normalized_name_max);
TRANSCRIPT_API const char *transcript_get_codeset(void);
TRANSCRIPT_API long transcript_get_version(void);

/** Minimum required size for an output buffer for ::transcript_to_unicode, if M:N conversion are allowed. */
#define TRANSCRIPT_MIN_UNICODE_BUFFER_SIZE (4*20)
/** Minimum required size for an output buffer for ::transcript_from_unicode, if M:N conversion are allowed. */
#define TRANSCRIPT_MIN_CODEPAGE_BUFFER_SIZE (32)
/** Minimum required size for an output buffer for either ::transcript_to_unicode or
    ::transcript_from_unicode, if M:N conversion are allowed. */
#define TRANSCRIPT_MIN_BUFFER_SIZE TRANSCRIPT_MIN_UNICODE_BUFFER_SIZE

/** @} */

#if defined(TRANSCRIPT_ICONV_API) || defined(TRANSCRIPT_ICONV)

/** @defgroup transcript_iconv Iconv compatible interface.
    This interface allows very limited control over the conversion and
    is only provided for systems without an iconv library. To make the interface
    available, define @c TRANSCRIPT_ICONV_API before including the @c transcript.h
    header. If you want the interface to be available without the @c cc_ prefix,
    as well, define @c TRANSCRIPT_ICONV instead.
*/
/** @addtogroup transcript_iconv */
/** @{ */

/** @struct transcript_iconv_t
    An opaque handle representing the transcript_iconv state.
*/
typedef struct _transcript_iconv_t *transcript_iconv_t;

TRANSCRIPT_API transcript_iconv_t transcript_iconv_open(const char *tocode, const char *fromcode);
TRANSCRIPT_API int transcript_iconv_close(transcript_iconv_t cd);
TRANSCRIPT_API size_t transcript_iconv(transcript_iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);

/** @} */

#ifdef TRANSCRIPT_ICONV
typedef transcript_iconv_t iconv_t;
#define iconv(_a, _b, _c, _d, _e) transcript_iconv((_a), (_b), (_c), (_d), (_e))
#define iconv_open(_a, _b) transcript_iconv_open((_a), (_b))
#define iconv_close(_a) transcript_iconv_close(_a)
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
