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
#include <string.h>
#include "transcript_internal.h"
#include "utf.h"
#include "static_assert.h"

enum {
	INTERNAL_TABLE = (1<<0)
};

/** @struct converter_state_t
    Structure holding the pointers to the data and the state of a state table converter. */
typedef struct {
	transcript_t common;
	sbcs_converter_v1_t tables;
} converter_state_t;

static transcript_error_t to_unicode_skip(converter_state_t *handle, const char **inbuf, const char const *inbuflimit);

/** Simplification macro for calling put_unicode which returns automatically on error. */
#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbuflimit)) != TRANSCRIPT_SUCCESS) \
		return result; \
} while (0)

/** convert_to implementation for SBCS table converters. */
static transcript_error_t to_unicode_conversion(converter_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;

	while (*inbuf < inbuflimit) {
		codepoint = handle->tables.byte_to_codepoint[*(const uint8_t *) *inbuf];

		if (codepoint < 0xfffe) {
			if (handle->tables.byte_to_codepoint_flags != NULL && !(flags & TRANSCRIPT_ALLOW_FALLBACK) &&
					(handle->tables.byte_to_codepoint_flags[(*(const uint8_t *) *inbuf) >> 3] & (1 << ((*(const uint8_t *) *inbuf) & 7))))
				return TRANSCRIPT_FALLBACK;
			if (codepoint >= 0xe000 && codepoint < 0xf900 && !(flags & TRANSCRIPT_ALLOW_PRIVATE_USE))
				return TRANSCRIPT_PRIVATE_USE;
			PUT_UNICODE(codepoint);
		} else if (codepoint == 0xffff) {
			if (flags & TRANSCRIPT_SUBST_UNASSIGNED)
				PUT_UNICODE(0xfffd);
			else
				return TRANSCRIPT_UNASSIGNED;
		} else if (codepoint == 0xfffe) {
			if (flags & TRANSCRIPT_SUBST_ILLEGAL)
				PUT_UNICODE(0xfffd);
			else
				return TRANSCRIPT_ILLEGAL;
		}
		(*inbuf)++;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}
	return TRANSCRIPT_SUCCESS;
}

/** skip_to implementation for SBCS table converters. */
static transcript_error_t to_unicode_skip(converter_state_t *handle, const char **inbuf, const char const *inbuflimit) {
	(void) handle;
	(void) inbuflimit;
	(*inbuf)++;
	return TRANSCRIPT_SUCCESS;
}

/** Simplification macro for the get_unicode function in the converter handle. */
#define GET_UNICODE() do { \
	codepoint = handle->common.get_unicode((const char **) &_inbuf, inbuflimit, false); \
} while (0)

/** Simplification macro for the put_bytes call, which automatically returns on TRANSCRIPT_NO_SPACE. */
#define PUT_BYTE(byte) do { \
	if (*outbuf == outbuflimit) \
		return TRANSCRIPT_NO_SPACE; \
	*(uint8_t *) (*outbuf)++ = byte; \
} while (0)

/** Simplification macro to lookup the index for the mapping table. */
#define LOOKUP_IDX(codepoint) handle->tables.codepoint_to_byte_idx1[ \
	handle->tables.codepoint_to_byte_idx0[codepoint >> 10]] \
	[(codepoint >> 5) & 0x1f]

/** convert_from implementation for SBCS table converters. */
static transcript_error_t from_unicode_conversion(converter_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	uint_fast32_t codepoint;

	while (*inbuf < inbuflimit) {
		GET_UNICODE();
		if (codepoint == TRANSCRIPT_UTF_INCOMPLETE)
			break;

		if (codepoint == TRANSCRIPT_UTF_ILLEGAL) {
			if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
				return TRANSCRIPT_ILLEGAL;
			PUT_BYTE(handle->tables.subchar);
			*inbuf = (const char *) _inbuf;
			continue;
		}

		if (codepoint < UINT32_C(0x10000)) {
			unsigned int idx = LOOKUP_IDX(codepoint);
			uint8_t byte = handle->tables.codepoint_to_byte_data[idx][codepoint & 0x1f];
			if (byte != 0 || codepoint == 0) {
				if (handle->tables.codepoint_to_byte_flags != NULL && !(flags & TRANSCRIPT_ALLOW_FALLBACK) &&
						(handle->tables.codepoint_to_byte_flags[((idx << 5) + (codepoint & 0x1f)) >> 3] & (1 << (codepoint & 7)))) {
					return TRANSCRIPT_FALLBACK;
				} else {
					PUT_BYTE(byte);
				}
			} else {
				if ((codepoint = transcript_get_generic_fallback(codepoint)) != 0xffff) {
					idx = LOOKUP_IDX(codepoint);
					byte = handle->tables.codepoint_to_byte_data[idx][codepoint & 0x1f];
					if (byte == 0) {
						if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
							return TRANSCRIPT_UNASSIGNED;
						PUT_BYTE(handle->tables.subchar);
					} else {
						if (!(flags & TRANSCRIPT_ALLOW_FALLBACK))
							return TRANSCRIPT_FALLBACK;
						PUT_BYTE(byte);
					}
				} else {
					if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
						return TRANSCRIPT_UNASSIGNED;
					PUT_BYTE(handle->tables.subchar);
				}
			}
		} else {
			if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
				return TRANSCRIPT_UNASSIGNED;
			PUT_BYTE(handle->tables.subchar);
		}

		*inbuf = (const char *) _inbuf;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}

	return TRANSCRIPT_SUCCESS;
}

/** @internal
    @brief Create a converter handle from an SBCS table handle.
    @param tables The SBCS table handle
    @param flags Flags for the converter.
    @param error The location to store an error.
*/
void *_transcript_open_sbcs_table_converter(const sbcs_converter_v1_t *tables, int flags, transcript_error_t *error) {
	converter_state_t *retval;

	if (!(flags & TRANSCRIPT_INTERNAL) && tables->flags & INTERNAL_TABLE) {
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_TABLE;
		return NULL;
	}

	if ((retval = malloc(sizeof(converter_state_t))) == NULL) {
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
		return NULL;
	}

	retval->tables = *tables;

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = NULL;
	retval->common.reset_from = NULL;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = NULL;
	retval->common.flags = flags;
	retval->common.close = NULL;
	retval->common.save = NULL;
	retval->common.load = NULL;
	return retval;
}
