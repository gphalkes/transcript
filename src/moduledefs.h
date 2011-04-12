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
#ifndef TRANSCRIPT_MODULEDEFS_H
#define TRANSCRIPT_MODULEDEFS_H
#include <stdlib.h>
#include <stdint.h>

#include "transcript.h"
#include "api.h"
#include "bool.h"
#include "handle.h"
#include "utf.h"

enum {
	TRANSCRIPT_FULL_MODULE_V1 = 1, /* Provides all functions itself. */
	TRANSCRIPT_STATE_TABLE_V1, /* Provides a set of state tables. See cct_convertor for details. */
	TRANSCRIPT_SBCS_TABLE_V1 /* Simple set of tables for SBCSs. See sbcs_convertor for details. */
};

enum {
	TRANSCRIPT_INTERNAL = (1<<15)
};

#define MAX_CHAR_BYTES_V1 4

typedef struct {
	const uint8_t bytes[MAX_CHAR_BYTES_V1];
	const uint8_t len;
	const uint8_t from_state;
	const uint8_t to_state;
} shift_state_v1_t;

typedef struct {
	const uint16_t codepoints[19];
	const uint8_t bytes[31];
	const uint8_t codepoints_length;
	const uint8_t bytes_length;
} multi_mapping_v1_t;

typedef struct {
	const uint32_t codepoint;
	const char codepage_bytes[4];
	const uint16_t sort_idx;
	const uint8_t from_unicode_flags;
	const uint8_t to_unicode_flags;
} variant_mapping_v1_t;

typedef struct {
	const variant_mapping_v1_t *simple_mappings;
	const uint16_t nr_mappings, flags;
} variant_v1_t;

typedef struct {
	const uint8_t *flags;
	const uint16_t *indices;
	const uint8_t default_flags;
	const uint8_t flags_type;
} flags_v1_t;

typedef struct {
	const uint32_t base, mul;
	const uint8_t low, next_state, action;
} entry_v1_t;

typedef struct {
	const entry_v1_t *entries;
	const uint32_t base;
	const uint8_t map[256];
} state_v1_t;

typedef struct {
	const state_v1_t *codepage_states;
	const state_v1_t *unicode_states;
	const shift_state_v1_t *shift_states;

	const uint16_t *codepage_mappings;
	const uint8_t *unicode_mappings;

	const flags_v1_t to_unicode_flags;
	const flags_v1_t from_unicode_flags;

	const uint8_t subchar[MAX_CHAR_BYTES_V1];

	const uint16_t flags;

	const uint8_t subchar_len;
	const uint8_t subchar1;
	const uint8_t nr_shift_states;
	const uint8_t single_size;
} convertor_v1_t;

typedef struct {
	const convertor_v1_t *convertor;
	const variant_v1_t *variant;
	const multi_mapping_v1_t * const *codepage_sorted_multi_mappings;
	const multi_mapping_v1_t * const *codepoint_sorted_multi_mappings;
	uint32_t nr_multi_mappings;
} convertor_tables_v1_t;

TRANSCRIPT_API uint32_t transcript_get_generic_fallback(uint32_t codepoint);
TRANSCRIPT_API transcript_error_t transcript_handle_unassigned(transcript_t *handle, uint32_t codepoint, char **outbuf,
		const char *outbuflimit, int flags);
TRANSCRIPT_API bool transcript_get_option(const char *name, char *option_buffer, size_t option_buffer_max, const char *option_name);
TRANSCRIPT_API int transcript_probe_convertor_nolock(const char *name);

#define HANDLE_UNASSIGNED(_code) \
	switch (transcript_handle_unassigned((transcript_t *) handle, codepoint, outbuf, outbuflimit, flags)) { \
		case TRANSCRIPT_UNASSIGNED: \
			_code \
			break; \
		case TRANSCRIPT_SUCCESS: \
			break; \
		case TRANSCRIPT_NO_SPACE: \
			return TRANSCRIPT_NO_SPACE; \
		case TRANSCRIPT_FALLBACK: \
			return TRANSCRIPT_FALLBACK; \
		default: \
			return TRANSCRIPT_INTERNAL_ERROR; \
	}

#define TRANSCRIPT_ALIAS_OPEN(_func, _name) \
	TRANSPORT_EXPORT transcript_t *transcript_open_#_name(const char *name, int flags, transcript_error_t *error) { \
		return _func(name, flags, error); }
#define TRANSCRIPT_ALIAS_PROBE(_func, _name) \
	TRANSPORT_EXPORT bool transcript_probe_#_name(const char *name) { return _func(name); }

#define TRANSCRIPT_ARRAY_SIZE(name) (sizeof(name) / sizeof(name[0]))

#endif