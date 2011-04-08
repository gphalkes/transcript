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
#ifndef CCT_CONVERTOR_H
#define CCT_CONVERTOR_H

#include <stdint.h>
#include "transcript_internal.h"

/* FIXME: we might consider converting some uintXX_t to uint_fastXX_t variables for speed. */

#define MAX_CHAR_BYTES 4

enum {
	FROM_UNICODE_FLAGS_TABLE_INCLUDED = (1<<0),
	TO_UNICODE_FLAGS_TABLE_INCLUDED = (1<<1),
	MULTI_MAPPINGS_AVAILABLE = (1<<2),
	SUBCHAR1_VALID = (1<<3),
	MULTIBYTE_START_STATE_1 = (1<<4),
	INTERNAL_TABLE = (1<<5),
	VARIANTS_AVAILABLE = (1<<6)
};

enum action_t {
	ACTION_FINAL,
	ACTION_FINAL_NOFLAGS,
	ACTION_FINAL_LEN1_NOFLAGS,
	ACTION_FINAL_LEN2_NOFLAGS,
	ACTION_FINAL_LEN3_NOFLAGS,
	ACTION_FINAL_LEN4_NOFLAGS,
	/* Define lengths 5 through 8 such that we don't have to renumber later.
	   Not used right now. */
	ACTION_FINAL_LEN5_NOFLAGS,
	ACTION_FINAL_LEN6_NOFLAGS,
	ACTION_FINAL_LEN7_NOFLAGS,
	ACTION_FINAL_LEN8_NOFLAGS,
	ACTION_VALID,
	ACTION_UNASSIGNED,
	ACTION_SHIFT,
	ACTION_ILLEGAL,

	ACTION_FLAG_PAIR = (1<<7),
	ACTION_FINAL_PAIR = ACTION_FINAL | ACTION_FLAG_PAIR,
	ACTION_FINAL_PAIR_NOFLAGS = ACTION_FINAL_NOFLAGS | ACTION_FLAG_PAIR,
};

enum {
	FROM_UNICODE_LENGTH_MASK = (3<<0),
	FROM_UNICODE_NOT_AVAIL = (1<<2),
	FROM_UNICODE_FALLBACK = (1<<3),
	FROM_UNICODE_SUBCHAR1 = (1<<4),
	FROM_UNICODE_MULTI_START = (1<<5),
	FROM_UNICODE_VARIANT = (1<<6)
};

enum {
	TO_UNICODE_FALLBACK = (1<<0),
	TO_UNICODE_MULTI_START = (1<<1),
	TO_UNICODE_PRIVATE_USE = (1<<2),
	TO_UNICODE_VARIANT = (1<<3)
};

typedef struct {
	uint8_t bytes[MAX_CHAR_BYTES];
	uint8_t len;
	uint8_t from_state;
	uint8_t to_state;
} shift_state_t;

typedef struct {
	uint8_t low, next_state, action;
	uint32_t mul, base;
} entry_t;

typedef struct {
	uint32_t base, range;
	uint16_t nr_entries;
	bool complete;
	uint8_t map[256];
	entry_t *entries;
} state_t;

typedef struct flags_t {
	uint8_t *flags;
	uint16_t *indices;
	uint8_t *bits2flags;
	uint8_t (*get_flags)(const struct flags_t *flags, uint_fast32_t idx);
	uint8_t default_flags;
} flags_t;

typedef struct {
	uint8_t bytes[31];
	uint16_t codepoints[19];
	uint8_t bytes_length;
	uint8_t codepoints_length;
} multi_mapping_t;

typedef struct {
	uint32_t codepoint;
	uint32_t codepage_bytes;
	uint16_t sort_idx;
	uint8_t from_unicode_flags;
	uint8_t to_unicode_flags;
} variant_mapping_t;

typedef struct {
	variant_mapping_t *simple_mappings;
	multi_mapping_t *multi_mappings;
	multi_mapping_t **codepage_sorted_multi_mappings;
	multi_mapping_t **codepoint_sorted_multi_mappings;
	char *id;
	uint16_t nr_simple_mappings;
	uint16_t nr_multi_mappings;
	uint8_t flags;
} variant_t;


typedef struct convertor_t {
	char *name;
	struct convertor_t *next;
	shift_state_t *shift_states;
	state_t *codepage_states;
	entry_t *codepage_entries;
	state_t *unicode_states;
	entry_t *unicode_entries;
	uint16_t *codepage_mappings;
	uint8_t *unicode_mappings;
	multi_mapping_t *multi_mappings;
	multi_mapping_t **codepage_sorted_multi_mappings;
	multi_mapping_t **codepoint_sorted_multi_mappings;

	variant_t *variants;

	uint32_t codepage_range;
	uint32_t unicode_range;
	uint32_t nr_multi_mappings;
	uint16_t nr_variants;

	int refcount;

	uint16_t nr_codepage_entries;
	uint16_t nr_unicode_entries;
	uint16_t flags;

	uint8_t subchar_len;
	uint8_t subchar[MAX_CHAR_BYTES];
	uint8_t subchar1;
	uint8_t nr_shift_states;
	uint8_t nr_codepage_states;
	uint8_t nr_unicode_states;
	uint8_t single_size;
	flags_t codepage_flags;
	flags_t unicode_flags;
} convertor_t;

TRANSCRIPT_LOCAL convertor_t *_transcript_load_cct_convertor(const char *file_name, transcript_error_t *error, variant_t **variant);
TRANSCRIPT_LOCAL void _transcript_unload_cct_convertor(convertor_t *convertor);
#endif
