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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "charconv_errors.h"
#include "utf.h"

#warning FIXME: these should not be replicated here!!!
#define T3_ERR_INVALID_FORMAT (-32)
#define T3_ERR_TRUNCATED_DB (-29)
#define T3_ERR_READ_ERROR (-28)
#define T3_ERR_WRONG_VERSION (-27)


#define MAX_CHAR_BYTES 4

enum {
	FROM_UNICODE_FLAGS_TABLE_INCLUDED = (1<<0),
	TO_UNICODE_FLAGS_TABLE_INCLUDED = (1<<1),
	MULTI_MAPPINGS_AVAILABLE = (1<<2),
	SUBCHAR1_VALID = (1<<3),
	MULTIBYTE_START_STATE_1 = (1<<4)
};

enum {
	ACTION_FINAL,
	ACTION_FINAL_PAIR,
	ACTION_VALID,
	ACTION_UNASSIGNED,
	ACTION_SHIFT,
	ACTION_ILLEGAL
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
	t3_bool complete;
	uint8_t map[256];
	entry_t *entries;
} state_t;

typedef struct flags_t {
	uint8_t *flags;
	uint16_t *indices;
	uint8_t (*get_flags)(struct flags_t *flags, uint_fast32_t idx);
	uint8_t default_flags;
} flags_t;

typedef struct {
	shift_state_t *shift_states;
	state_t *codepage_states;
	entry_t *codepage_entries;
	state_t *unicode_states;
	entry_t *unicode_entries;
	uint16_t *codepage_mappings;
	uint8_t *unicode_mappings;
	//FIXME: flag tries

	uint32_t codepage_range;
	uint32_t unicode_range;

	uint16_t nr_codepage_entries;
	uint16_t nr_unicode_entries;

	uint8_t flags;
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

typedef struct {
	convertor_t *convertor;
	//FIXME: add state
} convertor_state_t;

static t3_bool read_states(FILE *file, uint_fast32_t nr, state_t *states, entry_t *entries, uint_fast32_t max_entries, int *error);
static t3_bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t *range);
static void update_state_attributes(state_t *states, uint_fast32_t idx);
static t3_bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, int *error);

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)
#define READ(count, buf) do { if (fread(buf, 1, count, file) != (size_t) count) ERROR(T3_ERR_READ_ERROR); } while (0)
#define READ_BYTE(store) do { uint8_t value; if (fread(&value, 1, 1, file) != (size_t) 1) ERROR(T3_ERR_READ_ERROR); store = value; } while (0)
#define READ_WORD(store) do { uint16_t value; if (fread(&value, 1, 2, file) != (size_t) 2) ERROR(T3_ERR_READ_ERROR); store = ntohs(value); } while (0)
#define READ_DWORD(store) do { uint32_t value; if (fread(&value, 1, 4, file) != (size_t) 4) ERROR(T3_ERR_READ_ERROR); store = ntohl(value); } while (0)

//                                    0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
static int flag_info_to_shift[16] = { 0, 2, 2, 1, 2, 1, 1, 0, 2, 1, 1, 0, 1, 0, 0, 0 };

void *_t3_load_convertor(const char *file_name, int *error) {
	convertor_t *convertor = NULL;
	FILE *file;
	char magic[4];
	uint32_t version;
	uint_fast32_t i;

	if ((file = fopen(file_name, "r")) == NULL)
		ERROR(T3_ERR_ERRNO);

	READ(4, magic);
	if (memcmp(magic, "T3CM", 4) != 0)
		ERROR(T3_ERR_INVALID_FORMAT);
	READ_DWORD(version);
	if (version != UINT32_C(0))
		ERROR(T3_ERR_WRONG_VERSION);

	if ((convertor = calloc(1, sizeof(convertor_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	convertor->shift_states = NULL;
	convertor->codepage_states = NULL;
	convertor->codepage_entries = NULL;
	convertor->codepage_mappings = NULL;
	convertor->codepage_flags.flags = NULL;
	convertor->codepage_flags.indices = NULL;
	convertor->unicode_states = NULL;
	convertor->unicode_entries = NULL;
	convertor->unicode_mappings = NULL;
	convertor->unicode_flags.flags = NULL;
	convertor->unicode_flags.indices = NULL;

	READ_BYTE(convertor->flags);
	READ_BYTE(convertor->subchar_len);
	READ(4, convertor->subchar);
	READ_BYTE(convertor->subchar1);
	READ_BYTE(convertor->nr_shift_states);
	READ_BYTE(convertor->nr_codepage_states);
	READ_WORD(convertor->nr_codepage_entries);
	READ_BYTE(convertor->nr_unicode_states);
	READ_WORD(convertor->nr_unicode_entries);
	READ_BYTE(convertor->codepage_flags.default_flags);
	READ_BYTE(convertor->unicode_flags.default_flags);

	if ((convertor->shift_states = calloc(convertor->nr_shift_states, sizeof(shift_state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->codepage_states = calloc(convertor->nr_codepage_states, sizeof(state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->codepage_entries = malloc(convertor->nr_codepage_entries * sizeof(entry_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_states = calloc(convertor->nr_unicode_states, sizeof(state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_entries = malloc(convertor->nr_unicode_entries * sizeof(entry_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);

	for (i = 0; i < convertor->nr_shift_states; i++) {
		READ_BYTE(convertor->shift_states[i].from_state);
		READ_BYTE(convertor->shift_states[i].to_state);
		READ_BYTE(convertor->shift_states[i].len);
		READ(4, convertor->shift_states[i].bytes);
	}

	if (!read_states(file, convertor->nr_codepage_states, convertor->codepage_states, convertor->codepage_entries,
			convertor->nr_codepage_entries, error))
		goto end_error;
	if (!read_states(file, convertor->nr_unicode_states, convertor->unicode_states, convertor->unicode_entries,
			convertor->nr_unicode_entries, error))
		goto end_error;

	if (!validate_states(convertor->codepage_states, convertor->nr_codepage_states, convertor->flags, &convertor->codepage_range))
		ERROR(T3_ERR_INVALID_FORMAT);
	if (!validate_states(convertor->unicode_states, convertor->nr_unicode_states, 0, &convertor->unicode_range))
		ERROR(T3_ERR_INVALID_FORMAT);

	if ((convertor->codepage_mappings = malloc(convertor->codepage_range * sizeof(uint16_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_mappings = calloc(convertor->unicode_range, convertor->single_size)) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	memset(convertor->codepage_mappings, 0xff, convertor->codepage_range * sizeof(uint16_t));

	for (i = 0; i < convertor->codepage_range; i++)
		READ_WORD(convertor->codepage_mappings[i]);
	READ(convertor->unicode_range * convertor->single_size, convertor->unicode_mappings);

	//FIXME: read flag tries
	if (!read_flags(file, &convertor->codepage_flags, convertor->codepage_range, error))
		goto end_error;
	if (!read_flags(file, &convertor->unicode_flags, convertor->unicode_range, error))
		goto end_error;

	return convertor;

end_error:
	if (convertor == NULL)
		return error;
	free(convertor->shift_states);
	free(convertor->codepage_states);
	free(convertor->codepage_entries);
	free(convertor->codepage_mappings);
	free(convertor->codepage_flags.flags);
	free(convertor->codepage_flags.indices);
	free(convertor->unicode_states);
	free(convertor->unicode_entries);
	free(convertor->unicode_mappings);
	free(convertor->unicode_flags.flags);
	free(convertor->unicode_flags.indices);
	free(convertor);
	return NULL;
}

static t3_bool read_states(FILE *file, uint_fast32_t nr_states, state_t *states, entry_t *entries, uint_fast32_t max_entries, int *error) {
	uint_fast32_t i, j, entries_idx = 0;

	nr_states++;
	max_entries++;

	for (i = 0; i < nr_states; i++) {
		READ_BYTE(states[i].nr_entries);
		states[i].nr_entries++;
		states[i].entries = entries + entries_idx;
		for (j = 0; j < states[i].nr_entries && entries_idx < max_entries; j++) {
			READ_BYTE(entries[entries_idx].low);
			READ_BYTE(entries[entries_idx].next_state);
			READ_BYTE(entries[entries_idx].action);
			if (j > 0) {
				if (entries[entries_idx].low <= entries[entries_idx - 1].low)
					ERROR(T3_ERR_INVALID_FORMAT);
				memset(states[i].map + entries[entries_idx - 1].low, j - 1, entries[entries_idx].low - entries[entries_idx - 1].low);
			} else {
				if (entries[entries_idx].low != 0)
					ERROR(T3_ERR_INVALID_FORMAT);
			}
			entries_idx++;
		}
		memset(states[i].map + entries[entries_idx - 1].low, j - 1, 256 - entries[entries_idx - 1].low);
		if (j < states[i].nr_entries)
			ERROR(T3_ERR_INVALID_FORMAT);
	}
	if (entries_idx != max_entries)
		ERROR(T3_ERR_INVALID_FORMAT);

	return t3_true;
end_error:
	return t3_false;
}

static t3_bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t *range) {
	uint_fast32_t i, j;
	int next_is_initial;

	nr_states++;

	for (i = 0; i < nr_states; i++) {
		for (j = 0; j < states[i].nr_entries; j++) {
			if (states[i].entries[j].next_state >= nr_states)
				return t3_false;

			next_is_initial = states[i].entries[j].next_state == 0 ||
					((flags & MULTIBYTE_START_STATE_1) && states[i].entries[j].next_state == 1);
			if ((states[i].entries[j].action == ACTION_VALID) ^ next_is_initial)
				return t3_false;
		}
	}

	*range = 0;
	update_state_attributes(states, 0);
	*range = states[0].range;
	if (flags & MULTIBYTE_START_STATE_1) {
		update_state_attributes(states, 1);
		*range += states[1].range;
	}
	return t3_true;
}

static void update_state_attributes(state_t *states, uint_fast32_t idx) {
	uint_fast32_t i, sum = 0, high;

	if (states[idx].complete)
		return;

	for (i = 0; i < states[idx].nr_entries; i++) {
		switch (states[idx].entries[i].action) {
			case ACTION_VALID:
				update_state_attributes(states, states[idx].entries[i].next_state);
				states[idx].entries[i].base = sum;
				states[idx].entries[i].mul = states[states[idx].entries[i].next_state].range;
				high = i + 1 < states[idx].nr_entries ? states[idx].entries[i + 1].low : 256;
				sum += (high - states[idx].entries[i].low) * states[idx].entries[i].mul;
				break;
			case ACTION_FINAL_PAIR:
				states[idx].entries[i].mul = 2;
				goto action_final_shared;
			case ACTION_FINAL:
				states[idx].entries[i].mul = 1;
			action_final_shared:
				states[idx].entries[i].base = sum;
				high = i + 1 < states[idx].nr_entries ? states[idx].entries[i + 1].low : 256;
				sum += (high - states[idx].entries[i].low) * states[idx].entries[i].mul;
				break;
			default:
				break;
		}
	}
	states[idx].range = sum;
	states[idx].complete = t3_true;
}

static uint8_t get_flags_1(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | ((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3);
}
static uint8_t get_flags_2(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3) << 2);
}
static uint8_t get_flags_3(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | ((flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf);
}
static uint8_t get_flags_4(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3) << 4);
}
static uint8_t get_flags_5(flags_t *flags, uint_fast32_t idx) {
	uint8_t bits = flags->flags[idx >> 1] >> (4 * (idx & 1));
	return flags->default_flags | (bits & 0x3) | ((bits & 0xc) << 2);
}
static uint8_t get_flags_6(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf) << 2);
}
static uint8_t get_flags_8(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3) << 6);
}
static uint8_t get_flags_9(flags_t *flags, uint_fast32_t idx) {
	uint8_t bits = flags->flags[idx >> 1] >> (4 * (idx & 1));
	return flags->default_flags | (bits & 0x3) | ((bits & 0xc) << 4);
}
static uint8_t get_flags_10(flags_t *flags, uint_fast32_t idx) {
	uint8_t bits = flags->flags[idx >> 1] >> (4 * (idx & 1));
	return flags->default_flags | ((bits & 0x3) << 2) | ((bits & 0xc) << 4);
}
static uint8_t get_flags_12(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf) << 4);
}
static uint8_t get_flags_15(flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | flags->flags[idx];
}

static uint8_t get_flags_1_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_1(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_2_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_2(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_3_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_3(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_4_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_4(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_5_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_5(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_6_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_6(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_8_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_8(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_9_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_9(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_10_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_10(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_12_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_12(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_15_trie(flags_t *flags, uint_fast32_t idx) {
	return get_flags_15(flags, (idx & 15) + (flags->indices[idx >> 4] << 4));
}

static uint8_t (*get_flags[16])(flags_t *flags, uint_fast32_t idx) = {
	NULL,
	get_flags_1,
	get_flags_2,
	get_flags_3,
	get_flags_4,
	get_flags_5,
	get_flags_6,
	NULL,
	get_flags_8,
	get_flags_9,
	get_flags_10,
	NULL,
	get_flags_12,
	NULL,
	NULL,
	get_flags_15
};

static uint8_t (*get_flags_trie[16])(flags_t *flags, uint_fast32_t idx) = {
	NULL,
	get_flags_1_trie,
	get_flags_2_trie,
	get_flags_3_trie,
	get_flags_4_trie,
	get_flags_5_trie,
	get_flags_6_trie,
	NULL,
	get_flags_8_trie,
	get_flags_9_trie,
	get_flags_10_trie,
	NULL,
	get_flags_12_trie,
	NULL,
	NULL,
	get_flags_15_trie
};

static t3_bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, int *error) {
	uint_fast32_t nr_flag_bytes, nr_blocks, i;
	uint8_t flag_info;
	READ_BYTE(flag_info);

	nr_flag_bytes = (range + (1 << flag_info_to_shift[flag_info & 0xf]) - 1) >> flag_info_to_shift[flag_info & 0xf];
	if (flag_info & 0x80) {
		nr_flag_bytes = (nr_flag_bytes + 15) / 16;
		if ((flags->indices = malloc(nr_flag_bytes * 2)) == NULL)
			ERROR(T3_ERR_OUT_OF_MEMORY);
		for (i = 0; i < nr_flag_bytes; i++)
			READ_WORD(flags->indices[i]);

		READ_WORD(nr_blocks);
		nr_blocks++;
		if ((flags->flags = malloc(nr_blocks * 16)) == NULL)
			ERROR(T3_ERR_OUT_OF_MEMORY);
		READ(nr_blocks * 16, flags->flags);
		flags->get_flags = get_flags_trie[flag_info & 0xf];
	} else {
		if ((flags->flags = malloc(nr_flag_bytes)) == NULL)
			ERROR(T3_ERR_OUT_OF_MEMORY);
		READ(nr_flag_bytes, flags->flags);
		flags->get_flags = get_flags[flag_info & 0xf];
	}

	return t3_true;
end_error:
	return t3_false;
}

