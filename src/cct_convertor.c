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

#include "charconv.h"
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

enum {
	FROM_UNICODE_LENGTH_MASK = (3<<0),
	FROM_UNICODE_NOT_AVAIL = (1<<2),
	FROM_UNICODE_FALLBACK = (1<<3),
	FROM_UNICODE_SUBCHAR1 = (1<<4),
	FROM_UNICODE_MULTI_START = (1<<5),
};

enum {
	TO_UNICODE_FALLBACK = (1<<0),
	TO_UNICODE_MULTI_START = (1<<1),
	TO_UNICODE_PRIVATE_USE = (1<<2)
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
	uint8_t bytes[31];
	uint16_t codepoints[19];
	uint8_t bytes_length;
	uint8_t codepoints_length;
} multi_mapping_t;

typedef struct {
	shift_state_t *shift_states;
	state_t *codepage_states;
	entry_t *codepage_entries;
	state_t *unicode_states;
	entry_t *unicode_entries;
	uint16_t *codepage_mappings;
	uint8_t *unicode_mappings;
	multi_mapping_t *multi_mappings;
/* 	multi_mapping_t **multi_mappings_codepoint_sort; */

	uint32_t codepage_range;
	uint32_t unicode_range;
	uint32_t nr_multi_mappings;

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
	charconv_common_t common;
	convertor_t *convertor;
	uint8_t state;
} convertor_state_t;

static t3_bool read_states(FILE *file, uint_fast32_t nr, state_t *states, entry_t *entries, uint_fast32_t max_entries, int *error);
static t3_bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t *range);
static void update_state_attributes(state_t *states, uint_fast32_t idx);
static uint8_t get_default_flags(flags_t *flags, uint_fast32_t idx);
static t3_bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, int *error);
static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft);
/* static int multi_codepoint_compare(const multi_mapping_t **a, const multi_mapping_t **b); */

/* typedef int(*compare_func_t)(const void *, const void *); */

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
	uint_fast32_t i, j;

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

	/* Make sure all pointers are correctly initialized, even if the NULL pointer
	   is not actually zero. */
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
	convertor->multi_mappings = NULL;

	convertor->codepage_flags.get_flags = get_default_flags;
	convertor->unicode_flags.get_flags = get_default_flags;

	READ_BYTE(convertor->flags);
	READ_BYTE(convertor->subchar_len);
	READ(MAX_CHAR_BYTES, convertor->subchar);
	READ_BYTE(convertor->subchar1);
	READ_BYTE(convertor->nr_shift_states);
	READ_BYTE(convertor->nr_codepage_states);
	READ_WORD(convertor->nr_codepage_entries);
	READ_BYTE(convertor->nr_unicode_states);
	READ_WORD(convertor->nr_unicode_entries);
	READ_BYTE(convertor->codepage_flags.default_flags);
	READ_BYTE(convertor->unicode_flags.default_flags);
	READ_BYTE(convertor->single_size);

	if ((convertor->shift_states = calloc(convertor->nr_shift_states, sizeof(shift_state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->codepage_states = calloc(convertor->nr_codepage_states + 1, sizeof(state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->codepage_entries = malloc((convertor->nr_codepage_entries + 1) * sizeof(entry_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_states = calloc(convertor->nr_unicode_states + 1, sizeof(state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_entries = malloc((convertor->nr_unicode_entries + 1) * sizeof(entry_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);

	for (i = 0; i < convertor->nr_shift_states; i++) {
		READ_BYTE(convertor->shift_states[i].from_state);
		READ_BYTE(convertor->shift_states[i].to_state);
		READ_BYTE(convertor->shift_states[i].len);
		READ(MAX_CHAR_BYTES, convertor->shift_states[i].bytes);
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

	if ((convertor->flags & TO_UNICODE_FLAGS_TABLE_INCLUDED) &&
			!read_flags(file, &convertor->codepage_flags, convertor->codepage_range, error))
		goto end_error;
	if ((convertor->flags & FROM_UNICODE_FLAGS_TABLE_INCLUDED) &&
			!read_flags(file, &convertor->unicode_flags, convertor->unicode_range, error))
		goto end_error;

	if (convertor->flags & MULTI_MAPPINGS_AVAILABLE) {
		READ_DWORD(convertor->nr_multi_mappings);

		if ((convertor->multi_mappings = calloc(convertor->nr_multi_mappings, sizeof(multi_mapping_t))) == NULL)
			goto end_error;
		/* if ((convertor->multi_mappings_codepoint_sort = malloc(convertor->nr_multi_mappings * sizeof(multi_mapping_t *))) == NULL)
			goto end_error; */
		for (i = 0; i < convertor->nr_multi_mappings; i++) {
			/* convertor->multi_mappings_codepoint_sort[i] = &convertor->multi_mappings[i]; */
			READ_BYTE(convertor->multi_mappings[i].codepoints_length);
			for (j = 0; j < convertor->multi_mappings[i].codepoints_length; j++)
				READ_WORD(convertor->multi_mappings[i].codepoints[j]);
			READ_BYTE(convertor->multi_mappings[i].bytes_length);
			READ(convertor->multi_mappings[i].bytes_length, convertor->multi_mappings[i].bytes);
		}
		/* qsort(convertor->multi_mappings_codepoint_sort, convertor->nr_multi_mappings, sizeof(multi_mapping_t *),
			(compare_func_t) multi_codepoint_compare); */
	}

	if (fread(magic, 1, 1, file) != 0 || !feof(file))
		ERROR(T3_ERR_INVALID_FORMAT);

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
	free(convertor->multi_mappings);
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
			if ((states[i].entries[j].action != ACTION_VALID) ^ next_is_initial)
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

static uint8_t get_default_flags(flags_t *flags, uint_fast32_t idx) {
	(void) idx;
	return flags->default_flags;
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

/* static int multi_codepoint_compare(const multi_mapping_t **a, const multi_mapping_t **b) {
	int i;
	for (i = 0; i < (*a)->codepoints_length && i < (*b)->codepoints_length; i++) {
		if ((*a)->codepoints[i] < (*b)->codepoints[i])
			return -1;
		if ((*a)->codepoints[i] > (*b)->codepoints[i])
			return 1;
	}
	if ((*a)->codepoints_length < (*b)->codepoints_length)
		return -1;
	if ((*a)->codepoints_length > (*b)->codepoints_length)
		return 1;
	return 0;
} */

#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.unicode_func.put_unicode(codepoint, outbuf, outbytesleft)) != 0) \
		return result; \
} while (0)

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

static int to_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	uint_fast8_t state = handle->state;
	uint_fast32_t idx = 0;
	uint_fast32_t codepoint;
	entry_t *entry;

	if (flags & CHARCONV_FILE_START)
		PUT_UNICODE(UINT32_C(0xFEFF));

	while (_inbytesleft > 0) {
		entry = &handle->convertor->codepage_states[state].entries[handle->convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;
		_inbytesleft--;

		switch (entry->action) {
			case ACTION_FINAL:
			case ACTION_FINAL_PAIR:
				flags = handle->convertor->codepage_flags.get_flags(&handle->convertor->codepage_flags, idx);
				if (flags & TO_UNICODE_MULTI_START) {
					size_t outbytesleft_tmp, check_len;
					uint_fast32_t i, j;
					char *outbuf_tmp;
					int result;

					for (i = 0; i < handle->convertor->nr_multi_mappings; i++) {
						check_len = min(handle->convertor->multi_mappings[i].bytes_length, *inbytesleft);

						if (memcmp(handle->convertor->multi_mappings[i].bytes, *inbuf, check_len) != 0)
							continue;

						if (check_len != handle->convertor->multi_mappings[i].bytes_length && !(flags & CHARCONV_END_OF_TEXT))
							return CHARCONV_INCOMPLETE;

						outbuf_tmp = *outbuf;
						outbytesleft_tmp = *outbytesleft;
						for (j = 0; j < handle->convertor->multi_mappings[i].codepoints_length; j++) {
							codepoint = handle->convertor->multi_mappings[i].codepoints[j];
							if (codepoint >= UINT32_C(0xD800) && codepoint <= UINT32_C(0xD8FF)) {
								j++;
								codepoint -= UINT32_C(0xD800);
								codepoint <<= 10;
								codepoint += handle->convertor->multi_mappings[i].codepoints[j] - UINT32_C(0xDC00);
								codepoint += 0x10000;
							}
							if ((result = handle->common.unicode_func.put_unicode(codepoint, &outbuf_tmp, &outbytesleft_tmp)) != 0)
								return result;
						}
						*outbuf = outbuf_tmp;
						*outbytesleft = outbytesleft_tmp;

						handle->state = state = entry->next_state;
						*inbuf = (char *) _inbuf;
						check_len = (*inbytesleft) - check_len;
						*inbytesleft = _inbytesleft;
						while (*inbytesleft > check_len)
							if (to_unicode_skip(handle, inbuf, inbytesleft) != 0)
								return CHARCONV_INTERNAL_ERROR;
						idx = 0;
						continue;
					}
				}

				if ((flags & TO_UNICODE_PRIVATE_USE) && !(handle->common.flags & CHARCONV_ALLOW_PRIVATE_USE)) {
					if (!(handle->common.flags & CHARCONV_SUBSTITUTE))
						return CHARCONV_PRIVATE_USE;
					PUT_UNICODE(UINT32_C(0xFFFD));
					goto sequence_done;
				}
				if ((flags & TO_UNICODE_FALLBACK) && !(handle->common.flags & CHARCONV_ALLOW_FALLBACK))
					return CHARCONV_FALLBACK;

				codepoint = handle->convertor->codepage_mappings[idx];
				if (codepoint == UINT32_C(0xFFFF)) {
					if (!(handle->common.flags & CHARCONV_SUBSTITUTE))
						return CHARCONV_UNASSIGNED;
					PUT_UNICODE(UINT32_C(0xFFFD));
				} else {
					if (entry->action == ACTION_FINAL_PAIR && codepoint >= UINT32_C(0xD800) && codepoint <= UINT32_C(0xD8FF)) {
						codepoint -= UINT32_C(0xD800);
						codepoint <<= 10;
						codepoint += handle->convertor->codepage_mappings[idx + 1] - UINT32_C(0xDC00);
						codepoint += 0x10000;
					}
					PUT_UNICODE(codepoint);
				}
				goto sequence_done;
			case ACTION_VALID:
				state = entry->next_state;
				break;
			case ACTION_ILLEGAL:
				if (!(handle->common.flags & CHARCONV_SUBSTITUTE_ALL))
					return CHARCONV_ILLEGAL;
				PUT_UNICODE(UINT32_C(0xFFFD));
				goto sequence_done;
			case ACTION_UNASSIGNED:
				if (!(handle->common.flags & CHARCONV_SUBSTITUTE))
					return CHARCONV_UNASSIGNED;
				PUT_UNICODE(UINT32_C(0xFFFD));
				/* FALLTHROUGH */
			case ACTION_SHIFT:
			sequence_done:
				*inbuf = (char *) _inbuf;
				*inbytesleft = _inbytesleft;
				handle->state = state = entry->next_state;
				idx = 0;
				if (flags & CHARCONV_SINGLE_CONVERSION)
					return CHARCONV_SUCCESS;
				break;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}
	}

	if (*inbytesleft != 0) {
		if (flags & CHARCONV_END_OF_TEXT) {
			if (!(handle->common.flags & CHARCONV_SUBSTITUTE_ALL))
				return CHARCONV_ILLEGAL_END;
			PUT_UNICODE(UINT32_C(0xFFFD));
			*inbuf += *inbytesleft;
			*inbytesleft = 0;
		} else {
			return CHARCONV_INCOMPLETE;
		}
	}
	return CHARCONV_SUCCESS;
}

static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	uint_fast8_t state = handle->state;
	uint_fast32_t idx = 0;
	entry_t *entry;

	while (_inbytesleft > 0) {
		entry = &handle->convertor->codepage_states[state].entries[handle->convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;
		_inbytesleft--;

		switch (entry->action) {
			case ACTION_VALID:
				state = entry->next_state;
				break;
			case ACTION_FINAL:
			case ACTION_FINAL_PAIR:
			case ACTION_ILLEGAL:
			case ACTION_UNASSIGNED:
			case ACTION_SHIFT:
				*inbuf = (char *) _inbuf;
				*inbytesleft = _inbytesleft;
				handle->state = state = entry->next_state;
				return CHARCONV_SUCCESS;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}
	}

	return CHARCONV_INCOMPLETE;
}

#define GET_UNICODE() do { \
	if ((codepoint = handle->common.unicode_func.get_unicode((char **) &_inbuf, &_inbytesleft, t3_false)) == CHARCONV_UTF_INCOMPLETE) \
		return CHARCONV_INCOMPLETE; \
} while (0)
#define PUT_BYTES(count, buffer) do { size_t _count = count; \
	if (*outbytesleft < _count) return CHARCONV_NO_SPACE; \
	memcpy(*outbuf, buffer, _count); \
	*outbuf += _count; *outbytesleft -= _count; \
} while (0)


static int from_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	uint_fast8_t state = handle->state;
	uint_fast32_t idx = 0;
	uint_fast32_t codepoint;
	entry_t *entry;
	int_fast16_t i;
	uint_fast8_t byte;

	if (flags & CHARCONV_FILE_START) {
		GET_UNICODE();
		if (codepoint != UINT32_C(0xFEFF)) {
			_inbuf = (uint8_t *) *inbuf;
			_inbytesleft = *inbytesleft;
		}
	}

	while (_inbytesleft > 0) {
		GET_UNICODE();
		if (codepoint == CHARCONV_UTF_ILLEGAL) {
			if (!(handle->common.flags & CHARCONV_SUBSTITUTE_ALL))
				return CHARCONV_ILLEGAL;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
			*inbuf = (char *) _inbuf;
			*inbytesleft = _inbytesleft;
			continue;
		}

		for (i = 16; i >=0 ; i -= 8) {
			byte = (codepoint >> i) & 0xff;
			entry = &handle->convertor->unicode_states[state].entries[handle->convertor->unicode_states[state].map[byte]];

			idx += entry->base + (byte - entry->low) * entry->mul;

			switch (entry->action) {
				case ACTION_FINAL:
				case ACTION_FINAL_PAIR:
					flags = handle->convertor->unicode_flags.get_flags(&handle->convertor->unicode_flags, idx);
					if (flags & FROM_UNICODE_MULTI_START) {
					}

					if ((flags & FROM_UNICODE_FALLBACK) && !(handle->common.flags & CHARCONV_ALLOW_FALLBACK))
						return CHARCONV_FALLBACK;

					if (flags & FROM_UNICODE_NOT_AVAIL) {
						if (!(handle->common.flags & CHARCONV_SUBSTITUTE))
							return CHARCONV_UNASSIGNED;
						if (flags & FROM_UNICODE_SUBCHAR1)
							PUT_BYTES(1, &handle->convertor->subchar1);
						else
							PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
					} else {
						PUT_BYTES((flags & FROM_UNICODE_LENGTH_MASK) + 1,
							&handle->convertor->unicode_mappings[idx * handle->convertor->single_size]);
					}
					goto sequence_done;
				case ACTION_VALID:
					state = entry->next_state;
					break;
				case ACTION_ILLEGAL:
					if (!(handle->common.flags & CHARCONV_SUBSTITUTE_ALL))
						return CHARCONV_ILLEGAL;
					PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
					goto sequence_done;
				case ACTION_UNASSIGNED:
					if (!(handle->common.flags & CHARCONV_SUBSTITUTE))
						return CHARCONV_UNASSIGNED;
					PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
					/* FALLTHROUGH */
				sequence_done:
					*inbuf = (char *) _inbuf;
					*inbytesleft = _inbytesleft;
					handle->state = state = entry->next_state; /* Should always be 0! */
					idx = 0;
					if (flags & CHARCONV_SINGLE_CONVERSION)
						return CHARCONV_SUCCESS;
					break;
				case ACTION_SHIFT:
				default:
					return CHARCONV_INTERNAL_ERROR;
			}
		}
	}

	if (*inbytesleft != 0) {
		if (flags & CHARCONV_END_OF_TEXT) {
			if (!(handle->common.flags & CHARCONV_SUBSTITUTE_ALL))
				return CHARCONV_ILLEGAL_END;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
			*inbuf += *inbytesleft;
			*inbytesleft = 0;
		} else {
			return CHARCONV_INCOMPLETE;
		}
	}
	return CHARCONV_SUCCESS;
}

static int from_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	if (handle->common.unicode_func.get_unicode(inbuf, inbytesleft, t3_true) == CHARCONV_UTF_INCOMPLETE)
		return CHARCONV_INCOMPLETE;
	return CHARCONV_SUCCESS;
}


#if 1
#include <stdarg.h>
void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
#ifdef DEBUG
	abort();
#else
	exit(EXIT_FAILURE);
#endif
}
#endif

#if 0
int main(int argc, char *argv[]) {
	flags_t flags;
	uint8_t bytes[256];
	int i, twobits, fourbits;

	flags.flags = bytes;
	flags.default_flags = 0;

	for (i = 0; i < 256; i++)
		bytes[i] = i;

	for (i = 0; i < 256 * 4; i++) {
		twobits = i >> 2;
		twobits >>= 2 * (i & 3);
		twobits &= 3;
		if (get_flags_1(&flags, i) != twobits)
			fatal("%d: get_flags_1: %02x, expected: %02x\n", i, get_flags_1(&flags, i), twobits);
		if (get_flags_2(&flags, i) != (twobits << 2))
			fatal("%d: get_flags_2: %02x, expected: %02x\n", i, get_flags_2(&flags, i), (twobits << 2));
		if (get_flags_4(&flags, i) != (twobits << 4))
			fatal("%d: get_flags_4: %02x, expected: %02x\n", i, get_flags_4(&flags, i), (twobits << 4));
		if (get_flags_8(&flags, i) != (twobits << 6))
			fatal("%d: get_flags_8: %02x, expected: %02x\n", i, get_flags_8(&flags, i), (twobits << 6));
	}

	for (i = 0; i < 256 * 2; i++) {
		fourbits = i >> 1;
		fourbits >>= 4 * (i & 1);
		fourbits &= 15;
		if (get_flags_3(&flags, i) != fourbits)
			fatal("%d: get_flags_3: %02x, expected: %02x\n", i, get_flags_3(&flags, i), fourbits);
		if (get_flags_6(&flags, i) != (fourbits << 2))
			fatal("%d: get_flags_6: %02x, expected: %02x\n", i, get_flags_6(&flags, i), (fourbits << 2));
		if (get_flags_12(&flags, i) != (fourbits << 4))
			fatal("%d: get_flags_12: %02x, expected: %02x\n", i, get_flags_12(&flags, i), (fourbits << 4));
		fourbits = ((fourbits & 0xc) << 2) | (fourbits & 3);
		if (get_flags_5(&flags, i) != fourbits)
			fatal("%d: get_flags_5: %02x, expected: %02x\n", i, get_flags_5(&flags, i), fourbits);
		if (get_flags_10(&flags, i) != (fourbits << 2))
			fatal("%d: get_flags_10: %02x, expected: %02x\n", i, get_flags_10(&flags, i), (fourbits << 2));
		fourbits = ((fourbits & 0x30) << 2) | (fourbits & 3);
		if (get_flags_9(&flags, i) != fourbits)
			fatal("%d: get_flags_9: %02x, expected: %02x\n", i, get_flags_9(&flags, i), fourbits);
	}

	for (i = 0; i < 256; i++) {
		if (get_flags_15(&flags, i) != i)
			fatal("%d: get_flags_15: %02x, expected: %02x\n", i, get_flags_15(&flags, i), i);
	}

	return 0;
}
#endif
#if 0
int main(int argc, char *argv[]) {
	int error;
	convertor_t *conv;
	convertor_state_t conv_state;
	char inbuf[1024], outbuf[1024], *inbuf_ptr, *outbuf_ptr;
	size_t result;
	size_t fill, outleft;

	if (argc != 2)
		fatal("Usage: cct_convertor <cct file>\n");

	if ((conv = _t3_load_convertor(argv[1], &error)) == NULL)
		fatal("Error opening convertor: %d\n", error);

	conv_state.common.convert = (conversion_func_t) to_unicode_conversion;
	conv_state.common.skip = (skip_func_t) to_unicode_skip;
	conv_state.common.reset = NULL;
	conv_state.common.unicode_func.put_unicode = get_put_unicode(UTF16);
	conv_state.common.flags = 0;
	conv_state.convertor = conv;
	conv_state.state = 0;

	while ((result = fread(inbuf, 1, 1024 - fill, stdin)) != 0) {
		inbuf_ptr = inbuf;
		outbuf_ptr = outbuf;
		fill += result;
		outleft = 1024;
		if ((error = to_unicode_conversion(&conv_state, &inbuf_ptr, &fill, &outbuf_ptr, &outleft, 0)) != CHARCONV_SUCCESS)
			fatal("conversion result: %d\n", error);
		fwrite(outbuf, 1, 1024 - outleft, stdout);
	}

	return 0;
}
#endif

int main(int argc, char *argv[]) {
	int error;
	convertor_t *conv;
	convertor_state_t conv_state;
	char inbuf[1024], outbuf[1024], *inbuf_ptr, *outbuf_ptr;
	size_t result;
	size_t fill, outleft, i;

	if (argc != 2)
		fatal("Usage: cct_convertor <cct file>\n");

	if ((conv = _t3_load_convertor(argv[1], &error)) == NULL)
		fatal("Error opening convertor: %d\n", error);

	conv_state.common.convert = (conversion_func_t) from_unicode_conversion;
	conv_state.common.skip = (skip_func_t) from_unicode_skip;
	conv_state.common.reset = NULL;
	conv_state.common.unicode_func.get_unicode = get_get_unicode(UTF8_STRICT);
	conv_state.common.flags = 0;
	conv_state.convertor = conv;
	conv_state.state = 0;

	while ((result = fread(inbuf, 1, 1024 - fill, stdin)) != 0) {
		inbuf_ptr = inbuf;
		outbuf_ptr = outbuf;
		fill += result;
		outleft = 1024;
		if ((error = from_unicode_conversion(&conv_state, &inbuf_ptr, &fill, &outbuf_ptr, &outleft, 0)) != CHARCONV_SUCCESS)
			fatal("conversion result: %d\n", error);
		for (i = 0; i < 1024 - outleft; i++)
			printf("\\x%02X", (uint8_t) outbuf[i]);
	}
	putchar('\n');
	return 0;
}

