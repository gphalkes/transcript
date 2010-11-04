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
#include <string.h>
#include <arpa/inet.h>

#include "charconv_internal.h"
#include "cct_convertor.h"

typedef int (*compar_func_t)(const void *, const void *);

static bool read_states(FILE *file, uint_fast32_t nr, state_t *states, entry_t *entries, uint_fast32_t max_entries, int *error);
static bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t range);
static void update_state_attributes(state_t *states, uint_fast32_t idx);
static uint8_t get_default_flags(const flags_t *flags, uint_fast32_t idx);
static bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, int *error);
static int compare_multi_mapping_codepage(const multi_mapping_t **a, const multi_mapping_t **b);
static int compare_multi_mapping_codepoints(const multi_mapping_t **a, const multi_mapping_t **b);

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)
#define READ(count, buf) do { if (fread(buf, 1, count, file) != (size_t) count) ERROR(CHARCONV_TRUNCATED_MAP); } while (0)
#define READ_BYTE(store) do { uint8_t value; READ(1, &value); store = value; } while (0)
#define READ_WORD(store) do { uint16_t value; READ(2, &value); store = ntohs(value); } while (0)
#define READ_DWORD(store) do { uint32_t value; READ(4, &value); store = ntohl(value); } while (0)

static const int flag_info_to_shift[16] = { 0, 2, 2, 1, 2, 1, 1, 0, 2, 1, 1, 0, 1, 0, 0, 0 };
static convertor_t *cct_head = NULL;

convertor_t *_charconv_load_cct_convertor(const char *file_name, int *error) {
	convertor_t *convertor = NULL;
	FILE *file;
	char magic[4];
	uint32_t version;
	uint_fast32_t i, j;

	for (convertor = cct_head; convertor != NULL; convertor = convertor->next) {
		if (strcmp(convertor->name, file_name) == 0)
			return convertor;
	}

	if ((file = fopen(file_name, "r")) == NULL)
		ERROR(CHARCONV_ERRNO);

	READ(4, magic);
	if (memcmp(magic, "T3CM", 4) != 0)
		ERROR(CHARCONV_INVALID_FORMAT);
	READ_DWORD(version);
	if (version != UINT32_C(0))
		ERROR(CHARCONV_WRONG_VERSION);

	if ((convertor = calloc(1, sizeof(convertor_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);

	/* Make sure all pointers are correctly initialized, even if the NULL pointer
	   is not actually zero. */
	convertor->name = NULL;
	convertor->next = NULL;
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
	convertor->codepoint_sorted_multi_mappings = NULL;

	convertor->codepage_flags.get_flags = get_default_flags;
	convertor->unicode_flags.get_flags = get_default_flags;

	READ_WORD(convertor->flags);
	READ_BYTE(convertor->subchar_len);
	READ(MAX_CHAR_BYTES, convertor->subchar);
	READ_BYTE(convertor->subchar1);
	READ_BYTE(convertor->nr_shift_states);
	READ_BYTE(convertor->nr_codepage_states);
	READ_WORD(convertor->nr_codepage_entries);
	READ_DWORD(convertor->codepage_range);
	READ_BYTE(convertor->nr_unicode_states);
	READ_WORD(convertor->nr_unicode_entries);
	READ_DWORD(convertor->unicode_range);
	READ_BYTE(convertor->codepage_flags.default_flags);
	READ_BYTE(convertor->unicode_flags.default_flags);
	READ_BYTE(convertor->single_size);

	if ((convertor->shift_states = calloc(convertor->nr_shift_states, sizeof(shift_state_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
	if ((convertor->codepage_states = calloc(convertor->nr_codepage_states + 1, sizeof(state_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
	if ((convertor->codepage_entries = malloc((convertor->nr_codepage_entries + 1) * sizeof(entry_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
	if ((convertor->unicode_states = calloc(convertor->nr_unicode_states + 1, sizeof(state_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
	if ((convertor->unicode_entries = malloc((convertor->nr_unicode_entries + 1) * sizeof(entry_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);

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

	if (!validate_states(convertor->codepage_states, convertor->nr_codepage_states, convertor->flags, convertor->codepage_range))
		ERROR(CHARCONV_INVALID_FORMAT);
	if (!validate_states(convertor->unicode_states, convertor->nr_unicode_states, 0, convertor->unicode_range))
		ERROR(CHARCONV_INVALID_FORMAT);

	if ((convertor->codepage_mappings = malloc(convertor->codepage_range * sizeof(uint16_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
	if ((convertor->unicode_mappings = calloc(convertor->unicode_range, convertor->single_size)) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
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
			ERROR(CHARCONV_OUT_OF_MEMORY);
		for (i = 0; i < convertor->nr_multi_mappings; i++) {
			READ_BYTE(convertor->multi_mappings[i].codepoints_length);
			for (j = 0; j < convertor->multi_mappings[i].codepoints_length; j++)
				READ_WORD(convertor->multi_mappings[i].codepoints[j]);
			READ_BYTE(convertor->multi_mappings[i].bytes_length);
			READ(convertor->multi_mappings[i].bytes_length, convertor->multi_mappings[i].bytes);
		}

		if ((convertor->codepage_sorted_multi_mappings =
				malloc(convertor->nr_multi_mappings * sizeof(multi_mapping_t *))) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		if ((convertor->codepoint_sorted_multi_mappings =
				malloc(convertor->nr_multi_mappings * sizeof(multi_mapping_t *))) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		for (i = 0; i < convertor->nr_multi_mappings; i++) {
			convertor->codepage_sorted_multi_mappings[i] = &convertor->multi_mappings[i];
			convertor->codepoint_sorted_multi_mappings[i] = &convertor->multi_mappings[i];
		}
		qsort(convertor->codepage_sorted_multi_mappings, convertor->nr_multi_mappings, sizeof(multi_mapping_t *),
			(compar_func_t) compare_multi_mapping_codepage);
		qsort(convertor->codepoint_sorted_multi_mappings, convertor->nr_multi_mappings, sizeof(multi_mapping_t *),
			(compar_func_t) compare_multi_mapping_codepoints);
	}


	if (fread(magic, 1, 1, file) != 0 || !feof(file))
		ERROR(CHARCONV_INVALID_FORMAT);

	if ((convertor->name = strdup(file_name)) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);

	fclose(file);
	convertor->next = cct_head;
	cct_head = convertor;
	return convertor;

end_error:
	if (file != NULL)
		fclose(file);
	if (convertor == NULL)
		return NULL;
	_charconv_unload_cct_convertor(convertor);
	return NULL;
}

void _charconv_unload_cct_convertor(convertor_t *convertor) {
	if (cct_head == convertor) {
		cct_head = cct_head->next;
	} else {
		convertor_t *ptr;
		for (ptr = cct_head; ptr != NULL && ptr->next != convertor; ptr = ptr->next) {}
		if (ptr != NULL)
			ptr->next = ptr->next->next;
	}
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
	free(convertor->codepoint_sorted_multi_mappings);
	free(convertor);
}

static bool read_states(FILE *file, uint_fast32_t nr_states, state_t *states, entry_t *entries, uint_fast32_t max_entries, int *error) {
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
					ERROR(CHARCONV_INVALID_FORMAT);
				memset(states[i].map + entries[entries_idx - 1].low, j - 1, entries[entries_idx].low - entries[entries_idx - 1].low);
			} else {
				if (entries[entries_idx].low != 0)
					ERROR(CHARCONV_INVALID_FORMAT);
			}
			entries_idx++;
		}
		memset(states[i].map + entries[entries_idx - 1].low, j - 1, 256 - entries[entries_idx - 1].low);
		if (j < states[i].nr_entries)
			ERROR(CHARCONV_INVALID_FORMAT);
	}
	if (entries_idx != max_entries)
		ERROR(CHARCONV_INVALID_FORMAT);

	return true;
end_error:
	return false;
}

static bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t range) {
	uint_fast32_t i, j, calculated_range;
	int next_is_initial;

	nr_states++;

	for (i = 0; i < nr_states; i++) {
		for (j = 0; j < states[i].nr_entries; j++) {
			if (states[i].entries[j].next_state >= nr_states)
				return false;

			next_is_initial = states[i].entries[j].next_state == 0 ||
					((flags & MULTIBYTE_START_STATE_1) && states[i].entries[j].next_state == 1);
			if ((states[i].entries[j].action != ACTION_VALID) ^ next_is_initial)
				return false;
		}
	}

	calculated_range = 0;
	update_state_attributes(states, 0);
	calculated_range = states[0].range;
	if (flags & MULTIBYTE_START_STATE_1) {
		states[1].base = calculated_range;
		update_state_attributes(states, 1);
		calculated_range += states[1].range;
	}

	if (calculated_range != range)
		return false;

	return true;
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
	states[idx].complete = true;
}

static uint8_t get_default_flags(const flags_t *flags, uint_fast32_t idx) {
	(void) idx;
	return flags->default_flags;
}
static uint8_t get_flags_1(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | ((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3);
}
static uint8_t get_flags_2(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3) << 2);
}
static uint8_t get_flags_3(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | ((flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf);
}
static uint8_t get_flags_4(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3) << 4);
}
static uint8_t get_flags_5(const flags_t *flags, uint_fast32_t idx) {
	uint8_t bits = flags->flags[idx >> 1] >> (4 * (idx & 1));
	return flags->default_flags | (bits & 0x3) | ((bits & 0xc) << 2);
}
static uint8_t get_flags_6(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf) << 2);
}
static uint8_t get_flags_8(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3) << 6);
}
static uint8_t get_flags_9(const flags_t *flags, uint_fast32_t idx) {
	uint8_t bits = flags->flags[idx >> 1] >> (4 * (idx & 1));
	return flags->default_flags | (bits & 0x3) | ((bits & 0xc) << 4);
}
static uint8_t get_flags_10(const flags_t *flags, uint_fast32_t idx) {
	uint8_t bits = flags->flags[idx >> 1] >> (4 * (idx & 1));
	return flags->default_flags | ((bits & 0x3) << 2) | ((bits & 0xc) << 4);
}
static uint8_t get_flags_12(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | (((flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf) << 4);
}
static uint8_t get_flags_15(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | flags->flags[idx];
}

static uint8_t get_flags_1_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_1(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_2_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_2(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_3_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_3(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_4_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_4(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_5_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_5(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_6_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_6(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_8_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_8(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_9_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_9(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_10_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_10(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_12_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_12(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_15_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_15(flags, (idx & 15) + (flags->indices[idx >> 4] << 4));
}

static uint8_t (* const get_flags[16])(const flags_t *flags, uint_fast32_t idx) = {
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

static uint8_t (* const get_flags_trie[16])(const flags_t *flags, uint_fast32_t idx) = {
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

static bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, int *error) {
	uint_fast32_t nr_flag_bytes, nr_blocks, i;
	uint8_t flag_info;
	READ_BYTE(flag_info);

	nr_flag_bytes = (range + (1 << flag_info_to_shift[flag_info & 0xf]) - 1) >> flag_info_to_shift[flag_info & 0xf];
	if (flag_info & 0x80) {
		nr_flag_bytes = (nr_flag_bytes + 15) / 16;
		if ((flags->indices = malloc(nr_flag_bytes * 2)) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		for (i = 0; i < nr_flag_bytes; i++)
			READ_WORD(flags->indices[i]);

		READ_WORD(nr_blocks);
		nr_blocks++;
		if ((flags->flags = malloc(nr_blocks * 16)) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		READ(nr_blocks * 16, flags->flags);
		flags->get_flags = get_flags_trie[flag_info & 0xf];
	} else {
		if ((flags->flags = malloc(nr_flag_bytes)) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		READ(nr_flag_bytes, flags->flags);
		flags->get_flags = get_flags[flag_info & 0xf];
	}

	return true;
end_error:
	return false;
}

static int compare_multi_mapping_codepage(const multi_mapping_t **a, const multi_mapping_t **b) {
	if ((*a)->bytes_length < (*b)->bytes_length)
		return 1;
	if ((*a)->bytes_length > (*b)->bytes_length)
		return -1;
	return 0;
}

static int compare_multi_mapping_codepoints(const multi_mapping_t **a, const multi_mapping_t **b) {
	if ((*a)->codepoints_length < (*b)->codepoints_length)
		return 1;
	if ((*a)->codepoints_length > (*b)->codepoints_length)
		return -1;
	return 0;
}
