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
#include <errno.h>

#include "charconv_internal.h"
#include "cct_convertor.h"

/* FIXME: check limits on everything read! */


typedef int (*compar_func_t)(const void *, const void *);

static bool read_states(FILE *file, uint_fast32_t nr, state_t *states, entry_t *entries,
	uint_fast32_t max_entries, charconv_error_t *error);
static bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t range);
static void update_state_attributes(state_t *states, uint_fast32_t idx);
static uint8_t get_default_flags(const flags_t *flags, uint_fast32_t idx);
static bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, charconv_error_t *error);
static int compare_multi_mapping_codepage(const multi_mapping_t **a, const multi_mapping_t **b);
static int compare_multi_mapping_codepoints(const multi_mapping_t **a, const multi_mapping_t **b);
static bool load_multi_mappings(FILE *file, convertor_t *convertor, charconv_error_t *error);
static bool load_variants(FILE *file, convertor_t *convertor, charconv_error_t *error);

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)
#define READ(count, buf) do { if (fread(buf, 1, count, file) != (size_t) count) ERROR(CHARCONV_TRUNCATED_MAP); } while (0)
#define READ_BYTE(store) do { uint8_t value; READ(1, &value); store = value; } while (0)
#define READ_WORD(store) do { uint16_t value; READ(2, &value); store = ntohs(value); } while (0)
#define READ_DWORD(store) do { uint32_t value; READ(4, &value); store = ntohl(value); } while (0)

static const int flag_info_to_shift[16] = { 0, 2, 2, 1, 2, 1, 1, 0, 2, 1, 1, 0, 1, 0, 0, 0 };
static convertor_t *cct_head = NULL;

convertor_t *_charconv_load_cct_convertor(const char *name, charconv_error_t *error, variant_t **variant) {
	convertor_t *convertor = NULL;
	FILE *file;
	char magic[4];
	uint32_t version;
	uint_fast32_t i;

	for (convertor = cct_head; convertor != NULL; convertor = convertor->next) {
		if (convertor->variants == NULL) {
			if (strcmp(convertor->name, name) == 0) {
				*variant = NULL;
				convertor->refcount++;
				return convertor;
			}
		} else {
			for (i = 0; i < convertor->nr_variants; i++) {
				if (strcmp(convertor->variants[i].id, name) == 0) {
					*variant = &convertor->variants[i];
					convertor->refcount++;
					return convertor;
				}
			}
		}
	}

	if ((file = _charconv_db_open(name, ".cct", error)) == NULL)
		goto end_error;

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
	convertor->refcount = 1;

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

	if ((convertor->flags & MULTI_MAPPINGS_AVAILABLE) && !load_multi_mappings(file, convertor, error))
		goto end_error;

	if ((convertor->flags & VARIANTS_AVAILABLE) && !load_variants(file, convertor, error))
		goto end_error;

	if (fread(magic, 1, 1, file) != 0 || !feof(file))
		ERROR(CHARCONV_INVALID_FORMAT);

	if ((convertor->name = _charconv_strdup(name)) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);

	fclose(file);
	convertor->next = cct_head;
	cct_head = convertor;


	if (convertor->variants == NULL) {
		if (strcmp(convertor->name, name) == 0) {
			*variant = NULL;
			return convertor;
		}
	} else {
		for (i = 0; i < convertor->nr_variants; i++) {
			if (strcmp(convertor->variants[i].id, name) == 0) {
				*variant = &convertor->variants[i];
				return convertor;
			}
		}
	}

	if (error != NULL) {
		errno = ENOENT;
		*error = CHARCONV_ERRNO;
	}
end_error:
	if (file != NULL)
		fclose(file);
	if (convertor != NULL)
		_charconv_unload_cct_convertor(convertor);
	return NULL;
}

void _charconv_unload_cct_convertor(convertor_t *convertor) {
	if (--convertor->refcount > 0)
		return;
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
	if (convertor->variants != NULL) {
		uint_fast32_t i;
		for (i = 0; i < convertor->nr_variants; i++) {
			free(convertor->variants[i].simple_mappings);
			free(convertor->variants[i].multi_mappings);
			free(convertor->variants[i].codepage_sorted_multi_mappings);
			free(convertor->variants[i].codepoint_sorted_multi_mappings);
			free(convertor->variants[i].id);
		}
		free(convertor->variants);
	}
	free(convertor);
}

static bool read_states(FILE *file, uint_fast32_t nr_states, state_t *states, entry_t *entries,
		uint_fast32_t max_entries, charconv_error_t *error)
{
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
			case ACTION_FINAL_LEN1_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_LEN2_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_LEN3_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_LEN4_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_PAIR:
				states[idx].entries[i].action &= !ACTION_FLAG_PAIR;
			case ACTION_FINAL_PAIR_NOFLAGS:
				states[idx].entries[i].mul = 2;
				goto action_final_shared;
			case ACTION_FINAL_NOFLAGS:
			case ACTION_FINAL_LEN1_NOFLAGS:
			case ACTION_FINAL_LEN2_NOFLAGS:
			case ACTION_FINAL_LEN3_NOFLAGS:
			case ACTION_FINAL_LEN4_NOFLAGS:
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

static uint8_t bits2flags4[][16];
static uint8_t bits2flags2[][4];
static uint8_t bits2flags1[][2];

static uint8_t get_default_flags(const flags_t *flags, uint_fast32_t idx) {
	(void) idx;
	return flags->default_flags;
}
static uint8_t get_flags_1(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | flags->bits2flags[(flags->flags[idx >> 3] >> (idx & 7)) & 0x1];
}
static uint8_t get_flags_2(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | flags->bits2flags[(flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3];
}
static uint8_t get_flags_4(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | flags->bits2flags[(flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf];
}
static uint8_t get_flags_8(const flags_t *flags, uint_fast32_t idx) {
	return flags->default_flags | flags->flags[idx];
}

static uint8_t get_flags_1_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_1(flags, (idx & 127) + (flags->indices[idx >> 7] << 7));
}
static uint8_t get_flags_2_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_2(flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_4_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_4(flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_8_trie(const flags_t *flags, uint_fast32_t idx) {
	return get_flags_8(flags, (idx & 15) + (flags->indices[idx >> 4] << 4));
}


static bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, charconv_error_t *error) {
	uint_fast32_t nr_flag_bytes, nr_blocks, i;
	uint8_t flag_info;
	bool trie;
	READ_BYTE(flag_info);

	trie = (flag_info & 0x80) != 0;
	flag_info &= 0x7f;
	if (flag_info > 106) {
		ERROR(CHARCONV_INVALID_FORMAT);
	} else if (flag_info > 98) {
		flags->bits2flags = bits2flags1[flag_info - 99];
		flags->get_flags = trie ? get_flags_1_trie : get_flags_1;
		nr_flag_bytes = (range + 7) / 8;
	} else if (flag_info > 70) {
		flags->bits2flags = bits2flags2[flag_info - 71];
		flags->get_flags = trie ? get_flags_2_trie : get_flags_2;
		nr_flag_bytes = (range + 3) / 4;
	} else if (flag_info > 0) {
		flags->bits2flags = bits2flags4[flag_info - 1];
		flags->get_flags = trie ? get_flags_4_trie : get_flags_4;
		nr_flag_bytes = (range + 1) / 2;
	} else {
		flags->get_flags = trie ? get_flags_8_trie : get_flags_8;
		nr_flag_bytes = range;
	}

	if (trie) {
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
	} else {
		if ((flags->flags = malloc(nr_flag_bytes)) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		READ(nr_flag_bytes, flags->flags);
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


static bool load_multi_mappings(FILE *file, convertor_t *convertor, charconv_error_t *error) {
	uint_fast32_t i, j;

	/* FIXME: check length fields for maximum permissable lengths */
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
	return true;
end_error:
	return false;
}


static bool load_variants(FILE *file, convertor_t *convertor, charconv_error_t *error) {
	uint_fast32_t i, j;
	variant_t *variant;
	size_t id_len;

	READ_WORD(convertor->nr_variants);
	if ((convertor->variants = malloc(convertor->nr_variants * sizeof(variant_t))) == NULL)
		ERROR(CHARCONV_OUT_OF_MEMORY);
	for (i = 0; i < convertor->nr_variants; i++) {
		convertor->variants[i].simple_mappings = NULL;
		convertor->variants[i].multi_mappings = NULL;
		convertor->variants[i].id = NULL;
	}

	for (i = 0; i < convertor->nr_variants; i++) {
		variant = convertor->variants + i;

		READ_BYTE(id_len);
		if ((variant->id = malloc(id_len + 1)) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		READ(id_len, variant->id);
		variant->id[id_len] = 0;
		READ_BYTE(variant->flags);

		READ_WORD(variant->nr_simple_mappings);
		if ((variant->simple_mappings =
				calloc(variant->nr_simple_mappings, sizeof(variant_mapping_t))) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		for (j = 0; j < variant->nr_simple_mappings; j++) {
			READ_BYTE(variant->simple_mappings[j].to_unicode_flags);
			READ_BYTE(variant->simple_mappings[j].from_unicode_flags);
			READ((variant->simple_mappings[j].from_unicode_flags & FROM_UNICODE_LENGTH_MASK) + 1,
				&variant->simple_mappings[j].codepage_bytes);
			READ_WORD(variant->simple_mappings[j].codepoint);
			if ((variant->simple_mappings[j].codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
				uint_fast32_t next_codepoint;
				READ_WORD(next_codepoint);
				variant->simple_mappings[j].codepoint -= UINT32_C(0xd800);
				variant->simple_mappings[j].codepoint += 0x10000 + next_codepoint - UINT32_C(0xdc00);
			}
			READ_WORD(variant->simple_mappings[j].sort_idx);
		}

		READ_WORD(variant->nr_multi_mappings);
		if (variant->nr_multi_mappings == 0)
			continue;

		if ((variant->multi_mappings =
				malloc(variant->nr_multi_mappings * sizeof(multi_mapping_t))) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		for (j = 0; j < variant->nr_multi_mappings; j++) {
			READ_BYTE(variant->multi_mappings[j].codepoints_length);
			for (j = 0; j < variant->multi_mappings[j].codepoints_length; j++)
				READ_WORD(variant->multi_mappings[j].codepoints[j]);
			READ_BYTE(variant->multi_mappings[j].bytes_length);
			READ(variant->multi_mappings[j].bytes_length, variant->multi_mappings[j].bytes);
		}

		if ((variant->codepage_sorted_multi_mappings =
				malloc((convertor->nr_multi_mappings + variant->nr_multi_mappings) * sizeof(multi_mapping_t *))) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		if ((variant->codepoint_sorted_multi_mappings =
				malloc((convertor->nr_multi_mappings + variant->nr_multi_mappings) * sizeof(multi_mapping_t *))) == NULL)
			ERROR(CHARCONV_OUT_OF_MEMORY);
		for (i = 0; i < convertor->nr_multi_mappings; i++) {
			variant->codepage_sorted_multi_mappings[i] = &convertor->multi_mappings[i];
			variant->codepoint_sorted_multi_mappings[i] = &convertor->multi_mappings[i];
		}
		for (i = 0; i < variant->nr_multi_mappings; i++) {
			variant->codepage_sorted_multi_mappings[i + convertor->nr_multi_mappings] = &variant->multi_mappings[i];
			variant->codepoint_sorted_multi_mappings[i + convertor->nr_multi_mappings] = &variant->multi_mappings[i];
		}
		qsort(variant->codepage_sorted_multi_mappings, convertor->nr_multi_mappings + variant->nr_multi_mappings,
			sizeof(multi_mapping_t *), (compar_func_t) compare_multi_mapping_codepage);
		qsort(variant->codepoint_sorted_multi_mappings, convertor->nr_multi_mappings + variant->nr_multi_mappings,
			sizeof(multi_mapping_t *), (compar_func_t) compare_multi_mapping_codepoints);
	}
	return true;
end_error:
	return false;
}

static uint8_t bits2flags4[][16] = {
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x10, 0x11, 0x14, 0x15, 0x18, 0x19, 0x1c, 0x1d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x20, 0x21, 0x24, 0x25, 0x28, 0x29, 0x2c, 0x2d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e },
{ 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33 },
{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x20, 0x21, 0x24, 0x25, 0x30, 0x31, 0x34, 0x35 },
{ 0x00, 0x02, 0x04, 0x06, 0x10, 0x12, 0x14, 0x16, 0x20, 0x22, 0x24, 0x26, 0x30, 0x32, 0x34, 0x36 },
{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x20, 0x21, 0x28, 0x29, 0x30, 0x31, 0x38, 0x39 },
{ 0x00, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x20, 0x22, 0x28, 0x2a, 0x30, 0x32, 0x38, 0x3a },
{ 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x40, 0x41, 0x42, 0x43, 0x48, 0x49, 0x4a, 0x4b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4c, 0x4d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e },
{ 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x40, 0x41, 0x42, 0x43, 0x50, 0x51, 0x52, 0x53 },
{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x40, 0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 },
{ 0x00, 0x02, 0x04, 0x06, 0x10, 0x12, 0x14, 0x16, 0x40, 0x42, 0x44, 0x46, 0x50, 0x52, 0x54, 0x56 },
{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x40, 0x41, 0x48, 0x49, 0x50, 0x51, 0x58, 0x59 },
{ 0x00, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x40, 0x42, 0x48, 0x4a, 0x50, 0x52, 0x58, 0x5a },
{ 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c },
{ 0x00, 0x01, 0x02, 0x03, 0x20, 0x21, 0x22, 0x23, 0x40, 0x41, 0x42, 0x43, 0x60, 0x61, 0x62, 0x63 },
{ 0x00, 0x01, 0x04, 0x05, 0x20, 0x21, 0x24, 0x25, 0x40, 0x41, 0x44, 0x45, 0x60, 0x61, 0x64, 0x65 },
{ 0x00, 0x02, 0x04, 0x06, 0x20, 0x22, 0x24, 0x26, 0x40, 0x42, 0x44, 0x46, 0x60, 0x62, 0x64, 0x66 },
{ 0x00, 0x01, 0x08, 0x09, 0x20, 0x21, 0x28, 0x29, 0x40, 0x41, 0x48, 0x49, 0x60, 0x61, 0x68, 0x69 },
{ 0x00, 0x02, 0x08, 0x0a, 0x20, 0x22, 0x28, 0x2a, 0x40, 0x42, 0x48, 0x4a, 0x60, 0x62, 0x68, 0x6a },
{ 0x00, 0x04, 0x08, 0x0c, 0x20, 0x24, 0x28, 0x2c, 0x40, 0x44, 0x48, 0x4c, 0x60, 0x64, 0x68, 0x6c },
{ 0x00, 0x01, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41, 0x50, 0x51, 0x60, 0x61, 0x70, 0x71 },
{ 0x00, 0x02, 0x10, 0x12, 0x20, 0x22, 0x30, 0x32, 0x40, 0x42, 0x50, 0x52, 0x60, 0x62, 0x70, 0x72 },
{ 0x00, 0x04, 0x10, 0x14, 0x20, 0x24, 0x30, 0x34, 0x40, 0x44, 0x50, 0x54, 0x60, 0x64, 0x70, 0x74 },
{ 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78 },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x80, 0x81, 0x82, 0x83, 0x88, 0x89, 0x8a, 0x8b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x80, 0x81, 0x84, 0x85, 0x88, 0x89, 0x8c, 0x8d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e },
{ 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x80, 0x81, 0x82, 0x83, 0x90, 0x91, 0x92, 0x93 },
{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x80, 0x81, 0x84, 0x85, 0x90, 0x91, 0x94, 0x95 },
{ 0x00, 0x02, 0x04, 0x06, 0x10, 0x12, 0x14, 0x16, 0x80, 0x82, 0x84, 0x86, 0x90, 0x92, 0x94, 0x96 },
{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x80, 0x81, 0x88, 0x89, 0x90, 0x91, 0x98, 0x99 },
{ 0x00, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x80, 0x82, 0x88, 0x8a, 0x90, 0x92, 0x98, 0x9a },
{ 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x80, 0x84, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c },
{ 0x00, 0x01, 0x02, 0x03, 0x20, 0x21, 0x22, 0x23, 0x80, 0x81, 0x82, 0x83, 0xa0, 0xa1, 0xa2, 0xa3 },
{ 0x00, 0x01, 0x04, 0x05, 0x20, 0x21, 0x24, 0x25, 0x80, 0x81, 0x84, 0x85, 0xa0, 0xa1, 0xa4, 0xa5 },
{ 0x00, 0x02, 0x04, 0x06, 0x20, 0x22, 0x24, 0x26, 0x80, 0x82, 0x84, 0x86, 0xa0, 0xa2, 0xa4, 0xa6 },
{ 0x00, 0x01, 0x08, 0x09, 0x20, 0x21, 0x28, 0x29, 0x80, 0x81, 0x88, 0x89, 0xa0, 0xa1, 0xa8, 0xa9 },
{ 0x00, 0x02, 0x08, 0x0a, 0x20, 0x22, 0x28, 0x2a, 0x80, 0x82, 0x88, 0x8a, 0xa0, 0xa2, 0xa8, 0xaa },
{ 0x00, 0x04, 0x08, 0x0c, 0x20, 0x24, 0x28, 0x2c, 0x80, 0x84, 0x88, 0x8c, 0xa0, 0xa4, 0xa8, 0xac },
{ 0x00, 0x01, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x80, 0x81, 0x90, 0x91, 0xa0, 0xa1, 0xb0, 0xb1 },
{ 0x00, 0x02, 0x10, 0x12, 0x20, 0x22, 0x30, 0x32, 0x80, 0x82, 0x90, 0x92, 0xa0, 0xa2, 0xb0, 0xb2 },
{ 0x00, 0x04, 0x10, 0x14, 0x20, 0x24, 0x30, 0x34, 0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4, 0xb0, 0xb4 },
{ 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8 },
{ 0x00, 0x01, 0x02, 0x03, 0x40, 0x41, 0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0xc0, 0xc1, 0xc2, 0xc3 },
{ 0x00, 0x01, 0x04, 0x05, 0x40, 0x41, 0x44, 0x45, 0x80, 0x81, 0x84, 0x85, 0xc0, 0xc1, 0xc4, 0xc5 },
{ 0x00, 0x02, 0x04, 0x06, 0x40, 0x42, 0x44, 0x46, 0x80, 0x82, 0x84, 0x86, 0xc0, 0xc2, 0xc4, 0xc6 },
{ 0x00, 0x01, 0x08, 0x09, 0x40, 0x41, 0x48, 0x49, 0x80, 0x81, 0x88, 0x89, 0xc0, 0xc1, 0xc8, 0xc9 },
{ 0x00, 0x02, 0x08, 0x0a, 0x40, 0x42, 0x48, 0x4a, 0x80, 0x82, 0x88, 0x8a, 0xc0, 0xc2, 0xc8, 0xca },
{ 0x00, 0x04, 0x08, 0x0c, 0x40, 0x44, 0x48, 0x4c, 0x80, 0x84, 0x88, 0x8c, 0xc0, 0xc4, 0xc8, 0xcc },
{ 0x00, 0x01, 0x10, 0x11, 0x40, 0x41, 0x50, 0x51, 0x80, 0x81, 0x90, 0x91, 0xc0, 0xc1, 0xd0, 0xd1 },
{ 0x00, 0x02, 0x10, 0x12, 0x40, 0x42, 0x50, 0x52, 0x80, 0x82, 0x90, 0x92, 0xc0, 0xc2, 0xd0, 0xd2 },
{ 0x00, 0x04, 0x10, 0x14, 0x40, 0x44, 0x50, 0x54, 0x80, 0x84, 0x90, 0x94, 0xc0, 0xc4, 0xd0, 0xd4 },
{ 0x00, 0x08, 0x10, 0x18, 0x40, 0x48, 0x50, 0x58, 0x80, 0x88, 0x90, 0x98, 0xc0, 0xc8, 0xd0, 0xd8 },
{ 0x00, 0x01, 0x20, 0x21, 0x40, 0x41, 0x60, 0x61, 0x80, 0x81, 0xa0, 0xa1, 0xc0, 0xc1, 0xe0, 0xe1 },
{ 0x00, 0x02, 0x20, 0x22, 0x40, 0x42, 0x60, 0x62, 0x80, 0x82, 0xa0, 0xa2, 0xc0, 0xc2, 0xe0, 0xe2 },
{ 0x00, 0x04, 0x20, 0x24, 0x40, 0x44, 0x60, 0x64, 0x80, 0x84, 0xa0, 0xa4, 0xc0, 0xc4, 0xe0, 0xe4 },
{ 0x00, 0x08, 0x20, 0x28, 0x40, 0x48, 0x60, 0x68, 0x80, 0x88, 0xa0, 0xa8, 0xc0, 0xc8, 0xe0, 0xe8 },
{ 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 }};

static uint8_t bits2flags2[][4] = {
{ 0x00, 0x01, 0x02, 0x03 },
{ 0x00, 0x01, 0x04, 0x05 },
{ 0x00, 0x02, 0x04, 0x06 },
{ 0x00, 0x01, 0x08, 0x09 },
{ 0x00, 0x02, 0x08, 0x0a },
{ 0x00, 0x04, 0x08, 0x0c },
{ 0x00, 0x01, 0x10, 0x11 },
{ 0x00, 0x02, 0x10, 0x12 },
{ 0x00, 0x04, 0x10, 0x14 },
{ 0x00, 0x08, 0x10, 0x18 },
{ 0x00, 0x01, 0x20, 0x21 },
{ 0x00, 0x02, 0x20, 0x22 },
{ 0x00, 0x04, 0x20, 0x24 },
{ 0x00, 0x08, 0x20, 0x28 },
{ 0x00, 0x10, 0x20, 0x30 },
{ 0x00, 0x01, 0x40, 0x41 },
{ 0x00, 0x02, 0x40, 0x42 },
{ 0x00, 0x04, 0x40, 0x44 },
{ 0x00, 0x08, 0x40, 0x48 },
{ 0x00, 0x10, 0x40, 0x50 },
{ 0x00, 0x20, 0x40, 0x60 },
{ 0x00, 0x01, 0x80, 0x81 },
{ 0x00, 0x02, 0x80, 0x82 },
{ 0x00, 0x04, 0x80, 0x84 },
{ 0x00, 0x08, 0x80, 0x88 },
{ 0x00, 0x10, 0x80, 0x90 },
{ 0x00, 0x20, 0x80, 0xa0 },
{ 0x00, 0x40, 0x80, 0xc0 }};

static uint8_t bits2flags1[][2] = {
{ 0x00, 0x01 },
{ 0x00, 0x02 },
{ 0x00, 0x04 },
{ 0x00, 0x08 },
{ 0x00, 0x10 },
{ 0x00, 0x20 },
{ 0x00, 0x40 },
{ 0x00, 0x80 }};

