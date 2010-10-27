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
#include <pthread.h>

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
	uint8_t (*get_flags)(const struct flags_t *flags, uint_fast32_t idx);
	uint8_t default_flags;
} flags_t;

typedef struct {
	uint8_t bytes[31];
	uint16_t codepoints[19];
	uint8_t bytes_length;
	uint8_t codepoints_length;
} multi_mapping_t;

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

	uint32_t codepage_range;
	uint32_t unicode_range;
	uint32_t nr_multi_mappings;

	int refcount;

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
	uint8_t to_state, from_state;
} convertor_state_t;

typedef struct {
	uint8_t to_state, from_state;
} save_state_t;

static void unload_cct_convertor(convertor_t *convertor);
static t3_bool read_states(FILE *file, uint_fast32_t nr, state_t *states, entry_t *entries, uint_fast32_t max_entries, int *error);
static t3_bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t range);
static void update_state_attributes(state_t *states, uint_fast32_t idx);
static uint8_t get_default_flags(const flags_t *flags, uint_fast32_t idx);
static t3_bool read_flags(FILE *file, flags_t *flags, uint_fast32_t range, int *error);
static int to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft);
static void close_cct_convertor(convertor_state_t *handle);

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)
#define READ(count, buf) do { if (fread(buf, 1, count, file) != (size_t) count) ERROR(T3_ERR_READ_ERROR); } while (0)
#define READ_BYTE(store) do { uint8_t value; if (fread(&value, 1, 1, file) != (size_t) 1) ERROR(T3_ERR_READ_ERROR); store = value; } while (0)
#define READ_WORD(store) do { uint16_t value; if (fread(&value, 1, 2, file) != (size_t) 2) ERROR(T3_ERR_READ_ERROR); store = ntohs(value); } while (0)
#define READ_DWORD(store) do { uint32_t value; if (fread(&value, 1, 4, file) != (size_t) 4) ERROR(T3_ERR_READ_ERROR); store = ntohl(value); } while (0)

static const int flag_info_to_shift[16] = { 0, 2, 2, 1, 2, 1, 1, 0, 2, 1, 1, 0, 1, 0, 0, 0 };
static pthread_mutex_t cct_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static convertor_t *cct_head = NULL;

static convertor_t *load_cct_convertor(const char *file_name, int *error) {
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

	convertor->codepage_flags.get_flags = get_default_flags;
	convertor->unicode_flags.get_flags = get_default_flags;

	READ_BYTE(convertor->flags);
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

	if (!validate_states(convertor->codepage_states, convertor->nr_codepage_states, convertor->flags, convertor->codepage_range))
		ERROR(T3_ERR_INVALID_FORMAT);
	if (!validate_states(convertor->unicode_states, convertor->nr_unicode_states, 0, convertor->unicode_range))
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
		for (i = 0; i < convertor->nr_multi_mappings; i++) {
			READ_BYTE(convertor->multi_mappings[i].codepoints_length);
			for (j = 0; j < convertor->multi_mappings[i].codepoints_length; j++)
				READ_WORD(convertor->multi_mappings[i].codepoints[j]);
			READ_BYTE(convertor->multi_mappings[i].bytes_length);
			READ(convertor->multi_mappings[i].bytes_length, convertor->multi_mappings[i].bytes);
		}
	}

	if (fread(magic, 1, 1, file) != 0 || !feof(file))
		ERROR(T3_ERR_INVALID_FORMAT);

	if ((convertor->name = strdup(file_name)) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);

	fclose(file);
	return convertor;

end_error:
	if (file != NULL)
		fclose(file);
	if (convertor == NULL)
		return NULL;
	unload_cct_convertor(convertor);
	return NULL;
}

static void unload_cct_convertor(convertor_t *convertor) {
	if (convertor->next != NULL) {
		if (cct_head == convertor) {
			cct_head = cct_head->next;
		} else {
			convertor_t *ptr;
			for (ptr = cct_head; ptr != NULL && ptr->next != convertor; ptr = ptr->next) {}
			if (ptr != NULL)
				ptr->next = ptr->next->next;
		}
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
	free(convertor);
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

static t3_bool validate_states(state_t *states, uint_fast32_t nr_states, uint8_t flags, uint32_t range) {
	uint_fast32_t i, j, calculated_range;
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

	calculated_range = 0;
	update_state_attributes(states, 0);
	calculated_range = states[0].range;
	if (flags & MULTIBYTE_START_STATE_1) {
		states[1].base = calculated_range;
		update_state_attributes(states, 1);
		calculated_range += states[1].range;
	}

	if (calculated_range != range)
		return t3_false;

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


#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbytesleft)) != 0) \
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
	uint_fast8_t state = handle->to_state;
	uint_fast32_t idx = handle->convertor->codepage_states[handle->to_state].base;
	uint_fast32_t codepoint;
	entry_t *entry;
	uint_fast8_t conv_flags;

	if (flags & CHARCONV_FILE_START) {
		switch (handle->common.utf_type) {
			case UTF32:
			case UTF16:
			case UTF8_BOM:
			case UTF8_STRICT_BOM:
				PUT_UNICODE(UINT32_C(0xFEFF));
				break;
			default:
				break;
		}
	}

	flags |= handle->common.flags & 0xff;

	while (_inbytesleft > 0) {
		entry = &handle->convertor->codepage_states[state].entries[handle->convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;
		_inbytesleft--;

		switch (entry->action) {
			case ACTION_FINAL:
			case ACTION_FINAL_PAIR:
				conv_flags = handle->convertor->codepage_flags.get_flags(&handle->convertor->codepage_flags, idx);
				if (conv_flags & TO_UNICODE_MULTI_START) {
					size_t outbytesleft_tmp, check_len;
					uint_fast32_t i, j;
					char *outbuf_tmp;
					int result;

					for (i = 0; i < handle->convertor->nr_multi_mappings; i++) {
						check_len = min(handle->convertor->multi_mappings[i].bytes_length, *inbytesleft);

						if (memcmp(handle->convertor->multi_mappings[i].bytes, *inbuf, check_len) != 0)
							continue;

						if (check_len != handle->convertor->multi_mappings[i].bytes_length) {
							if (flags & CHARCONV_END_OF_TEXT)
								continue;
							return CHARCONV_INCOMPLETE;
						}

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
							if ((result = handle->common.put_unicode(codepoint, &outbuf_tmp, &outbytesleft_tmp)) != 0)
								return result;
						}
						*outbuf = outbuf_tmp;
						*outbytesleft = outbytesleft_tmp;

						handle->to_state = state = entry->next_state;
						*inbuf = (char *) _inbuf;
						check_len = (*inbytesleft) - check_len;
						*inbytesleft = _inbytesleft;
						while (*inbytesleft > check_len)
							if (to_unicode_skip(handle, inbuf, inbytesleft) != 0)
								return CHARCONV_INTERNAL_ERROR;
						idx = handle->convertor->codepage_states[handle->to_state].base;
						break;
					}
					if (i != handle->convertor->nr_multi_mappings)
						continue;
				}

				if ((conv_flags & TO_UNICODE_PRIVATE_USE) && !(flags & CHARCONV_ALLOW_PRIVATE_USE)) {
					if (!(flags & CHARCONV_SUBSTITUTE))
						return CHARCONV_PRIVATE_USE;
					PUT_UNICODE(UINT32_C(0xFFFD));
					goto sequence_done;
				}
				if ((conv_flags & TO_UNICODE_FALLBACK) && !(flags & CHARCONV_ALLOW_FALLBACK))
					return CHARCONV_FALLBACK;

				codepoint = handle->convertor->codepage_mappings[idx];
				if (codepoint == UINT32_C(0xFFFF)) {
					if (!(flags & CHARCONV_SUBSTITUTE))
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
				if (!(flags & CHARCONV_SUBSTITUTE_ALL))
					return CHARCONV_ILLEGAL;
				PUT_UNICODE(UINT32_C(0xFFFD));
				goto sequence_done;
			case ACTION_UNASSIGNED:
				if (!(flags & CHARCONV_SUBSTITUTE))
					return CHARCONV_UNASSIGNED;
				PUT_UNICODE(UINT32_C(0xFFFD));
				/* FALLTHROUGH */
			case ACTION_SHIFT:
			sequence_done:
				*inbuf = (char *) _inbuf;
				*inbytesleft = _inbytesleft;
				handle->to_state = state = entry->next_state;
				idx = handle->convertor->codepage_states[handle->to_state].base;
				if (flags & CHARCONV_SINGLE_CONVERSION)
					return CHARCONV_SUCCESS;
				break;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}
	}

	if (*inbytesleft != 0) {
		if (flags & CHARCONV_END_OF_TEXT) {
			if (!(flags & CHARCONV_SUBSTITUTE_ALL))
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
	uint_fast8_t state = handle->to_state;
	uint_fast32_t idx = handle->convertor->codepage_states[handle->to_state].base;
	entry_t *entry;

	while (_inbytesleft > 0) {
		entry = &handle->convertor->codepage_states[state].entries[handle->convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;
		_inbytesleft--;

		switch (entry->action) {
			case ACTION_SHIFT:
			case ACTION_VALID:
				state = entry->next_state;
				break;
			case ACTION_FINAL:
			case ACTION_FINAL_PAIR:
			case ACTION_ILLEGAL:
			case ACTION_UNASSIGNED:
				*inbuf = (char *) _inbuf;
				*inbytesleft = _inbytesleft;
				handle->to_state = state = entry->next_state;
				return CHARCONV_SUCCESS;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}
	}

	return CHARCONV_INCOMPLETE;
}

static void to_unicode_reset(convertor_state_t *handle) {
	handle->to_state = 0;
	if (handle->common.utf_type == UTF32 || handle->common.utf_type == UTF16)
		handle->common.put_unicode = get_put_unicode(handle->common.utf_type);
}


#define GET_UNICODE() do { \
	codepoint = handle->common.get_unicode((char **) &_inbuf, &_inbytesleft, t3_false); \
} while (0)

#define PUT_BYTES(count, buffer) do { \
	if (put_bytes(handle, outbuf, outbytesleft, count, buffer) == CHARCONV_NO_SPACE) \
		return CHARCONV_NO_SPACE; \
} while (0)

static int put_bytes(convertor_state_t *handle, char **outbuf, size_t *outbytesleft, size_t count, uint8_t *bytes) {
	uint_fast8_t required_state;
	uint_fast8_t i;

	if (handle->convertor->flags & MULTIBYTE_START_STATE_1) {
		required_state = count > 1 ? 1 : 0;
		if (handle->from_state != required_state) {
			for (i = 0; i < handle->convertor->nr_shift_states; i++) {
				if (handle->convertor->shift_states[i].from_state == handle->from_state &&
						handle->convertor->shift_states[i].to_state == required_state)
				{
					if (*outbytesleft < count + handle->convertor->shift_states[i].len)
						return CHARCONV_NO_SPACE;
					memcpy(*outbuf, handle->convertor->shift_states[i].bytes, handle->convertor->shift_states[i].len);
					*outbuf += handle->convertor->shift_states[i].len;
					*outbytesleft -= handle->convertor->shift_states[i].len;
					handle->from_state = required_state;
					goto write_bytes;
				}
			}
		}
	}
	if (*outbytesleft < count)
		return CHARCONV_NO_SPACE;
write_bytes:
	memcpy(*outbuf, bytes, count);
	*outbuf += count;
	*outbytesleft -= count;
	return CHARCONV_SUCCESS;
}

static int from_unicode_check_multi_mappings(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint_fast32_t codepoint;
	uint_fast32_t i;

	uint16_t codepoints[19];
	char *ptr = (char *) codepoints;
	size_t codepoints_left = 19 * 2;

	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	size_t check_len;
	size_t mapping_check_len;
	t3_bool can_read_more = t3_true;

	GET_UNICODE();
	if (put_utf16(codepoint, &ptr, &codepoints_left) != 0)
		return CHARCONV_INTERNAL_ERROR;

	for (i = 0; i < handle->convertor->nr_multi_mappings; i++) {
		mapping_check_len = handle->convertor->multi_mappings[i].codepoints_length * 2;
		check_len = min(19 * 2 - codepoints_left, mapping_check_len);

		/* No need to read more of the input if we already know that the start doesn't match. */
		if (memcmp(codepoints, handle->convertor->multi_mappings[i].codepoints, check_len) != 0)
			continue;

		/* If we already read enough codepoints, then the comparison already verified that
		   the sequence matches. */
		if (check_len == mapping_check_len)
			goto check_complete;

		while (can_read_more && check_len < mapping_check_len) {
			GET_UNICODE();

			if (codepoint == CHARCONV_UTF_INCOMPLETE) {
				if (flags & CHARCONV_END_OF_TEXT) {
					can_read_more = t3_false;
					goto check_next_mapping;
				}
				return CHARCONV_INCOMPLETE;
			}

			if (codepoint == CHARCONV_UTF_ILLEGAL) {
				can_read_more = t3_false;
				goto check_next_mapping;
			}

			switch (put_utf16(codepoint, &ptr, &codepoints_left)) {
				case CHARCONV_INCOMPLETE:
					if (flags & CHARCONV_END_OF_TEXT) {
						can_read_more = t3_false;
						goto check_next_mapping;
					}
					return CHARCONV_INCOMPLETE;
				case CHARCONV_SUCCESS:
					break;
				case CHARCONV_NO_SPACE:
					can_read_more = t3_false;
					goto check_next_mapping;
				default:
					return CHARCONV_INTERNAL_ERROR;
			}
			check_len = 19 * 2 - codepoints_left;
		}

		if (check_len < mapping_check_len)
			continue;

		if (memcmp(codepoints, handle->convertor->multi_mappings[i].codepoints, check_len) == 0) {
check_complete:
			if (*outbytesleft < handle->convertor->multi_mappings[i].bytes_length)
				return CHARCONV_NO_SPACE;
			PUT_BYTES(handle->convertor->multi_mappings[i].bytes_length, handle->convertor->multi_mappings[i].bytes);

			if (19 * 2 - codepoints_left != mapping_check_len) {
				/* Re-read codepoints up to the number in the mapping. */
				_inbuf = (uint8_t *) *inbuf;
				_inbytesleft = *inbytesleft;
				check_len = 19 * 2 - check_len;
				codepoints_left = 19 * 2;
				ptr = (char *) codepoints;
				while (codepoints_left > check_len) {
					GET_UNICODE();
					put_utf16(codepoint, &ptr, &codepoints_left);
				}
			}
			*inbuf = (char *) _inbuf;
			*inbytesleft = _inbytesleft;
			return CHARCONV_SUCCESS;
		}
check_next_mapping: ;
	}
	return -1;
}

static int from_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint8_t *_inbuf;
	size_t _inbytesleft;
	uint_fast8_t state = 0;
	uint_fast32_t idx = 0;
	uint_fast32_t codepoint;
	entry_t *entry;
	int_fast16_t i;
	uint_fast8_t byte;
	uint_fast8_t conv_flags;

	if (inbuf == NULL || *inbuf == NULL) {
		if (handle->from_state != 0)
			PUT_BYTES(0, NULL);
		return CHARCONV_SUCCESS;
	}

	_inbuf = (uint8_t *) *inbuf;
	_inbytesleft = *inbytesleft;

	if (flags & CHARCONV_FILE_START) {
		if (handle->common.utf_type == UTF32 || handle->common.utf_type == UTF16) {
			codepoint = get_get_unicode(handle->common.utf_type == UTF32 ? UTF32BE : UTF16BE)(inbuf, inbytesleft, t3_false);
			if (codepoint == UINT32_C(0xFEFF)) {
				handle->common.get_unicode = get_get_unicode(handle->common.utf_type == UTF32 ? UTF32BE : UTF16BE);
			} else if (codepoint == CHARCONV_ILLEGAL) {
				codepoint = get_get_unicode(handle->common.utf_type == UTF32 ? UTF32LE : UTF16LE)(inbuf, inbytesleft, t3_false);
				if (codepoint == UINT32_C(0xFEFF))
					handle->common.get_unicode = get_get_unicode(handle->common.utf_type == UTF32 ? UTF32LE : UTF16LE);
				else
					handle->common.get_unicode = get_get_unicode(handle->common.utf_type == UTF32 ? UTF32BE : UTF16BE);
			}
		} else {
			GET_UNICODE();
		}
		/* Anything, including bad input, will simply cause a reset, meaning that only
		   the BOM will be ignored. */
		if (codepoint != UINT32_C(0xFEFF)) {
			_inbuf = (uint8_t *) *inbuf;
			_inbytesleft = *inbytesleft;
		}
	}

	flags |= handle->common.flags & 0xff;

	while (_inbytesleft > 0) {
		GET_UNICODE();
		if (codepoint == CHARCONV_UTF_INCOMPLETE)
			break;

		if (codepoint == CHARCONV_UTF_ILLEGAL) {
			if (!(flags & CHARCONV_SUBSTITUTE_ALL))
				return CHARCONV_ILLEGAL;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
			*inbuf = (char *) _inbuf;
			*inbytesleft = _inbytesleft;
			continue;
		}

		for (i = 16; i >= 0 ; i -= 8) {
			byte = (codepoint >> i) & 0xff;
			entry = &handle->convertor->unicode_states[state].entries[handle->convertor->unicode_states[state].map[byte]];

			idx += entry->base + (byte - entry->low) * entry->mul;

			switch (entry->action) {
				case ACTION_FINAL:
				case ACTION_FINAL_PAIR:
					conv_flags = handle->convertor->unicode_flags.get_flags(&handle->convertor->unicode_flags, idx);
					if (conv_flags & FROM_UNICODE_MULTI_START) {
						switch (from_unicode_check_multi_mappings(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags)) {
							case CHARCONV_SUCCESS:
								_inbuf = (uint8_t *) *inbuf;
								_inbytesleft = *inbytesleft;
								state = 0;
								idx = 0;
								continue;
							case CHARCONV_INCOMPLETE:
								return CHARCONV_INCOMPLETE;
							case CHARCONV_INTERNAL_ERROR:
							default:
								return CHARCONV_INTERNAL_ERROR;
							case CHARCONV_NO_SPACE:
								return CHARCONV_NO_SPACE;
							case -1:
								break;
						}
					}

					if ((conv_flags & FROM_UNICODE_FALLBACK) && !(flags & CHARCONV_ALLOW_FALLBACK))
						return CHARCONV_FALLBACK;

					if (conv_flags & FROM_UNICODE_NOT_AVAIL) {
						if (!(flags & CHARCONV_SUBSTITUTE))
							return CHARCONV_UNASSIGNED;
						if (conv_flags & FROM_UNICODE_SUBCHAR1)
							PUT_BYTES(1, &handle->convertor->subchar1);
						else
							PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
					} else {
						PUT_BYTES((conv_flags & FROM_UNICODE_LENGTH_MASK) + 1,
							&handle->convertor->unicode_mappings[idx * handle->convertor->single_size]);
					}
					goto sequence_done;
				case ACTION_VALID:
					state = entry->next_state;
					break;
				case ACTION_ILLEGAL:
					if (!(flags & CHARCONV_SUBSTITUTE_ALL))
						return CHARCONV_ILLEGAL;
					PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
					goto sequence_done;
				case ACTION_UNASSIGNED:
					if (!(flags & CHARCONV_SUBSTITUTE))
						return CHARCONV_UNASSIGNED;
					PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
					/* FALLTHROUGH */
				sequence_done:
					*inbuf = (char *) _inbuf;
					*inbytesleft = _inbytesleft;
					state = 0; /* Should always be 0! */
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
			if (!(flags & CHARCONV_SUBSTITUTE_ALL))
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

static void from_unicode_reset(convertor_state_t *handle) {
	handle->from_state = 0;
	if (handle->common.utf_type == UTF32 || handle->common.utf_type == UTF16)
		handle->common.get_unicode = get_get_unicode(handle->common.utf_type);
}

static void save_cct_state(convertor_state_t *handle, save_state_t *save) {
	save->to_state = handle->to_state;
	save->from_state = handle->from_state;
}

static void load_cct_state(convertor_state_t *handle, save_state_t *save) {
	handle->to_state = save->to_state;
	handle->from_state = save->from_state;
}

void *open_cct_convertor(const char *name, int utf_type, int flags, int *error) {
	size_t len = strlen(DB_DIRECTORY) + strlen(name) + 6;
	convertor_state_t *retval;
	convertor_t *ptr;
	char *file_name;

	if ((file_name = malloc(len)) == NULL) {
		if (error != NULL)
			*error = T3_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	strcpy(file_name, DB_DIRECTORY);
	strcat(file_name, "/");
	strcat(file_name, name);
	strcat(file_name, ".cct");

	pthread_mutex_lock(&cct_list_mutex);
	for (ptr = cct_head; ptr != NULL; ptr = ptr->next) {
		if (strcmp(ptr->name, file_name) == 0)
			break;
	}

	if (ptr == NULL) {
		ptr = load_cct_convertor(file_name, error);
		if (ptr == NULL) {
			pthread_mutex_unlock(&cct_list_mutex);
			return NULL;
		}
		ptr->next = cct_head;
		cct_head = ptr;
	}
	free(file_name);

	if ((retval = malloc(sizeof(convertor_state_t))) == NULL) {
		if (ptr->refcount == 0)
			unload_cct_convertor(ptr);
		if (error != NULL)
			*error = T3_ERR_OUT_OF_MEMORY;
		pthread_mutex_unlock(&cct_list_mutex);
		return NULL;
	}
	ptr->refcount++;
	pthread_mutex_unlock(&cct_list_mutex);

	retval->convertor = ptr;
	retval->from_state = 0;
	retval->to_state = 0;

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.get_unicode = get_get_unicode(utf_type);
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.put_unicode = get_put_unicode(utf_type);
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.utf_type = utf_type;
	retval->common.close = (close_func_t) close_cct_convertor;
	retval->common.save = (save_func_t) save_cct_state;
	retval->common.load = (load_func_t) load_cct_state;
	return retval;
}

static void close_cct_convertor(convertor_state_t *handle) {
	pthread_mutex_lock(&cct_list_mutex);
	if (handle->convertor->refcount == 1)
		unload_cct_convertor(handle->convertor);
	else
		handle->convertor->refcount--;
	pthread_mutex_unlock(&cct_list_mutex);
	free(handle);
}

size_t get_cct_saved_state_size(void) {
	return sizeof(save_state_t);
}
