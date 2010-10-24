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
	uint8_t map[256];
	entry_t *entries;
} state_t;

typedef struct {
	shift_state_t *shift_states;
	state_t *codepage_states;
	entry_t *codepage_entries;
	state_t *unicode_states;
	entry_t *unicode_entries;
	uint16_t *codepage_mappings;
	uint8_t *unicode_mappings;
	//FIXME: flag tries

	uint16_t nr_codepage_entries;
	uint16_t nr_unicode_entries;

	uint8_t flags;
	uint8_t subchar_len;
	uint8_t subchar[MAX_CHAR_BYTES];
	uint8_t subchar1;
	uint8_t nr_shift_states;
	uint8_t nr_codepage_states;
	uint8_t nr_unicode_states;
	uint8_t default_from_unicode_flags;
	uint8_t default_to_unicode_flags;
	uint8_t single_size;
} convertor_t;

typedef struct {
	convertor_t *convertor;
	//FIXME: add state
} convertor_state_t;

static t3_bool read_states(FILE *file, int nr, state_t *states, entry_t *entries, uint16_t max_entries, int *error);

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)
#define READ(count, buf) do { if (fread(buf, 1, count, file) != (size_t) count) ERROR(T3_ERR_READ_ERROR); } while (0)
#define READ_BYTE(store) do { uint8_t value; if (fread(&value, 1, 1, file) != (size_t) 1) ERROR(T3_ERR_READ_ERROR); store = value; } while (0)
#define READ_WORD(store) do { uint16_t value; if (fread(&value, 1, 2, file) != (size_t) 2) ERROR(T3_ERR_READ_ERROR); store = ntohs(value); } while (0)
#define READ_DWORD(store) do { uint32_t value; if (fread(&value, 1, 4, file) != (size_t) 4) ERROR(T3_ERR_READ_ERROR); store = ntohl(value); } while (0)

void *_t3_load_convertor(const char *file_name, int *error) {
	convertor_t *convertor = NULL;
	FILE *file;
	char magic[4];
	uint32_t version;
	uint8_t i;

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
	convertor->unicode_states = NULL;
	convertor->unicode_entries = NULL;
	convertor->unicode_mappings = NULL;

	READ_BYTE(convertor->flags);
	READ_BYTE(convertor->subchar_len);
	READ(4, convertor->subchar);
	READ_BYTE(convertor->subchar1);
	READ_BYTE(convertor->nr_shift_states);
	READ_BYTE(convertor->nr_codepage_states);
	READ_WORD(convertor->nr_codepage_entries);
	READ_BYTE(convertor->nr_unicode_states);
	READ_WORD(convertor->nr_unicode_entries);
	READ_BYTE(convertor->default_from_unicode_flags);
	READ_BYTE(convertor->default_to_unicode_flags);

	if ((convertor->shift_states = calloc(convertor->nr_shift_states, sizeof(shift_state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->codepage_states = malloc(convertor->nr_codepage_states * sizeof(state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->codepage_entries = malloc(convertor->nr_codepage_entries * sizeof(entry_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_states = malloc(convertor->nr_unicode_states * sizeof(state_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);
	if ((convertor->unicode_entries = malloc(convertor->nr_unicode_entries * sizeof(entry_t))) == NULL)
		ERROR(T3_ERR_OUT_OF_MEMORY);

	for (i = 0; i < convertor->nr_shift_states; i++) {
		READ_BYTE(convertor->shift_states[i].from_state);
		READ_BYTE(convertor->shift_states[i].to_state);
		READ_BYTE(convertor->shift_states[i].len);
		READ(4, convertor->shift_states[i].bytes);
	}

	read_states(file, convertor->nr_codepage_states, convertor->codepage_states, convertor->codepage_entries,
		convertor->nr_codepage_entries, error);
	read_states(file, convertor->nr_unicode_states, convertor->unicode_states, convertor->unicode_entries,
		convertor->nr_unicode_entries, error);

	//FIXME: validate and annotate state machines
	//FIXME: read mappings
	//FIXME: read flag tries
	return convertor;

end_error:
	if (convertor == NULL)
		return error;
	free(convertor->shift_states);
	free(convertor->codepage_states);
	free(convertor->codepage_entries);
	free(convertor->codepage_mappings);
	free(convertor->unicode_states);
	free(convertor->unicode_entries);
	free(convertor->unicode_mappings);
	free(convertor);
	return NULL;
}

static t3_bool read_states(FILE *file, int nr, state_t *states, entry_t *entries, uint16_t max_entries, int *error) {
	uint8_t nr_entries, i, j;
	uint16_t entries_idx = 0;

	for (i = 0; i < nr; i++) {
		READ_BYTE(nr_entries);
		states[i].entries = entries + entries_idx;
		for (j = 0; j < nr_entries && entries_idx < max_entries; j++) {
			READ_BYTE(entries[entries_idx].low);
			READ_BYTE(entries[entries_idx].next_state);
			READ_BYTE(entries[entries_idx].action);
			if (j > 0)
				memset(states[i].map + entries[entries_idx - 1].low, j - 1, entries[entries_idx].low - entries[entries_idx - 1].low);
			entries_idx++;
		}
		memset(states[i].map + entries[entries_idx - 1].low, j - 1, 256 - entries[entries_idx - 1].low);
		if (j < nr_entries)
			ERROR(T3_ERR_INVALID_FORMAT);
	}
	if (entries_idx != max_entries)
		ERROR(T3_ERR_INVALID_FORMAT);

	return t3_true;
end_error:
	return t3_false;
}
