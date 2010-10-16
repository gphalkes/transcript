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
#ifndef GENCONV_H
#define GENCONV_H

#include <inttypes.h>
#include "common.h"

typedef enum { false, true } bool;

typedef enum {
	ACTION_FINAL,
	ACTION_FINAL_PAIR,
	ACTION_VALID,
	ACTION_UNASSIGNED,
	ACTION_SHIFT,
	ACTION_ILLEGAL
} action_t;

//FIXME: use uint8_t and uint32_t as types, rather than int

typedef struct linked_entry_t {
	int low, high;
	int next_state;
	action_t action;
	struct linked_entry_t *next, *previous;
} linked_entry_t;


typedef struct linked_state_t {
	int flags;
	linked_entry_t *entry_head, *entry_tail;
	struct linked_state_t *next;
} linked_state_t;

typedef struct {
	int low, high;
	int next_state;
	action_t action;
	int base;
	int mul;
	int max;
} entry_t;

typedef struct {
	int flags;
	int nr_entries;
	entry_t *entries;
	int base, range;
	bool complete;
} state_t;

typedef struct {
	state_t *states;
	int nr_states;
} flat_states_t;

typedef enum {
	IGNORED = -1,
	CODE_SET_NAME,
	UCONV_CLASS,
	SUBCHAR,
	SUBCHAR1,
	ICU_BASE,

	/* All tags must be defined before this value. */
	LAST_TAG
} tag_t;

enum {
	CLASS_MBCS = 1,
	CLASS_SBCS,
	CLASS_DBCS,
	CLASS_EBCDIC_STATEFUL
};

typedef struct ucm {
	/* First two entries must be the same as flat_states_t!! */
	state_t *states;
	int nr_states;

	int range;
	uint16_t *to_unicode_mappings;
	uint8_t *to_unicode_flags;
	uint32_t *from_unicode_mappings;
	uint8_t *from_unicode_flags;
	char *tag_values[LAST_TAG];
	int uconv_class;
	int flags;

	int max_bytes;
} ucm_t;

#define STATE_INITIAL (1<<0)
#define INVALID_SEQUENCE 0xffffffff
#define SKIP_SEQUENCE 0xfffffffe
#define DIR_SEP '/'

extern int line_number;
extern char *file_name;

ucm_t *new_ucm(void);
tag_t string_to_tag(const char *str);
void set_tag_value(ucm_t *ucm, tag_t tag, const char *str);
void new_entry(linked_entry_t entry);
void new_state(int flags);
void process_header_part1(ucm_t *ucm);
void process_header_part2(ucm_t *ucm);
void print_states(ucm_t *ucm);
void flatten_states(flat_states_t *ucm);
void flatten_states_with_default(ucm_t *ucm);
void validate_states(flat_states_t *flat_states);
void calculate_state_attributes(ucm_t *ucm);
void allocate_charmap(ucm_t *ucm);
bool map_charseq(ucm_t *ucm, char *charseq, uint32_t *mapped, int *mapped_size);
void add_mapping(ucm_t *ucm, uint32_t *codepoints, int codepoints_size, uint32_t *mapped, int mapped_size, int precision);

extern flat_states_t codepage_machine, unicode_machine;


void minimize_state_machine(ucm_t *ucm);
#endif
