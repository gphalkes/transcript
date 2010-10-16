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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "genconv.h"
#include "ucmparser.h"

#define FROM_FLAG_FALLBACK (1<<0)
#define FROM_FLAG_SUBCHAR1 (1<<1)
#define FROM_FLAG_START_MN (1<<2)
#define FROM_FLAG_CONT_MN (1<<3) // This doesn't need to be saved! Internal use only

#define TO_FLAG_FALLBACK (1<<0)
#define TO_FLAG_PRIVATE_USE (1<<1)
#define TO_FLAG_START_MN (1<<2)
#define TO_FLAG_CONT_MN (1<<3) // This doesn't need to be saved! Internal use only

#define MULTIBYTE_START_STATE_1 (1<<0)

static linked_state_t *head, *tail;
flat_states_t codepage_machine, unicode_machine;
extern FILE *yyin;

ucm_t *new_ucm(void) {
	ucm_t *result;
	int i;

	if ((result = calloc(1, sizeof(ucm_t))) == NULL)
		OOM();

	result->states = NULL;
	result->to_unicode_mappings = NULL;
	for (i = 0; i < LAST_TAG; i++)
		result->tag_values[i] = NULL;

	return result;
}

tag_t string_to_tag(const char *str) {
	if (strcmp(str, "<code_set_name>") == 0)
		return CODE_SET_NAME;
	if (strcmp(str, "<uconv_class>") == 0)
		return UCONV_CLASS;
	if (strcmp(str, "<subchar>") == 0)
		return SUBCHAR;
	if (strcmp(str, "<subchar1>") == 0)
		return SUBCHAR1;
	if (strcmp(str, "<icu:base>") == 0)
		return ICU_BASE;
	return IGNORED;
}

void set_tag_value(ucm_t *ucm, tag_t tag, const char *str) {
	if ((ucm->tag_values[tag] = strdup(str)) == NULL)
		OOM();
}

void new_entry(linked_entry_t entry) {
	linked_entry_t *new_entry, *ptr, *ptr_low, *ptr_high;

	if (entry.low < 0 || entry.low > 255 ||
			entry.high < 0 || entry.high > 255 ||
			entry.next_state < 0 || entry.next_state > 255)
		fatal("%s:%d: Range definition or next state invalid\n", file_name, line_number);

	if ((new_entry = malloc(sizeof(linked_entry_t))) == NULL)
		OOM();

	*new_entry = entry;

	for (ptr_low = tail->entry_head; ptr_low->high < entry.low; ptr_low = ptr_low->next) {}
	for (ptr_high = ptr_low; ptr_high != NULL && ptr_high->high <= entry.high; ptr_high = ptr_high->next) {}

	if (ptr_high == ptr_low) {
		if (ptr_low->low == entry.low) {
			new_entry->next = ptr_low;
			new_entry->previous = ptr_low->previous;
			ptr_low->previous = new_entry;
			ptr_low->low = entry.high + 1;
			if (new_entry->previous == NULL)
				tail->entry_head = new_entry;
			else
				new_entry->previous->next = new_entry;
			return;
		}
		// Split entry
		if ((ptr_high = malloc(sizeof(linked_entry_t))) == NULL)
			OOM();

		*ptr_high = *ptr_low;
		if (ptr_high->next != NULL)
			ptr_high->next->previous = ptr_high;
	} else {
		// Free completely overlapped entries
		while (ptr_low->next != ptr_high) {
			ptr = ptr_low->next;
			ptr_low->next = ptr_low->next->next;
			free(ptr);
		}
		if (ptr_low->low == entry.low) {
			free(new_entry);
			ptr_low->high = entry.high;
			ptr_low->action = entry.action;
			ptr_low->next_state = entry.next_state;
			if (ptr_low->next != NULL)
				ptr_low->next->low = entry.high + 1;
			return;
		}
	}
	ptr_low->next = new_entry;
	if (ptr_high != NULL)
		ptr_high->previous = new_entry;
	else
		tail->entry_tail = new_entry;
	new_entry->next = ptr_high;
	new_entry->previous = ptr_low;
	ptr_low->high = entry.low - 1;
	if (ptr_high != NULL)
		ptr_high->low = entry.high + 1;
}

void new_state(int flags) {
	linked_state_t *new_state;

	if ((new_state = malloc(sizeof(linked_state_t))) == NULL)
		OOM();

	if (head == NULL) {
		head = tail = new_state;
	} else {
		tail->next = new_state;
		tail = new_state;
	}
	new_state->flags = flags;
	if ((new_state->entry_head = malloc(sizeof(linked_entry_t))) == NULL)
		OOM();

	new_state->entry_tail = new_state->entry_head;
	new_state->entry_head->low = 0;
	new_state->entry_head->high = 255;
	new_state->entry_head->next_state = 0;
	new_state->entry_head->action = ACTION_ILLEGAL;
	new_state->entry_head->next = new_state->entry_head->previous = NULL;
}

static bool check_map(ucm_t *ucm, int state, int byte, action_t action, int next_state) {
	int i;
	for (i = 0; i < ucm->states[state].nr_entries; i++) {
		if (!(byte >= ucm->states[state].entries[i].low && byte <= ucm->states[state].entries[i].high))
			continue;
		return ucm->states[state].entries[i].action == action && ucm->states[state].entries[i].next_state == next_state;
	}
	PANIC();
	return false;
}

void process_header_part1(ucm_t *ucm) {
	if (strcmp(ucm->tag_values[UCONV_CLASS], "SBCS") == 0)
		ucm->uconv_class = CLASS_SBCS;
	else if (strcmp(ucm->tag_values[UCONV_CLASS], "DBCS") == 0)
		ucm->uconv_class = CLASS_DBCS;
	else if (strcmp(ucm->tag_values[UCONV_CLASS], "MBCS") == 0)
		ucm->uconv_class = CLASS_MBCS;
	else if (strcmp(ucm->tag_values[UCONV_CLASS], "EBCDIC_STATEFUL") == 0)
		ucm->uconv_class = CLASS_EBCDIC_STATEFUL;
	else
		fatal("%s:%d: <uconv_class> specifies an unknown class\n", file_name, line_number);
}

void process_header_part2(ucm_t *ucm) {
	if (ucm->nr_states > 2 && (ucm->states[1].flags & STATE_INITIAL) &&
			check_map(ucm, 0, 0xe, ACTION_SHIFT, 1) && check_map(ucm, 1, 0xe, ACTION_SHIFT, 1) &&
			check_map(ucm, 0, 0xf, ACTION_SHIFT, 0) && check_map(ucm, 1, 0xf, ACTION_SHIFT, 0))
		ucm->flags |= MULTIBYTE_START_STATE_1;

	if (codepage_machine.nr_states > 0) {
		//FIXME: clean up old state machine
		ucm->nr_states = codepage_machine.nr_states;
		ucm->states = codepage_machine.states;
	}
}

void print_states(ucm_t *ucm) {
	int i, j;

	for (i = 0; i < ucm->nr_states; i++) {
		printf("State %d%s:", i, i == 0 || (ucm->states[i].flags & STATE_INITIAL) ? " [initial]" : "");
		for (j = 0; j < ucm->states[i].nr_entries; j++) {
			printf(" %02x", ucm->states[i].entries[j].low);
			if (ucm->states[i].entries[j].high != ucm->states[i].entries[j].low)
				printf("-%02x", ucm->states[i].entries[j].high);
			printf(":%x", ucm->states[i].entries[j].next_state);
			if (ucm->states[i].entries[j].action != ACTION_VALID)
				printf(".");
			if (ucm->states[i].entries[j].action > ACTION_VALID)
				printf("%c", "##usi"[ucm->states[i].entries[j].action]);

			if (ucm->states[i].entries[j].action <= ACTION_VALID)
				printf(" (%d, %d)", ucm->states[i].entries[j].base, ucm->states[i].entries[j].mul);
		}
		printf("\n");
	}
	printf("Total defined range: %d\n", ucm->range);
}

#define ENTRY(low, high, next_state, action) { low, high, next_state, action, 0, 0, 0 }
static void set_default_states(ucm_t *ucm) {

	if (ucm->uconv_class == 0 || ucm->uconv_class == CLASS_MBCS)
		fatal("No states specified and no implicit states defined through <uconv_class> either\n");

	if (ucm->uconv_class == CLASS_SBCS) {
		static entry_t sbcs_entries_0[1] = {ENTRY(0, 255, 0, ACTION_FINAL)};
		static state_t sbcs_states[1] = {{ STATE_INITIAL, 1, sbcs_entries_0, 0, 0, 0 }};

		ucm->states = sbcs_states;
		ucm->nr_states = 1;
	} else if (ucm->uconv_class == CLASS_DBCS) {
		static entry_t dbcs_entries_0[4] = {ENTRY(0, 0x3f, 3, ACTION_VALID),
				ENTRY(0x40, 0x40, 2, ACTION_VALID),
				ENTRY(0x41, 0xfe, 1, ACTION_VALID),
				ENTRY(0xff, 0xff, 3, ACTION_VALID)};
		static entry_t dbcs_entries_1[3] = {ENTRY(0, 0x40, 0, ACTION_ILLEGAL),
				ENTRY(0x41, 0xfe, 0, ACTION_FINAL),
				ENTRY(0xff, 0xff, 0, ACTION_ILLEGAL)};
		static entry_t dbcs_entries_2[3] = {ENTRY(0, 0x3f, 0, ACTION_ILLEGAL),
				ENTRY(0x40, 0x40, 0, ACTION_FINAL),
				ENTRY(0x41, 0xff, 0, ACTION_ILLEGAL)};
		static entry_t dbcs_entries_3[1] = {ENTRY(0, 255, 0, ACTION_ILLEGAL)};
		static state_t dbcs_states[4] = {{ STATE_INITIAL, 4, dbcs_entries_0, 0, 0, 0 },
				{ 0, 3, dbcs_entries_1, 0, 0, 0 },
				{ 0, 3, dbcs_entries_2, 0, 0, 0 },
				{ 0, 1, dbcs_entries_3, 0, 0, 0 }};

		ucm->states = dbcs_states;
		ucm->nr_states = 4;
	} else if (ucm->uconv_class == CLASS_EBCDIC_STATEFUL) {
		static entry_t ebcdic_stateful_entries_0[4] = {ENTRY(0, 0x0d, 0, ACTION_FINAL),
				ENTRY(0x0e, 0x0e, 1, ACTION_SHIFT),
				ENTRY(0x0f, 0x0f, 0, ACTION_SHIFT),
				ENTRY(0x10, 0xff, 0, ACTION_FINAL)};
		static entry_t ebcdic_stateful_entries_1[7] = {ENTRY(0, 0x0d, 4, ACTION_VALID),
				ENTRY(0x0e, 0x0e, 1, ACTION_SHIFT),
				ENTRY(0x0f, 0x0f, 0, ACTION_SHIFT),
				ENTRY(0x10, 0x3f, 4, ACTION_VALID),
				ENTRY(0x40, 0x40, 3, ACTION_VALID),
				ENTRY(0x41, 0xfe, 2, ACTION_VALID),
				ENTRY(0xff, 0xff, 4, ACTION_VALID)};
		static entry_t ebcdic_stateful_entries_2[3] = {ENTRY(0, 0x40, 1, ACTION_ILLEGAL),
				ENTRY(0x41, 0xfe, 1, ACTION_FINAL),
				ENTRY(0xff, 0xff, 1, ACTION_ILLEGAL)};
		static entry_t ebcdic_stateful_entries_3[3] = {ENTRY(0, 0x3f, 1, ACTION_ILLEGAL),
				ENTRY(0x40, 0x40, 1, ACTION_FINAL),
				ENTRY(0x41, 0xff, 1, ACTION_ILLEGAL)};
		static entry_t ebcdic_stateful_entries_4[1] = {ENTRY(0, 255, 1, ACTION_ILLEGAL)};
		static state_t ebcdic_stateful_states[5] = {{ STATE_INITIAL, 4, ebcdic_stateful_entries_0, 0, 0, 0 },
				{ STATE_INITIAL, 7, ebcdic_stateful_entries_1, 0, 0, 0 },
				{ 0, 3, ebcdic_stateful_entries_2, 0, 0, 0 },
				{ 0, 3, ebcdic_stateful_entries_3, 0, 0, 0 },
				{ 0, 1, ebcdic_stateful_entries_4, 0, 0, 0 }};

		ucm->states = ebcdic_stateful_states;
		ucm->nr_states = 5;
	} else {
		PANIC();
	}
}

void flatten_states(flat_states_t *flat_states) {
	linked_state_t *state_ptr;
	linked_entry_t *entry_ptr;
	int state_count, entry_count;

	if (head == NULL) {
		flat_states->nr_states = 0;
		flat_states->states = NULL;
		return;
	}

	for (state_ptr = head, state_count = 0; state_ptr != NULL; state_ptr = state_ptr->next, state_count++) {}

	if (state_count > 255)
		fatal("Too many states specified\n");

	if ((flat_states->states = malloc(state_count * sizeof(state_t))) == NULL)
		OOM();

	for (state_ptr = head, state_count = 0; state_ptr != NULL; state_ptr = state_ptr->next, state_count++) {
		flat_states->states[state_count].flags = state_ptr->flags;
		for (entry_ptr = state_ptr->entry_head, entry_count = 0; entry_ptr != NULL; entry_ptr = entry_ptr->next, entry_count++) {}

		if ((flat_states->states[state_count].entries = malloc(entry_count * sizeof(entry_t))) == NULL)
			OOM();

		flat_states->states[state_count].nr_entries = entry_count;
		flat_states->states[state_count].complete = false;
		for (entry_ptr = state_ptr->entry_head, entry_count = 0; entry_ptr != NULL; entry_ptr = entry_ptr->next, entry_count++) {
			flat_states->states[state_count].entries[entry_count].low = entry_ptr->low;
			flat_states->states[state_count].entries[entry_count].high = entry_ptr->high;
			flat_states->states[state_count].entries[entry_count].next_state = entry_ptr->next_state;
			flat_states->states[state_count].entries[entry_count].action = entry_ptr->action;
			flat_states->states[state_count].entries[entry_count].mul = 0;
		}
		while (state_ptr->entry_head != NULL) {
			entry_ptr = state_ptr->entry_head;
			state_ptr->entry_head = state_ptr->entry_head->next;
			free(entry_ptr);
		}
	}
	flat_states->states[0].flags |= STATE_INITIAL;

	flat_states->nr_states = state_count;
	while (head != NULL) {
		state_ptr = head;
		head = head->next;
		free(state_ptr);
	}
	head = tail = NULL;
}

void flatten_states_with_default(ucm_t *ucm) {
	if (head == NULL) {
		set_default_states(ucm);
		return;
	}
	flatten_states((flat_states_t *) ucm);
}



void validate_states(flat_states_t *flat_states) {
	int i, j;
	for (i = 0; i < flat_states->nr_states; i++) {
		for (j = 0; j < flat_states->states[i].nr_entries; j++) {
			if (flat_states->states[i].entries[j].action == ACTION_UNASSIGNED &&
					flat_states->states[i].entries[j].action == ACTION_ILLEGAL)
				continue;

			if (flat_states->states[i].entries[j].next_state >= flat_states->nr_states)
				fatal("State %d:%x-%x designates a non-existant state as next state\n", i,
					flat_states->states[i].entries[j].low, flat_states->states[i].entries[j].high);

			if (flat_states->states[i].entries[j].action != ACTION_VALID &&
					!(flat_states->states[flat_states->states[i].entries[j].next_state].flags & STATE_INITIAL))
				fatal("State %d:%x-%x designates a non-initial state as next state for final/unassigned/illegal/shift transition\n",
					i, flat_states->states[i].entries[j].low, flat_states->states[i].entries[j].high);

			if (flat_states->states[i].entries[j].action != ACTION_VALID)
				continue;

			if (flat_states->states[flat_states->states[i].entries[j].next_state].flags & STATE_INITIAL)
				fatal("State %d:%x-%x designates an initial state as next state for non-final transition\n", i,
					flat_states->states[i].entries[j].low, flat_states->states[i].entries[j].high);
		}
	}
}

static void update_state_attributes(ucm_t *ucm, int idx) {
	int i, sum = 0;

	if (ucm->states[idx].complete)
		return;

	for (i = 0; i < ucm->states[idx].nr_entries; i++) {
		switch (ucm->states[idx].entries[i].action) {
			case ACTION_VALID:
				update_state_attributes(ucm, ucm->states[idx].entries[i].next_state);
				ucm->states[idx].entries[i].base = sum;
				ucm->states[idx].entries[i].mul = ucm->states[ucm->states[idx].entries[i].next_state].range;
				sum += (ucm->states[idx].entries[i].high - ucm->states[idx].entries[i].low + 1) *
					ucm->states[idx].entries[i].mul;
				ucm->states[idx].entries[i].max = sum;
				break;
			case ACTION_FINAL_PAIR:
				ucm->states[idx].entries[i].mul = 2;
				goto action_final_shared;
			case ACTION_FINAL:
				ucm->states[idx].entries[i].mul = 1;
			action_final_shared:
				ucm->states[idx].entries[i].base = sum;
				sum += (ucm->states[idx].entries[i].high - ucm->states[idx].entries[i].low + 1) * ucm->states[idx].entries[i].mul;
				ucm->states[idx].entries[i].max = sum;
				break;
			default:
				break;
		}
	}
	ucm->states[idx].range = sum;
	ucm->states[idx].complete = true;
}

void calculate_state_attributes(ucm_t *ucm) {
	int i;
	for (i = 0; i < ucm->nr_states; i++) {
		if (ucm->states[i].flags & STATE_INITIAL) {
			update_state_attributes(ucm, i);
			ucm->states[i].base = ucm->range;
			ucm->range += ucm->states[i].range;
		}
	}
}

void allocate_charmap(ucm_t *ucm) {
	if ((ucm->to_unicode_mappings = malloc(ucm->range * sizeof(uint16_t))) == NULL)
		OOM();
	if ((ucm->to_unicode_flags = malloc(ucm->range)) == NULL)
		OOM();

	memset(ucm->to_unicode_mappings, 0xff, ucm->range * sizeof(uint16_t));
	memset(ucm->to_unicode_flags, 0x00, ucm->range);

	if ((ucm->from_unicode_mappings = malloc(CODEPOINTS_MAX * sizeof(uint32_t))) == NULL)
		OOM();
	if ((ucm->from_unicode_flags = malloc(CODEPOINTS_MAX)) == NULL)
		OOM();

	memset(ucm->from_unicode_mappings, 0xff, CODEPOINTS_MAX * sizeof(uint32_t));
	memset(ucm->from_unicode_flags, 0x00, CODEPOINTS_MAX);
}

static unsigned char charseq_result[32];
unsigned char *parse_charseq(char *charseq, int *result_size) {
	int idx = 0;
	long value;

	for (; *charseq != 0 && idx < 32; idx++) {
		charseq += 2; /* Skip \x */
		value = strtol(charseq, &charseq, 16);
		if (value > 255 || value < 0)
			fatal("%s:%d: byte value out of range\n", file_name, line_number);
		charseq_result[idx] = (unsigned char) value;
		if (*charseq == '+')
			charseq++;
	}
	if (*charseq != 0)
		fatal("%s:%d: character sequence too long\n", file_name, line_number);

	*result_size = idx;
	return charseq_result;
}

bool map_charseq(ucm_t *ucm, char *charseq, uint32_t *mapped, int *mapped_size) {
	uint32_t value;
	int i, j, length, state;
	unsigned char *chars;

	chars = parse_charseq(charseq, &length);

	/* Some stateful converters are treated specially: single byte characters can not
	   be part of a multi-byte sequence && must be defined in state 0. See
	   process_header_part2() to see what conditions a convertor must satisfy for this
	   special treatment.

	   The spec is really deficient in this respect: there is no way to know what initial
	   state a byte-sequence belongs to. Because of this, several hacks were construed to
	   allow the parser to determine this. However, this is not a nice clean general
	   solution, but rather a work-around for certain types of converters (i.e. the EBCDIC
	   stateful converters and similar ones).
	*/
	state = (ucm->flags & MULTIBYTE_START_STATE_1) && length > 1 ? 1 : 0;
	value = ucm->states[state].base;

	*mapped_size = 0;
	for (i = 0; i < length; i++) {
		for (j = 0; j < ucm->states[state].nr_entries; j++) {
			if (!(chars[i] >= ucm->states[state].entries[j].low && chars[i] <= ucm->states[state].entries[j].high))
				continue;

			value += ucm->states[state].entries[j].base + (uint32_t)(chars[i] - ucm->states[state].entries[j].low) *
				ucm->states[state].entries[j].mul;
			switch (ucm->states[state].entries[j].action) {
				case ACTION_ILLEGAL:
				case ACTION_UNASSIGNED:
				case ACTION_SHIFT:
					return false;
				case ACTION_VALID:
					state = ucm->states[state].entries[j].next_state;
					goto next_char;
				case ACTION_FINAL_PAIR:
				case ACTION_FINAL:
					mapped[(*mapped_size)++] = value;
					state = ucm->states[state].entries[j].next_state;
					value = ucm->states[state].base;
					goto next_char;
				default:
					PANIC();
			}
		}
		PANIC();
next_char:;
	}
	return true;
}

static char *linear_to_string(ucm_t *ucm, uint32_t mapped) {
	static char buffer[4 * 32 + 1];
	int buffer_idx = 0;
	int state, i;

	for (state = 0; state < ucm->nr_states; state++) {
		if (!(ucm->states[state].flags & STATE_INITIAL))
			continue;

		if (!(ucm->states[state].base <= (int) mapped && ucm->states[state].base + ucm->states[state].range > (int) mapped))
			continue;
		break;
	}
	mapped -= ucm->states[state].base;

	while (1) {
		for (i = 0; i < ucm->states[state].nr_entries; i++) {
			if (!((int) mapped >= ucm->states[state].entries[i].base && (int) mapped < ucm->states[state].entries[i].max))
				continue;

			mapped -= ucm->states[state].entries[i].base;
			sprintf(buffer + buffer_idx, "\\x%02X", ucm->states[state].entries[i].low + mapped / ucm->states[state].entries[i].mul);
			buffer_idx += 4;
			mapped %= ucm->states[state].entries[i].mul;

			switch (ucm->states[state].entries[i].action) {
				case ACTION_ILLEGAL:
				case ACTION_UNASSIGNED:
				case ACTION_SHIFT:
					return NULL;
				case ACTION_VALID:
					state = ucm->states[state].entries[i].next_state;
					goto next_char;
				case ACTION_FINAL_PAIR:
				case ACTION_FINAL:
					return buffer;
				default:
					PANIC();
			}
		}
		PANIC();
next_char:;
	}
	return NULL;
}

static action_t linear_to_action(ucm_t *ucm, uint32_t mapped) {
	int state, i;

	for (state = 0; state < ucm->nr_states; state++) {
		if (!(ucm->states[state].flags & STATE_INITIAL))
			continue;

		if (!(ucm->states[state].base <= (int) mapped && ucm->states[state].base + ucm->states[state].range > (int) mapped))
			continue;
		break;
	}
	mapped -= ucm->states[state].base;

	while (1) {
		for (i = 0; i < ucm->states[state].nr_entries; i++) {
			if (!((int) mapped >= ucm->states[state].entries[i].base && (int) mapped < ucm->states[state].entries[i].max))
				continue;

			mapped -= ucm->states[state].entries[i].base;
			mapped %= ucm->states[state].entries[i].mul;

			switch (ucm->states[state].entries[i].action) {
				case ACTION_FINAL_PAIR:
				case ACTION_FINAL:
				case ACTION_ILLEGAL:
				case ACTION_UNASSIGNED:
				case ACTION_SHIFT:
					return ucm->states[state].entries[i].action;
				case ACTION_VALID:
					state = ucm->states[state].entries[i].next_state;
					goto next_char;
				default:
					PANIC();
			}
		}
		PANIC();
next_char:;
	}
	/* This should be unreachable. */
	PANIC();
	return -1;
}

static bool is_private_use(uint32_t codepoint) {
	if (codepoint >= UINT32_C(0xE000) && codepoint < UINT32_C(0xF900))
		return true;
	if (codepoint >= UINT32_C(0xF0000) && codepoint <= UINT32_C(0xFFFFD))
		return true;
	if (codepoint >= UINT32_C(0x100000) && codepoint <= UINT32_C(0x10FFFD))
		return true;
	return false;
}

void add_mapping(ucm_t *ucm, uint32_t *codepoints, int codepoints_size, uint32_t *mapped, int mapped_size, int precision) {
	if (codepoints_size > 1 || mapped_size > 1) {
		int i;
		ucm->to_unicode_flags[*mapped] |= TO_FLAG_START_MN;
		for (i = 1; i < mapped_size; i++)
			ucm->to_unicode_flags[mapped[i]] |= TO_FLAG_CONT_MN;

		ucm->from_unicode_flags[*codepoints] |= FROM_FLAG_START_MN;
		for (i = 1; i < mapped_size; i++)
			ucm->from_unicode_flags[codepoints[i]] |= FROM_FLAG_CONT_MN;
		//FIXME: save in list
		return;
	}

	if (*mapped >= (uint32_t) ucm->range)
		PANIC();

	//FIXME: put mappings from the second CHARMAP into a separate mapping
	//FIXME: handle m:n mappings
	//FIXME: check that mapped sequence == subchar1
	if (precision == 2) {
		ucm->from_unicode_flags[*codepoints] |= FROM_FLAG_SUBCHAR1;
		return;
	}

	if (precision == 0 || precision == 1) {
		if (ucm->from_unicode_mappings[*codepoints] != UINT32_C(0xffffffff))
			fatal("%s:%d: Duplicate mapping defined for U%04" PRIX32 "\n", file_name, line_number - 1, *codepoints);
		ucm->from_unicode_mappings[*codepoints] = *mapped;
		if (precision)
			ucm->from_unicode_flags[*codepoints] |= FROM_FLAG_FALLBACK;
	}

	if (precision == 0 || precision == 3) {
		if (ucm->to_unicode_mappings[*mapped] != UINT16_C(0xffff))
			fatal("%s:%d: Duplicate mapping defined for %s (linear: %" PRId32 ", previous: %04" PRIX32 ")\n", file_name, line_number - 1,
				linear_to_string(ucm, *mapped), *mapped, ucm->to_unicode_mappings[*mapped]);
		if (*codepoints > UINT32_C(0xffff)) {
			if (linear_to_action(ucm, *mapped) != ACTION_FINAL_PAIR)
				fatal("%s:%d: Mapping with codepoint above U+FFFF but not in a .p range\n", file_name, line_number);
			ucm->to_unicode_mappings[*mapped] = (((*codepoints) - 0x10000) >> 10) + 0xD800;
			ucm->to_unicode_mappings[1 + *mapped] = (((*codepoints) - 0x10000) & 0x3ff) + 0xD800;
		} else {
			ucm->to_unicode_mappings[*mapped] = *codepoints;
		}
		if (precision)
			ucm->to_unicode_flags[*mapped] |= TO_FLAG_FALLBACK;
		if (is_private_use(*codepoints))
			ucm->to_unicode_flags[*mapped] |= TO_FLAG_PRIVATE_USE;
	}
}

static int byte_to_entry_from_state(ucm_t *ucm, int byte, int state) {
	int i;
	for (i = 0; i < ucm->states[state].nr_entries; i++) {
		if (byte >= ucm->states[state].entries[i].low && byte <= ucm->states[state].entries[i].high)
			return i;
	}
	PANIC();
	return 0;
}

static void print_dbcs(ucm_t *ucm) {
	int i, j, assigned, state, entry;
	int linear, linear_base;

	if (!(ucm->flags & MULTIBYTE_START_STATE_1))
		fprintf(stderr, "Cannot print character set representation\n");

	for (i = 0; i < 255; i++) {
		entry = byte_to_entry_from_state(ucm, i, 1);
		/* Skip single byte and unassigned/invalid entries */
		if (ucm->states[1].entries[entry].action != ACTION_VALID)
			continue;

		linear_base = ucm->states[1].base + ucm->states[1].entries[entry].base +
			(i - ucm->states[1].entries[entry].low) * ucm->states[1].entries[entry].mul;
		state = ucm->states[1].entries[entry].next_state;
		assigned = 0;

		for (j = 0, entry = 0; j < 256; j++) {
			if (ucm->states[state].entries[entry].high < j)
				entry++;
			if (ucm->states[state].entries[entry].action <= ACTION_FINAL_PAIR) {
				linear = linear_base + ucm->states[state].entries[entry].base +
					(j - ucm->states[state].entries[entry].low) * ucm->states[state].entries[entry].mul;
				//~ printf("\\x%02X\\x%02X %s\n", i, j, linear_to_string(ucm, linear));
				if (ucm->to_unicode_mappings[linear] != UINT16_C(0xffff))
					assigned++;
			}
		}
		printf("%03d %02X ", assigned, i);

		for (j = 0, entry = 0; j < 256; j++) {
			if (ucm->states[state].entries[entry].high < j)
				entry++;
			switch (ucm->states[state].entries[entry].action) {
				case ACTION_FINAL:
				case ACTION_FINAL_PAIR:
					linear = linear_base + ucm->states[state].entries[entry].base +
						(j - ucm->states[state].entries[entry].low) * ucm->states[state].entries[entry].mul;
					if (ucm->to_unicode_mappings[linear] >= UINT16_C(0xd800) && ucm->to_unicode_mappings[linear] < 0xd900)
						putchar('*');
					else if (ucm->to_unicode_mappings[linear] != UINT16_C(0xffff))
						putchar('+');
					else
						putchar('.');
					break;
				case ACTION_ILLEGAL:
					putchar('X');
					break;
				case ACTION_UNASSIGNED:
					putchar('u');
					break;
				case ACTION_VALID:
					putchar('v');
					break;
				default:
					PANIC();
			}
		}
		putchar('\n');
	}
}

static void print_unicode_blocks(ucm_t *ucm) {
	int i, j, assigned;
	putchar('\n');
	for (i = 0; i < CODEPOINTS_MAX; i += 128) {
		assigned = 0;
		for (j = 0; j < 128; j++) {
			if (ucm->from_unicode_mappings[i + j] != UINT32_C(0xffffffff))
				assigned++;
		}

		if (assigned == 0)
			continue;

		printf("%02X/%02X: ", (i >> 14) & 0x7f, (i >> 7) & 0x7f);
		for (j = 0; j < 128; j++) {
			if (ucm->from_unicode_mappings[i + j] == UINT32_C(0xffffffff))
				putchar('.');
			//FIXME: print * for long outputs (>2 bytes)
			else
				putchar('+');
		}
		putchar('\n');
	}
}

static int get_depth(ucm_t *ucm, int state) {
	int i, result = 0, tmp;


	for (i = 0; i < ucm->states[state].nr_entries; i++) {
		if (ucm->states[state].entries[i].action == ACTION_VALID) {
			tmp = get_depth(ucm, ucm->states[state].entries[i].next_state);
			if (tmp > result)
				result = tmp;
		}
	}
	return result + 1;
}

static void calculate_max_bytes(ucm_t *ucm) {
	int i, tmp;

	for (i = 0; i < ucm->nr_states; i++) {
		if (!(ucm->states[i].flags & STATE_INITIAL))
			continue;

		tmp = get_depth(ucm, i);
		if (tmp > ucm->max_bytes)
			ucm->max_bytes = tmp;
	}
}

int main(int argc, char *argv[]) {
	const char *state_machine_file = NULL;
	bool opt_print_dbcs = false;
	ucm_t *file, *base;
	table_info_t info;
	int c;

	while ((c = getopt(argc, argv, "s:p")) != -1) {
		switch (c) {
			case 's':
				state_machine_file = optarg;
				break;
			case 'p':
				opt_print_dbcs = true;
				break;
			default:
				fatal("Error in option parsing\n");
		}
	}


	if (argc - optind != 1)
		fatal("Usage: genconv [-s <state machine file>] [-p] <ucm file>\n");

	if (state_machine_file != NULL) {
		if ((yyin = fopen(state_machine_file, "r")) == NULL)
			fatal("Could not open '%s': %s\n", argv[optind], strerror(errno));
		file_name = argv[optind];

		parse_states_file();
		fclose(yyin);
		line_number = 1;
	}

	if ((yyin = fopen(argv[optind], "r")) == NULL)
		fatal("Could not open '%s': %s\n", argv[optind], strerror(errno));
	file_name = argv[optind];

	parse_ucm((void **) &file);
	calculate_max_bytes(file);

	{
		int i;
		int count = 0;
		for (i = 0; i < file->range; i++)
			if (file->to_unicode_mappings[i] != UINT16_C(0xffff))
				count++;
		printf("Range: %d, used: %d\n", file->range, count);
	}
//	if (file->max_bytes <= 2)
	if (state_machine_file == NULL)
		minimize_state_machine(file);

	if (opt_print_dbcs) {
		print_dbcs(file);
		print_unicode_blocks(file);
		exit(0);
	}

	fclose(yyin);


#if 0
	if (file->tag_values[ICU_BASE] != NULL) {
		char *name, *slash;
		size_t name_length;

		name_length = strlen(file->tag_values[ICU_BASE]);
		if ((slash = strrchr(argv[optind], DIR_SEP)) != NULL) {
			name_length += strlen(argv[optind]);
			name_length -= strlen(slash + 1);
		}
		name_length += 1 + 4;
		if ((name = calloc(1, name_length)) == NULL)
			OOM();
		if (slash != NULL)
			strncpy(name, argv[optind], slash - argv[optind] + 1);
		strcat(name, file->tag_values[ICU_BASE]);
		strcat(name, ".ucm");

		if ((yyin = fopen(name, "r")) == NULL)
			fatal("Could not open base file '%s': %s\n", name, strerror(errno));

		file_name = name;
		line_number = 1;
		parse_ucm((void **) &base);
		fclose(yyin);
		free(name);
	}
#endif
#if 0
	{
		int i;
		uint8_t *data = (uint8_t *) file->from_unicode_mappings;
		data_fmt_t data_fmt = DATAFMT_INT32;
		if (file->range <= 256)
			data_fmt = DATAFMT_BYTE;
		else if (file->range <= 65536)
			data_fmt = DATAFMT_INT16;

		printf("range: %d\n", file->range);
		info = calculate_compressed_table((uint8_t *) file->from_unicode_mappings, data_fmt, DATAFMT_INT32, CODEPOINTS_MAX, 2);
		printf("Best size: %d\n", info.size);
		for (i = 2; i >= 0; i--)
			printf("  Bits: %d\n", info.bits[i]);

		data_fmt = DATAFMT_INT16;
		printf("data_fmt: %d\n", data_size[data_fmt]);
		info = calculate_compressed_table((uint8_t *) file->to_unicode_mappings, data_fmt, DATAFMT_INT16, file->range, 2);
		if (info.size > file->range * data_size[data_fmt]) {
			printf("Best size: %d (flat table)\n", file->range * data_size[data_fmt]);
		} else {
			printf("Best size: %d\n", info.size);
			for (i = 2; i >= 0; i--)
				printf("  Bits: %d\n", info.bits[i]);
		}
	}
#endif
	return EXIT_SUCCESS;
}

