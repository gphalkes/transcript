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
#include <cstring>
#include <cstdio>
#include <algorithm>
#include "ucm2cct.h"

State::State(void) : flags(0), base(0), range(0), complete(false) {
	entries.push_back(Entry(0, 255, 0, ACTION_ILLEGAL, 0, 0, 0));
}

void State::new_entry(Entry entry) {
	vector<Entry>::iterator ptr_low, ptr_high;

	if (entry.low < 0 || entry.low > 255 ||
			entry.high < 0 || entry.high > 255 ||
			entry.next_state < 0 || entry.next_state > 255)
		PANIC();

	for (ptr_low = entries.begin(); ptr_low->high < entry.low; ptr_low++) {};
	for (ptr_high = ptr_low; ptr_high != entries.end() && ptr_high->high <= entry.high; ptr_high++) {}

	if (ptr_high == ptr_low) {
		if (ptr_low->low == entry.low) {
			ptr_low->low = entry.high + 1;
			entries.insert(ptr_low, entry);
		} else {
			// Split entry
			Entry insert[2] = { entry, *ptr_low };
			insert[2].low = entry.high + 1;
			ptr_low->high = entry.low - 1;
			entries.insert(ptr_low, insert, insert + 2);
		}
	} else {
		if (ptr_low->low == entry.low) {
			*ptr_low = entry;
			if (ptr_high != entries.end())
				ptr_high->low = entry.high + 1;
			entries.erase(ptr_low + 1, ptr_high);
		} else {
			*(ptr_low + 1) = entry;
			ptr_low->high = entry.low - 1;
			if (ptr_high != entries.end())
				ptr_high->low = entry.high + 1;
			entries.erase(ptr_low + 2, ptr_high);
		}
	}
}


Ucm::Ucm(void) {
	for (int i = 0; i < LAST_TAG; i++)
		tag_values[i] = NULL;
}

void Ucm::set_tag_value(tag_t tag, const char *value) {
	if (tag == IGNORED)
		return;
	if ((tag_values[tag] = strdup(value)) == NULL)
		OOM();
}

void Ucm::new_codepage_state(int _flags) {
	codepage_states.resize(codepage_states.size() + 1);
	codepage_states.back().flags = _flags;
	if (codepage_states.size() == 1)
		codepage_states.back().flags |= State::INITIAL;
}

void Ucm::new_codepage_entry(Entry entry) {
	if (entry.low < 0 || entry.low > 255 ||
			entry.high < 0 || entry.high > 255 ||
			entry.next_state < 0 || entry.next_state > 255)
		fatal("%s:%d: Range definition or next state invalid\n", file_name, line_number);

	codepage_states.back().new_entry(entry);
}

bool Ucm::check_map(int state, int byte, action_t action, int next_state) {
	size_t i;
	for (i = 0; i < codepage_states[state].entries.size(); i++) {
		if (!(byte >= codepage_states[state].entries[i].low && byte <= codepage_states[state].entries[i].high))
			continue;
		return codepage_states[state].entries[i].action == action && codepage_states[state].entries[i].next_state == next_state;
	}
	PANIC();
	return false;
}

void Ucm::process_header(void) {
	if (strcmp(tag_values[UCONV_CLASS], "SBCS") == 0)
		uconv_class = CLASS_SBCS;
	else if (strcmp(tag_values[UCONV_CLASS], "DBCS") == 0)
		uconv_class = CLASS_DBCS;
	else if (strcmp(tag_values[UCONV_CLASS], "MBCS") == 0)
		uconv_class = CLASS_MBCS;
	else if (strcmp(tag_values[UCONV_CLASS], "EBCDIC_STATEFUL") == 0)
		uconv_class = CLASS_EBCDIC_STATEFUL;
	else
		fatal("%s:%d: <uconv_class> specifies an unknown class\n", file_name, line_number);

	if (codepage_states.size() == 0)
		set_default_codepage_states();

	if (codepage_states.size() > 2 && (codepage_states[1].flags & State::INITIAL) &&
			check_map(0, 0xe, ACTION_SHIFT, 1) && check_map(1, 0xe, ACTION_SHIFT, 1) &&
			check_map(0, 0xf, ACTION_SHIFT, 0) && check_map(1, 0xf, ACTION_SHIFT, 0))
		flags |= MULTIBYTE_START_STATE_1;
}

void Ucm::set_default_codepage_states(void) {
#define ENTRY(low, high, next_state, action) Entry(low, high, next_state, action, 0, 0, 0)
	if (uconv_class == 0 || uconv_class == CLASS_MBCS)
		fatal("No states specified and no implicit states defined through <uconv_class> either\n");

	if (uconv_class == CLASS_SBCS) {
		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0, 255, 0, ACTION_FINAL));
	} else if (uconv_class == CLASS_DBCS) {
		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0, 0x3f, 3, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0x40, 0x40, 2, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0x41, 0xfe, 1, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0xff, 0xff, 3, ACTION_VALID));

		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0x41, 0xfe, 0, ACTION_FINAL));

		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0x40, 0x40, 0, ACTION_FINAL));

		new_codepage_state();
		// All illegal state
	} else if (uconv_class == CLASS_EBCDIC_STATEFUL) {
		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0, 0x0d, 0, ACTION_FINAL));
		codepage_states.back().new_entry(ENTRY(0x0e, 0x0e, 1, ACTION_SHIFT));
		codepage_states.back().new_entry(ENTRY(0x0f, 0x0f, 0, ACTION_SHIFT));
		codepage_states.back().new_entry(ENTRY(0x10, 0xff, 0, ACTION_FINAL));
		new_codepage_state(State::INITIAL);

		codepage_states.back().new_entry(ENTRY(0, 0x0d, 4, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0x0e, 0x0e, 1, ACTION_SHIFT));
		codepage_states.back().new_entry(ENTRY(0x0f, 0x0f, 0, ACTION_SHIFT));
		codepage_states.back().new_entry(ENTRY(0x10, 0x3f, 4, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0x40, 0x40, 3, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0x41, 0xfe, 2, ACTION_VALID));
		codepage_states.back().new_entry(ENTRY(0xff, 0xff, 4, ACTION_VALID));

		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0x41, 0xfe, 1, ACTION_FINAL));

		new_codepage_state();
		codepage_states.back().new_entry(ENTRY(0x40, 0x40, 1, ACTION_FINAL));

		new_codepage_state();
		// All illegal state
	} else {
		PANIC();
	}
#undef ENTRY
}

void Ucm::validate_states(void) {
	size_t i, j;
	for (i = 0; i < codepage_states.size(); i++) {
		for (j = 0; j < codepage_states[i].entries.size(); j++) {
			if (codepage_states[i].entries[j].action == ACTION_UNASSIGNED &&
					codepage_states[i].entries[j].action == ACTION_ILLEGAL)
				continue;

			if (codepage_states[i].entries[j].next_state >= (int) codepage_states.size())
				fatal("State %zd:%x-%x designates a non-existant state as next state\n", i,
					codepage_states[i].entries[j].low, codepage_states[i].entries[j].high);

			if (codepage_states[i].entries[j].action != ACTION_VALID &&
					!(codepage_states[codepage_states[i].entries[j].next_state].flags & State::INITIAL))
				fatal("State %zd:%x-%x designates a non-initial state as next state for final/unassigned/illegal/shift transition\n",
					i, codepage_states[i].entries[j].low, codepage_states[i].entries[j].high);

			if (codepage_states[i].entries[j].action != ACTION_VALID)
				continue;

			if (codepage_states[codepage_states[i].entries[j].next_state].flags & State::INITIAL)
				fatal("State %d:%x-%x designates an initial state as next state for non-final transition\n", i,
					codepage_states[i].entries[j].low, codepage_states[i].entries[j].high);
		}
	}
}


int Ucm::check_codepage_bytes(vector<uint8_t> &bytes) {
	int state, count = 0;
	size_t i, j;

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
	state = (flags & MULTIBYTE_START_STATE_1) && bytes.size() > 1 ? 1 : 0;

	for (i = 0; i < bytes.size(); i++) {
		for (j = 0; j < codepage_states[state].entries.size(); j++) {
			if (!(bytes[i] >= codepage_states[state].entries[j].low && bytes[i] <= codepage_states[state].entries[j].high))
				continue;

			switch (codepage_states[state].entries[j].action) {
				case ACTION_ILLEGAL:
					fatal("%s:%d: Illegal sequence\n", file_name, line_number);
				case ACTION_UNASSIGNED:
					fatal("%s:%d: Unassigned sequence\n", file_name, line_number);
				case ACTION_SHIFT:
					fatal("%s:%d: Shift in sequence\n", file_name, line_number);
				case ACTION_VALID:
					state = codepage_states[state].entries[j].next_state;
					goto next_char;
				case ACTION_FINAL_PAIR:
				case ACTION_FINAL:
					state = codepage_states[state].entries[j].next_state;
					count++;
					goto next_char;
				default:
					PANIC();
			}
		}
		PANIC();
next_char:;
	}
	return count;
}

static int compareCodepageBytesSimple(Mapping *a, Mapping *b) {
	size_t i;

	for (i = 0; i < a->codepage_bytes.size() && i < b->codepage_bytes.size(); i++) {
		if (a->codepage_bytes[i] < b->codepage_bytes[i])
			return -1;
		if (a->codepage_bytes[i] > b->codepage_bytes[i])
			return 1;
	}

	if (a->codepage_bytes.size() < b->codepage_bytes.size())
		return -1;
	else if (a->codepage_bytes.size() > b->codepage_bytes.size())
		return 1;
	return 0;
}

static const int reorder_precision[4] = {0, 2, 3, 1};
static bool compareCodepageBytes(Mapping *a, Mapping *b) {
	int result = compareCodepageBytesSimple(a, b);

	if (result == 0)
		return reorder_precision[a->precision] < reorder_precision[b->precision];
	return result < 0;
}

static int compareCodepointsSimple(Mapping *a, Mapping *b) {
	size_t i;

	for (i = 0; i < a->codepoints.size() && i < b->codepoints.size(); i++) {
		if (a->codepoints[i] < b->codepoints[i])
			return -1;
		if (a->codepoints[i] > b->codepoints[i])
			return 1;
	}

	if (a->codepoints.size() < b->codepoints.size())
		return -1;
	else if (a->codepoints.size() > b->codepoints.size())
		return 1;
	return 0;
}

static bool compareCodepoints(Mapping *a, Mapping *b) {
	int result = compareCodepointsSimple(a, b);

	if (result == 0)
		return a->precision < b->precision;
	return result < 0;
}

void Ucm::add_mapping(Mapping *mapping) {
	int codepage_chars = check_codepage_bytes(mapping->codepage_bytes);

	if (codepage_chars == 1 && mapping->codepoints.size() == 1)
		simple_mappings.push_back(mapping);
	else
		multi_mappings.push_back(mapping);
}

void Ucm::check_duplicates(vector<Mapping *> &mappings) {
	vector<Mapping *>::iterator iter;
	if (mappings.size() != 0) {
		sort(mappings.begin(), mappings.end(), compareCodepoints);
		for (iter = mappings.begin() + 1; iter != mappings.end(); iter++) {
			if (compareCodepointsSimple(*iter, *(iter - 1)) == 0) {
				if ((*iter)->precision > 1 || (*(iter - 1))->precision > 1)
					continue;
				fprintf(stderr, "Duplicate mapping defined for ");
				for (vector<uint32_t>::iterator codepoint_iter = (*iter)->codepoints.begin();
						codepoint_iter != (*iter)->codepoints.end(); codepoint_iter++)
					fprintf(stderr,  "<U%04" PRIX32 ">", *codepoint_iter);
				fatal("\n");
			}
		}

		sort(mappings.begin(), mappings.end(), compareCodepageBytes);
		for (iter = mappings.begin() + 1; iter != mappings.end(); iter++) {
			if (compareCodepageBytesSimple(*iter, *(iter - 1)) == 0) {
				if (reorder_precision[(*iter)->precision] > 1 || reorder_precision[(*(iter - 1))->precision] > 1)
					continue;
				fprintf(stderr, "Duplicate mapping defined for ");
				for (vector<uint8_t>::iterator codepage_byte_iter = (*iter)->codepage_bytes.begin();
						codepage_byte_iter != (*iter)->codepage_bytes.end(); codepage_byte_iter++)
					fprintf(stderr,  "\\x%02" PRIX32, *codepage_byte_iter);
				fatal("\n");
			}
		}
	}
}

void Ucm::check_duplicates(void) {
	if (option_verbose)
		fprintf(stderr, "Checking for duplicate mappings\n");
	check_duplicates(simple_mappings);
	check_duplicates(multi_mappings);
}
