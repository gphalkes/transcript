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
#include <arpa/inet.h>
#include <limits.h>
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
			insert[1].low = entry.high + 1;
			ptr_low->high = entry.low - 1;
			entries.insert(ptr_low + 1, insert, insert + 2);
		}
	} else {
		if (ptr_low->low == entry.low) {
			*ptr_low = entry;
			if (ptr_high != entries.end())
				ptr_high->low = entry.high + 1;
			entries.erase(ptr_low + 1, ptr_high);
		} else if (ptr_low + 1 == ptr_high) {
			ptr_low->high = entry.low - 1;
			ptr_high->low = entry.high + 1;
			entries.insert(ptr_high, entry);
		} else {
			*(ptr_low + 1) = entry;
			ptr_low->high = entry.low - 1;
			if (ptr_high != entries.end())
				ptr_high->low = entry.high + 1;
			if (ptr_low + 1 != entries.end() && ptr_low + 2 != entries.end())
				entries.erase(ptr_low + 2, ptr_high);
		}
	}
}


Ucm::Ucm(void) : flags(0), from_unicode_flags(0), to_unicode_flags(0), from_unicode_flags_save(0), to_unicode_flags_save(0) {
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
	codepage_states.push_back(new State());
	codepage_states.back()->flags = _flags;
	if (codepage_states.size() == 1)
		codepage_states.back()->flags |= State::INITIAL;
}

void Ucm::new_codepage_entry(Entry entry) {
	if (entry.low < 0 || entry.low > 255 ||
			entry.high < 0 || entry.high > 255 ||
			entry.next_state < 0 || entry.next_state > 255)
		fatal("%s:%d: Range definition or next state invalid\n", file_name, line_number);

	codepage_states.back()->new_entry(entry);
}

bool Ucm::check_map(int state, int byte, action_t action, int next_state) {
	size_t i;
	for (i = 0; i < codepage_states[state]->entries.size(); i++) {
		if (!(byte >= codepage_states[state]->entries[i].low && byte <= codepage_states[state]->entries[i].high))
			continue;
		return codepage_states[state]->entries[i].action == action && codepage_states[state]->entries[i].next_state == next_state;
	}
	PANIC();
	return false;
}

#define ENTRY(low, high, next_state, action) Entry(low, high, next_state, action, 0, 0, 0)
void Ucm::process_header(void) {
	if (tag_values[UCONV_CLASS] == NULL)
		fatal("<uconv_class> unspecified\n");

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

	if (tag_values[MB_MAX] == NULL)
		fatal("<mb_cur_max> unspecified\n");
	if (tag_values[MB_MIN] == NULL)
		fatal("<mb_cur_min> unspecified\n");
	if (tag_values[SUBCHAR] == NULL)
		fatal("<subchar> unspecified\n");

	if (tag_values[SUBCHAR1] != NULL)
		flags |= SUBCHAR1_VALID;

	if (codepage_states.size() == 0)
		set_default_codepage_states();

	if (codepage_states.size() > 2 && (codepage_states[1]->flags & State::INITIAL) &&
			check_map(0, 0xe, ACTION_SHIFT, 1) && check_map(1, 0xe, ACTION_SHIFT, 1) &&
			check_map(0, 0xf, ACTION_SHIFT, 0) && check_map(1, 0xf, ACTION_SHIFT, 0))
		flags |= MULTIBYTE_START_STATE_1;

	//FIXME: check for multiple initial states (only permissible if MULTIBYTE_START_STATE_1 flag is set)

	// Initial state
	unicode_states.push_back(new State());
	unicode_states.back()->flags |= State::INITIAL;
	unicode_states.back()->new_entry(ENTRY(0, 0, 1, ACTION_VALID));
	unicode_states.back()->new_entry(ENTRY(1, 0x10, 2, ACTION_VALID));

	// Second state for BMP
	unicode_states.push_back(new State());
	unicode_states.back()->new_entry(ENTRY(0, 0xff, 3, ACTION_VALID));
	unicode_states.back()->new_entry(ENTRY(0xd8, 0xdf, 4, ACTION_VALID));
	unicode_states.back()->new_entry(ENTRY(0xfd, 0xfd, 5, ACTION_VALID));
	unicode_states.back()->new_entry(ENTRY(0xff, 0xff, 6, ACTION_VALID));

	// Second state for non-BMP planes
	unicode_states.push_back(new State());
	unicode_states.back()->new_entry(ENTRY(0, 0xfe, 3, ACTION_VALID));
	unicode_states.back()->new_entry(ENTRY(0xff, 0xff, 6, ACTION_VALID));

	// Final state for all regular ranges
	unicode_states.push_back(new State());
	unicode_states.back()->new_entry(ENTRY(0, 0xff, 0, ACTION_UNASSIGNED));

	// Final state for U+D800..U+DFFF (surrogates)
	unicode_states.push_back(new State());

	// Final state for U+FD00..U+FDFF, which contains a reserved range
	unicode_states.push_back(new State());
	unicode_states.back()->new_entry(ENTRY(0, 0xff, 0, ACTION_UNASSIGNED));
	unicode_states.back()->new_entry(ENTRY(0xd0, 0xef, 0, ACTION_ILLEGAL));

	// Final state for U+??FF00..U+??FFFF, which contains two reserved codepoints
	unicode_states.push_back(new State());
	unicode_states.back()->new_entry(ENTRY(0, 0xfd, 0, ACTION_UNASSIGNED));
}

void Ucm::set_default_codepage_states(void) {
	if (uconv_class == 0 || uconv_class == CLASS_MBCS)
		fatal("No states specified and no implicit states defined through <uconv_class> either\n");

	if (uconv_class == CLASS_SBCS) {
		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0, 255, 0, ACTION_FINAL));
	} else if (uconv_class == CLASS_DBCS) {
		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0, 0x3f, 3, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0x40, 0x40, 2, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0x41, 0xfe, 1, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0xff, 0xff, 3, ACTION_VALID));

		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0x41, 0xfe, 0, ACTION_FINAL));

		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0x40, 0x40, 0, ACTION_FINAL));

		new_codepage_state();
		// All illegal state
	} else if (uconv_class == CLASS_EBCDIC_STATEFUL) {
		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0, 0x0d, 0, ACTION_FINAL));
		codepage_states.back()->new_entry(ENTRY(0x0e, 0x0e, 1, ACTION_SHIFT));
		codepage_states.back()->new_entry(ENTRY(0x0f, 0x0f, 0, ACTION_SHIFT));
		codepage_states.back()->new_entry(ENTRY(0x10, 0xff, 0, ACTION_FINAL));
		new_codepage_state(State::INITIAL);

		codepage_states.back()->new_entry(ENTRY(0, 0x0d, 4, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0x0e, 0x0e, 1, ACTION_SHIFT));
		codepage_states.back()->new_entry(ENTRY(0x0f, 0x0f, 0, ACTION_SHIFT));
		codepage_states.back()->new_entry(ENTRY(0x10, 0x3f, 4, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0x40, 0x40, 3, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0x41, 0xfe, 2, ACTION_VALID));
		codepage_states.back()->new_entry(ENTRY(0xff, 0xff, 4, ACTION_VALID));

		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0x41, 0xfe, 1, ACTION_FINAL));

		new_codepage_state();
		codepage_states.back()->new_entry(ENTRY(0x40, 0x40, 1, ACTION_FINAL));

		new_codepage_state();
		// All illegal state
	} else {
		PANIC();
	}
}
#undef ENTRY

int Ucm::calculate_depth(Entry *entry) {
	int depth, max_depth = 0;
	size_t i;

	switch (entry->action) {
		case ACTION_FINAL:
		case ACTION_FINAL_PAIR:
		case ACTION_UNASSIGNED:
		case ACTION_SHIFT:
			return 1;
		case ACTION_VALID:
			for (i = 0; i < codepage_states[entry->next_state]->entries.size(); i++) {
				depth = calculate_depth(&codepage_states[entry->next_state]->entries[i]);
				if (depth > max_depth)
					max_depth = depth;
			}
			if (max_depth > 0)
				return max_depth + 1;
			else
				return -1;
		case ACTION_ILLEGAL:
			return -1;
		default:
			PANIC();
	}
	PANIC();
	return 0;
}

void Ucm::validate_states(void) {
	size_t i, j;
	int mb_cur_max = 4, mb_cur_min = 1;

	for (i = 0; i < codepage_states.size(); i++) {
		for (j = 0; j < codepage_states[i]->entries.size(); j++) {
			if (codepage_states[i]->entries[j].action == ACTION_UNASSIGNED &&
					codepage_states[i]->entries[j].action == ACTION_ILLEGAL)
				continue;

			if (codepage_states[i]->entries[j].next_state >= (int) codepage_states.size())
				fatal("State %zd:%x-%x designates a non-existant state as next state\n", i,
					codepage_states[i]->entries[j].low, codepage_states[i]->entries[j].high);

			if (codepage_states[i]->entries[j].action != ACTION_VALID &&
					!(codepage_states[codepage_states[i]->entries[j].next_state]->flags & State::INITIAL))
				fatal("State %zd:%x-%x designates a non-initial state as next state for final/unassigned/illegal/shift transition\n",
					i, codepage_states[i]->entries[j].low, codepage_states[i]->entries[j].high);

			if (codepage_states[i]->entries[j].action != ACTION_VALID)
				continue;

			if (codepage_states[codepage_states[i]->entries[j].next_state]->flags & State::INITIAL)
				fatal("State %d:%x-%x designates an initial state as next state for non-final transition\n", i,
					codepage_states[i]->entries[j].low, codepage_states[i]->entries[j].high);
		}
	}

	mb_cur_max = atoi(tag_values[MB_MAX]);
	mb_cur_min = atoi(tag_values[MB_MIN]);

	if (mb_cur_max > 4 || mb_cur_max < 1)
		fatal("<mb_cur_max> is out of range\n");
	if (mb_cur_min > mb_cur_max || mb_cur_min < 1)
		fatal("<mb_cur_min> is out of range\n");

	for (i = 0; i < codepage_states.size(); i++) {
		if (!(codepage_states[i]->flags & State::INITIAL))
			continue;

		for (j = 0; j < codepage_states[i]->entries.size(); j++) {
			int depth = calculate_depth(&codepage_states[i]->entries[j]);
			if (depth > 0 && depth > mb_cur_max)
				fatal("State machine specifies byte sequences longer than <mb_cur_max>\n");
			if (depth > 0 && depth < mb_cur_min)
				fatal("State machine specifies byte sequences shorter than <mb_cur_min>\n");
		}
	}

	vector<uint8_t> bytes;
	/* FIXME: line number is not correct at this point, so the error messages generated from the
	   functions below will be confusing. */

	parse_byte_sequence(tag_values[SUBCHAR], bytes);
	check_codepage_bytes(bytes);
}

static const char *print_sequence(vector<uint8_t> &bytes) {
	static char sequence_buffer[31 * 4 + 1];
	size_t i;
	for (i = 0; i < 31 && i < bytes.size(); i++)
		sprintf(sequence_buffer + i * 4, "\\x%02X", bytes[i]);
	return sequence_buffer;
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
		for (j = 0; j < codepage_states[state]->entries.size(); j++) {
			if (!(bytes[i] >= codepage_states[state]->entries[j].low && bytes[i] <= codepage_states[state]->entries[j].high))
				continue;

			switch (codepage_states[state]->entries[j].action) {
				case ACTION_ILLEGAL:
					fatal("%s:%d: Illegal sequence '%s'\n", file_name, line_number - 1, print_sequence(bytes));
				case ACTION_UNASSIGNED:
					fatal("%s:%d: Unassigned sequence '%s'\n", file_name, line_number - 1, print_sequence(bytes));
				case ACTION_SHIFT:
					fatal("%s:%d: Shift in sequence '%s'\n", file_name, line_number - 1, print_sequence(bytes));
				case ACTION_VALID:
					state = codepage_states[state]->entries[j].next_state;
					goto next_char;
				case ACTION_FINAL_PAIR:
				case ACTION_FINAL:
					state = codepage_states[state]->entries[j].next_state;
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

	if (codepage_chars == 1 && mapping->codepoints.size() == 1) {
		switch (mapping->precision) {
			case 0:
				break;
			case 1:
				mapping->from_unicode_flags |= Mapping::FROM_UNICODE_FALLBACK;
				break;
			case 2:
				if (tag_values[SUBCHAR1] == NULL) {
					fprintf(stderr, "%s:%d: WARNING: subchar1 is not defined, but mapping with precision 2 was found. Ignoring.\n", file_name, line_number - 1);
					return;
				} else {
					/* When calculating which bits are required, don't include length for SUBCHAR1 flagged mappings */
					mapping->from_unicode_flags |= Mapping::FROM_UNICODE_SUBCHAR1;
				}
				break;
			case 3:
				mapping->to_unicode_flags |= Mapping::TO_UNICODE_FALLBACK;
				break;
			default:
				PANIC();
		}
		if ((mapping->codepoints[0] >= UINT32_C(0xfdd0) && mapping->codepoints[0] <= UINT32_C(0xfdef)) ||
				(mapping->codepoints[0] & UINT32_C(0xfffe)) == UINT32_C(0xfffe))
			fatal("%s:%d: codepoint specifies a non-character (U%04" PRIX32 ")\n", file_name, line_number - 1, mapping->codepoints[0]);

		if ((mapping->codepoints[0] >= UINT32_C(0xe000) && mapping->codepoints[0] <= UINT32_C(0xf8ff)) ||
				(mapping->codepoints[0] >= UINT32_C(0xf0000) && mapping->codepoints[0] <= UINT32_C(0xffffd)) ||
				(mapping->codepoints[0] >= UINT32_C(0x100000) && mapping->codepoints[0] <= UINT32_C(0x10fffd)))
			mapping->to_unicode_flags |= Mapping::TO_UNICODE_PRIVATE_USE;
		mapping->from_unicode_flags |= (mapping->codepage_bytes.size() - 1) << 2;
		simple_mappings.push_back(mapping);
	} else {
		//FIXME: check for private-use or non-character codepoints
		multi_mappings.push_back(mapping);
	}
}

void Ucm::remove_fullwidth_fallbacks(void) {
	if (option_verbose)
		fprintf(stderr, "Removing fullwidth fallbacks\n");

	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); ) {
		if ((*iter)->codepoints[0] >= UINT32_C(0xff01) && (*iter)->codepoints[0] <= UINT32_C(0xff5e) && (*iter)->precision == 1) {
			vector<Mapping *>::iterator search_iter;
			uint32_t search_for;
			size_t i;

			search_for = (*iter)->codepoints[0] - 0xff00 + 0x20;
			for (search_iter = simple_mappings.begin(); search_iter != simple_mappings.end(); search_iter++) {
				if ((*search_iter)->codepoints[0] == search_for)
					break;
			}

			if (search_iter == simple_mappings.end()) {
				iter++;
				continue;
			}

			if ((*iter)->codepage_bytes.size() != (*search_iter)->codepage_bytes.size()) {
				iter++;
				continue;
			}

			for (i = 0; i < (*iter)->codepage_bytes.size(); i++) {
				if ((*iter)->codepage_bytes[i] != (*search_iter)->codepage_bytes[i])
					break;
			}

			if (i == (*iter)->codepage_bytes.size()) {
				iter = simple_mappings.erase(iter);
				continue;
			}
		}

		iter++;
	}
}

void Ucm::remove_private_use_fallbacks(void) {
	/* The fallbacks from private-use codepoints are only useful if you have
	   previously converted texts in which the private-use codepoints were actually
	   saved, and then mostly if the use of private-use codepoints is standardized
	   between all convertors. The first is something that should not occur because
	   private-use codepoints should not be used without context, and the second is
	   unenforcable. If a unicode codepoint is finally assigned, it should be used
	   in all relevant codepages. */
	if (option_verbose)
		fprintf(stderr, "Removing fallbacks from private-use codepoints\n");
	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); ) {
		if ((*iter)->precision == 1 && ((*iter)->to_unicode_flags & Mapping::TO_UNICODE_PRIVATE_USE)) {
			iter = simple_mappings.erase(iter);
			continue;
		}
		iter++;
	}
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

void Ucm::ensure_ascii_controls(void) {
	vector<Mapping *>::iterator iter;
	int mb_min, mb_max, seen = 0;

	if (tag_values[CHARSET_FAMILY] != NULL && strcmp(tag_values[CHARSET_FAMILY], "ASCII") != 0)
		return;

	if (tag_values[SUBCHAR] != NULL && strcmp(tag_values[SUBCHAR], "\\x7F") != 0)
		return;

	mb_max = atoi(tag_values[MB_MAX]);
	mb_min = atoi(tag_values[MB_MIN]);

	if (mb_min != 1 || mb_max != 1) {
		fprintf(stderr, "Check this page!\n");
		return;
	}

	for (iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		switch ((*iter)->codepoints[0]) {
			case 0x1a:
				if ((*iter)->codepage_bytes[0] != 0x7f)
					return;
				seen |= 1;
				break;
			case 0x1c:
				if ((*iter)->codepage_bytes[0] != 0x1a)
					return;
				seen |= 2;
				break;
			case 0x7f:
				if ((*iter)->codepage_bytes[0] != 0x1c)
					return;
				seen |= 4;
				break;
			default:;
		}
	}
	if (seen != 7)
		return;
	fprintf(stderr, "WARNING: mappings define IBM specific control code mappings. Correcting.\n");

	for (iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		switch ((*iter)->codepage_bytes[0]) {
			case 0x1a:
				(*iter)->codepage_bytes[0] = 0x1c;
				break;
			case 0x1c:
				(*iter)->codepage_bytes[0] = 0x7f;
				break;
			case 0x7f:
				(*iter)->codepage_bytes[0] = 0x1a;
				break;
			default:;
		}
	}
}

void Ucm::calculate_item_costs(void) {
	from_unicode_flags = simple_mappings[0]->from_unicode_flags;
	to_unicode_flags = simple_mappings[0]->to_unicode_flags;

	uint8_t used_from_unicode_flags = 0, used_to_unicode_flags = 0;
	int length_counts[4] = { 0, 0, 0, 0 };
	int i, j, best_size;
	double size;

	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		uint8_t change = from_unicode_flags ^ (*iter)->from_unicode_flags;
		if ((*iter)->from_unicode_flags & Mapping::FROM_UNICODE_SUBCHAR1)
			change &= ~Mapping::FROM_UNICODE_LENGTH_MASK;
		used_from_unicode_flags |= change;

		used_to_unicode_flags |= to_unicode_flags ^ (*iter)->to_unicode_flags;

		length_counts[(*iter)->codepage_bytes.size() - 1]++;
	}

	if (multi_mappings.size() > 0) {
		used_from_unicode_flags |= Mapping::FROM_UNICODE_MULTI_START;
		used_to_unicode_flags |= Mapping::TO_UNICODE_MULTI_START;
	}

	if (option_verbose)
		fprintf(stderr, "Items to save:\n");

	from_flag_costs = to_flag_costs = 0.0;
	from_flag_costs += 0.25; /* FIXME: when there are no unassigned mappings in the range, and there
		are no FROM_UNICODE_FALLBACK characters, this should be 0. However, we don't know whether there
		are unassigned mappings, because that will be calculated based on the costs calculated here.
		Chicken, egg, etc. */
	from_unicode_flags &= ~(Mapping::FROM_UNICODE_NOT_AVAIL | Mapping::FROM_UNICODE_FALLBACK);
	from_unicode_flags_save = 1;
	fprintf(stderr, "- from unicode not available/fallback flags\n");
	if (used_from_unicode_flags & (Mapping::FROM_UNICODE_SUBCHAR1 | Mapping::FROM_UNICODE_MULTI_START)) {
		from_flag_costs += 0.25;
		from_unicode_flags &= ~(Mapping::FROM_UNICODE_SUBCHAR1 | Mapping::FROM_UNICODE_MULTI_START);
		from_unicode_flags_save |= 2;
		if (option_verbose)
			fprintf(stderr, "- from unicode M:N mappings/subchar1 flags\n");
	}
	if (used_from_unicode_flags & Mapping::FROM_UNICODE_LENGTH_MASK) {
		from_flag_costs += 0.25;
		from_unicode_flags &= ~Mapping::FROM_UNICODE_LENGTH_MASK;
		from_unicode_flags_save |= 4;
		if (option_verbose)
			fprintf(stderr, "- from unicode length\n");
	}

	if (used_to_unicode_flags & (Mapping::TO_UNICODE_FALLBACK | Mapping::TO_UNICODE_MULTI_START)) {
		to_flag_costs += 0.25;
		to_unicode_flags &= ~(Mapping::TO_UNICODE_FALLBACK | Mapping::TO_UNICODE_MULTI_START);
		to_unicode_flags_save |= 1;
		if (option_verbose)
			fprintf(stderr, "- to unicode fallback/M:N mappings\n");
	}
	if (used_to_unicode_flags & Mapping::TO_UNICODE_PRIVATE_USE) {
		to_flag_costs += 0.25;
		to_unicode_flags &= ~Mapping::TO_UNICODE_PRIVATE_USE;
		to_unicode_flags_save |= 2;
		if (option_verbose)
			fprintf(stderr, "- to unicode private use\n");
	}

	best_size = INT_MAX;
	for (i = 1; i <= 3; i++) {
		size = 0.0;

		if (i == 1 && (length_counts[2] != 0 || length_counts[3] != 0))
			continue;

		for (j = 0; j < 4; j++) {
			if (j < i)
				size += (double) length_counts[j] * (i + from_flag_costs);
			else
				size += (double) length_counts[j] * 2 * (i + from_flag_costs);
		}

		if (size + 0.99 < best_size) {
			best_size = size + 0.99;
			single_bytes = i;
		}
	}

	if (from_unicode_flags_save != 0)
		flags |= FROM_UNICODE_FLAGS_TABLE_INCLUDED;
	if (to_unicode_flags_save != 0)
		flags |= TO_UNICODE_FLAGS_TABLE_INCLUDED;
	if (!multi_mappings.empty())
		flags |= MULTI_MAPPINGS_AVAILABLE;
}

void Ucm::minimize_state_machines(void) {
	StateMachineInfo *info = new CodepageBytesStateMachineInfo(*this);
	minimize_state_machine(info, flags);
	delete info;
	info = new UnicodeStateMachineInfo(*this);
	minimize_state_machine(info, 0);
	delete info;
}

#define WRITE(file, count, bytes) do { if (fwrite(bytes, 1, count, file) != count) fatal("Error writing file\n"); } while (0)
#define WRITE_BYTE(file, value) do { uint8_t byte = value; if (fwrite(&byte, 1, 1, file) != 1) fatal("Error writing file\n"); } while (0)
#define WRITE_WORD(file, value) do { uint16_t byte = htons(value); if (fwrite(&byte, 1, 2, file) != 2) fatal("Error writing file\n"); } while (0)
#define WRITE_DWORD(file, value) do { uint32_t byte = htons(value); if (fwrite(&byte, 1, 4, file) != 4) fatal("Error writing file\n"); } while (0)

void Ucm::write_table(FILE *output) {
	const char magic[] = "T3CM";
	size_t total_entries;

	WRITE(output, 4, magic); // magic (4)
	WRITE_DWORD(output, 0); // version (4)
	WRITE_BYTE(output, flags); // flags (1)
	vector<uint8_t> subchar;
	parse_byte_sequence(tag_values[Ucm::SUBCHAR], subchar);
	WRITE_BYTE(output, subchar.size()); // subchar length (1)
	for (vector<uint8_t>::iterator iter = subchar.begin(); iter != subchar.end(); iter++)
		WRITE_BYTE(output, *iter); // subchar byte (1)
	WRITE_BYTE(output, tag_values[Ucm::SUBCHAR1] != NULL ? strtol(tag_values[Ucm::SUBCHAR1] + 2, NULL, 16) : 0); // subchar1 (1)
	WRITE_BYTE(output, 0); //FIXME: nr of shift sequences
	WRITE_BYTE(output, codepage_states.size()); // nr of states in codepage state machine (1)
	total_entries = 0;
	for (vector<State *>::iterator state_iter = codepage_states.begin();
			state_iter != codepage_states.end(); state_iter++)
		total_entries += (*state_iter)->entries.size();
	WRITE_WORD(output, total_entries); // total nr of entries (code page) (2)
	WRITE_BYTE(output, unicode_states.size()); // nr of states in unicode state machine (1)
	total_entries = 0;
	for (vector<State *>::iterator state_iter = unicode_states.begin();
			state_iter != unicode_states.end(); state_iter++)
		total_entries += (*state_iter)->entries.size();
	WRITE_WORD(output, total_entries); // total nr of entries (unicode) (2)
	WRITE_BYTE(output, from_unicode_flags); // default from-unicode flags (1)
	WRITE_BYTE(output, to_unicode_flags); //default to-unicode flags (1)
	//FIXME: write shift sequences

	for (vector<State *>::iterator state_iter = codepage_states.begin();
			state_iter != codepage_states.end(); state_iter++)
	{
		WRITE_BYTE(output, (*state_iter)->entries.size());
		for (vector<Entry>::iterator entry_iter = (*state_iter)->entries.begin();
				entry_iter != (*state_iter)->entries.end(); entry_iter++)
		{
			WRITE_BYTE(output, entry_iter->low);
			WRITE_BYTE(output, entry_iter->high);
			WRITE_BYTE(output, entry_iter->next_state);
			WRITE_BYTE(output, entry_iter->action);
		}
	}

	for (vector<State *>::iterator state_iter = unicode_states.begin();
		state_iter != unicode_states.end(); state_iter++)
	{
		WRITE_BYTE(output, (*state_iter)->entries.size());
		for (vector<Entry>::iterator entry_iter = (*state_iter)->entries.begin();
			entry_iter != (*state_iter)->entries.end(); entry_iter++)
		{
			WRITE_BYTE(output, entry_iter->low);
			WRITE_BYTE(output, entry_iter->high);
			WRITE_BYTE(output, entry_iter->next_state);
			WRITE_BYTE(output, entry_iter->action);
		}
	}

	write_from_unicode_table(output);
	write_to_unicode_table(output);
	if (from_unicode_flags_save != 0)
		write_from_unicode_flags(output);
	if (to_unicode_flags_save != 0)
		write_to_unicode_flags(output);
}

void Ucm::write_to_unicode_table(FILE *output) {
	uint16_t *codepoints;
	uint8_t buffer[32];
	uint32_t idx;

	if ((codepoints = (uint16_t *) malloc(codepage_range * sizeof(uint16_t))) == NULL)
		OOM();

	memset(codepoints, 0xff, codepage_range * sizeof(uint16_t));

	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if ((*iter)->precision != 0 && (*iter)->precision != 3)
			continue;

		copy((*iter)->codepage_bytes.begin(), (*iter)->codepage_bytes.end(), buffer);
		idx = map_charseq(codepage_states, buffer, (*iter)->codepage_bytes.size(), flags);
		if ((*iter)->codepoints[0] > UINT32_C(0xffff)) {
			codepoints[idx] = (((*iter)->codepoints[0] - 0x10000) >> 10) + 0xd800;
			codepoints[idx + 1] = (((*iter)->codepoints[0] - 0x10000) & 0x3ff) + 0xdc00;
		} else {
			codepoints[idx] = (*iter)->codepoints[0];
		}
	}

	for (idx = 0; idx < codepage_range; idx++)
		WRITE_WORD(output, codepoints[idx]);

	free(codepoints);
}

void Ucm::write_from_unicode_table(FILE *output) {
	uint8_t *codepage_bytes;
	uint32_t idx, codepoint;

	if ((codepage_bytes = (uint8_t *) malloc(unicode_range * single_bytes)) == NULL)
		OOM();

	memset(codepage_bytes, 0x00, unicode_range * single_bytes);

	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if ((*iter)->precision != 0 && (*iter)->precision != 1)
			continue;

		codepoint = htonl((*iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		copy((*iter)->codepage_bytes.begin(), (*iter)->codepage_bytes.end(), codepage_bytes + idx * single_bytes);
	}

	WRITE(output, unicode_range * single_bytes, codepage_bytes);
	free(codepage_bytes);
}

static uint8_t convert_flags(uint8_t flags_save, uint8_t flags) {
	static uint8_t mask[16] = { 0x00, 0x03, 0x0c, 0x0f, 0x30, 0x33, 0x3c, 0x00, 0xc0, 0xc3, 0xcc, 0x00, 0xf0, 0x00, 0x00, 0xff };
	static int shift_1[16] = { 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0 };
	static int shift_2[16] = { 0, 0, 0, 0, 4, 2, 2, 0, 0, 0, 0, 0, 4, 0, 0, 0 };
	static int shift_3[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 6, 4, 4, 0, 4, 0, 0, 0 };
	uint8_t parts[4];

	flags &= mask[flags_save];
	parts[0] = flags & mask[1];
	parts[1] = flags & mask[2];
	parts[2] = flags & mask[4];
	parts[3] = flags & mask[8];

	return parts[0] | (parts[1] >> shift_1[flags_save]) | (parts[2] >> shift_2[flags_save]) | (parts[3] >> shift_3[flags_save]);
}

static void merge_and_write_flags(FILE *output, uint8_t *data, uint32_t range, uint8_t flags_save) {
	static int shift[16] = {0, 2, 2, 4, 2, 4, 4, 0, 2, 4, 4, 0, 4, 0, 0, 8};
	static int step[16] = {0, 4, 4, 2, 4, 2, 2, 0, 4, 2, 2, 0, 2, 0, 0, 1};
	size_t store_idx = 0;
	uint8_t byte;
	uint32_t i;
	int j;

	for (i = 0; i < range; ) {
		byte = 0;
		for (j = 0; j < step[flags_save]; j++)
			byte |= convert_flags(flags_save, data[i++]) << (shift[flags_save] * j);
		data[store_idx++] = byte;
	}
	WRITE(output, store_idx, data);
}

void Ucm::write_to_unicode_flags(FILE *output) {
	uint32_t idx;
	uint8_t buffer[32];
	uint8_t *save_flags;

	if ((save_flags = (uint8_t *) malloc(codepage_range + 7)) == NULL)
		OOM();

	memset(save_flags, 0, codepage_range + 7);
	WRITE_BYTE(output, to_unicode_flags_save);

	for (vector<Mapping *>::iterator simple_iter = simple_mappings.begin();
			simple_iter != simple_mappings.end(); simple_iter++)
	{
		if ((*simple_iter)->precision == 1)
			continue;

		copy((*simple_iter)->codepage_bytes.begin(), (*simple_iter)->codepage_bytes.end(), buffer);
		idx = map_charseq(codepage_states, buffer, (*simple_iter)->codepage_bytes.size(), flags);
		save_flags[idx] = (*simple_iter)->to_unicode_flags;
	}

	for (vector<Mapping *>::iterator multi_iter = multi_mappings.begin();
			multi_iter != multi_mappings.end(); multi_iter++)
	{
		copy((*multi_iter)->codepage_bytes.begin(), (*multi_iter)->codepage_bytes.end(), buffer);
		idx = map_charseq(codepage_states, buffer, (*multi_iter)->codepage_bytes.size(), flags);
		save_flags[idx] |= Mapping::TO_UNICODE_MULTI_START;
	}

	merge_and_write_flags(output, save_flags, codepage_range, to_unicode_flags_save);
	free(save_flags);
}

void Ucm::write_from_unicode_flags(FILE *output) {
	uint32_t idx, codepoint;
	uint8_t *save_flags;

	if ((save_flags = (uint8_t *) malloc(unicode_range + 7)) == NULL)
		OOM();

	memset(save_flags, Mapping::FROM_UNICODE_NOT_AVAIL, unicode_range + 7);
	WRITE_BYTE(output, from_unicode_flags_save);

	for (vector<Mapping *>::iterator simple_iter = simple_mappings.begin();
			simple_iter != simple_mappings.end(); simple_iter++)
	{
		if ((*simple_iter)->precision == 3)
			continue;

		codepoint = htonl((*simple_iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		save_flags[idx] |= (*simple_iter)->from_unicode_flags;
		save_flags[idx] &= ~Mapping::FROM_UNICODE_NOT_AVAIL;
	}

	for (vector<Mapping *>::iterator multi_iter = multi_mappings.begin();
			multi_iter != multi_mappings.end(); multi_iter++)
	{
		codepoint = htonl((*multi_iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		save_flags[idx] |= Mapping::FROM_UNICODE_MULTI_START;
	}

	merge_and_write_flags(output, save_flags, unicode_range, from_unicode_flags_save);
	free(save_flags);
}


Ucm::CodepageBytesStateMachineInfo::CodepageBytesStateMachineInfo(Ucm &_source) : source(_source),
	iterating_simple_mappings(true), idx(0)
{}

const vector<State *> &Ucm::CodepageBytesStateMachineInfo::get_state_machine(void) {
	return source.codepage_states;
}

void Ucm::CodepageBytesStateMachineInfo::replace_state_machine(vector<State *> &states) {
	for (vector<State *>::iterator iter = source.codepage_states.begin();
			iter != source.codepage_states.end(); iter++)
		delete (*iter);

	source.codepage_states = states;
}

bool Ucm::CodepageBytesStateMachineInfo::get_next_byteseq(uint8_t *bytes, size_t &length, bool &pair) {

	if (iterating_simple_mappings) {
next_simple_mapping:
		if (idx < source.simple_mappings.size()) {
			if (source.simple_mappings[idx]->precision != 0 && source.simple_mappings[idx]->precision != 3) {
				idx++;
				goto next_simple_mapping;
			}
			copy(source.simple_mappings[idx]->codepage_bytes.begin(), source.simple_mappings[idx]->codepage_bytes.end(), bytes);
			length = source.simple_mappings[idx]->codepage_bytes.size();
			pair = source.simple_mappings[idx]->codepoints[0] > UINT32_C(0xffff);
			idx++;
			return true;
		} else {
			iterating_simple_mappings = false;
			idx = 0;
		}
	}

next_multi_mapping:
	if (idx >= source.multi_mappings.size())
		return false;

	if (source.multi_mappings[idx]->precision != 0 && source.multi_mappings[idx]->precision != 3) {
		idx++;
		goto next_multi_mapping;
	}

	copy(source.multi_mappings[idx]->codepage_bytes.begin(), source.multi_mappings[idx]->codepage_bytes.end(), bytes);
	length = source.multi_mappings[idx]->codepage_bytes.size();
	pair = false;
	idx++;
	return true;
}

double Ucm::CodepageBytesStateMachineInfo::get_single_cost(void) {
	return source.to_flag_costs + 2;
}

Ucm::UnicodeStateMachineInfo::UnicodeStateMachineInfo(Ucm &_source) : source(_source),
	iterating_simple_mappings(true), idx(0)
{}

const vector<State *> &Ucm::UnicodeStateMachineInfo::get_state_machine(void) {
	return source.unicode_states;
}

void Ucm::UnicodeStateMachineInfo::replace_state_machine(vector<State *> &states) {
	for (vector<State *>::iterator iter = source.unicode_states.begin();
			iter != source.unicode_states.end(); iter++)
		delete (*iter);

	source.unicode_states = states;
}

bool Ucm::UnicodeStateMachineInfo::get_next_byteseq(uint8_t *bytes, size_t &length, bool &pair) {
	uint32_t codepoint;

	if (iterating_simple_mappings) {
next_simple_mapping:
		if (idx < source.simple_mappings.size()) {
			if (source.simple_mappings[idx]->precision == 3) {
				idx++;
				goto next_simple_mapping;
			}
			codepoint = htonl(source.simple_mappings[idx]->codepoints[0]);
			memcpy(bytes, 1 + (char *) &codepoint, 3);
			length = 3;
			pair = source.simple_mappings[idx]->codepage_bytes.size() > (size_t) source.single_bytes;
			idx++;
			return true;
		} else {
			iterating_simple_mappings = false;
			idx = 0;
		}
	}

next_multi_mapping:
	if (idx >= source.multi_mappings.size())
		return false;

	if (source.multi_mappings[idx]->precision != 0 && source.multi_mappings[idx]->precision != 1) {
		idx++;
		goto next_multi_mapping;
	}

	codepoint = htonl(source.simple_mappings[idx]->codepoints[0]);
	memcpy(bytes, 1 + (char *) &codepoint, 3);
	length = 3;
	pair = false;
	idx++;
	return true;
}

double Ucm::UnicodeStateMachineInfo::get_single_cost(void) {
	return source.from_flag_costs + source.single_bytes;
}
