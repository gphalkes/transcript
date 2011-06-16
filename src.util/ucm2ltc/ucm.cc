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
#include <cstdlib>
#include <arpa/inet.h>
#include <algorithm>
#include "moduledefs.h"
#include "ucm2ltc.h"

State::State(void) : flags(0), base(0), range(0), complete(false) {
	entries.push_back(Entry(0, 255, 0, ACTION_ILLEGAL, 0, 0));
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

void UcmBase::add_mapping(Mapping *mapping) {
	int codepage_chars = check_codepage_bytes(mapping->codepage_bytes);

	if (codepage_chars == 1 && mapping->codepoints.size() == 1) {
		switch (mapping->precision) {
			case 0:
				break;
			case 1:
				mapping->from_unicode_flags |= Mapping::FROM_UNICODE_FALLBACK;
				break;
			case 2:
				if (get_tag_value(SUBCHAR1) == NULL) {
					fprintf(stderr, "%s:%d: WARNING: subchar1 is not defined, but mapping with precision 2 was found. Ignoring.\n",
						file_name, line_number - 1);
					return;
				} else {
					mapping->from_unicode_flags |= Mapping::FROM_UNICODE_SUBCHAR1 | Mapping::FROM_UNICODE_NOT_AVAIL;
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
		mapping->from_unicode_flags |= (mapping->codepage_bytes.size() - 1);
		simple_mappings.push_back(mapping);
	} else {
		//FIXME: check for private-use or non-character codepoints
		used_to_unicode_flags |= Mapping::TO_UNICODE_MULTI_START;
		used_from_unicode_flags |= Mapping::FROM_UNICODE_MULTI_START;

		if (mapping->precision == 2)
			fatal("%s:%d: Multi-mapping can not have precision 2\n", file_name, line_number - 1);

		multi_mappings.push_back(mapping);
	}
}

Ucm::Ucm(const char *_name) : variant(this, option_converter_name == NULL ? _name : option_converter_name),
		name(_name), flags(option_internal_table ? INTERNAL_TABLE : 0), from_unicode_flags(0), to_unicode_flags(0)
{
	for (int i = 0; i < LAST_TAG; i++)
		tag_values[i].str = NULL;
}

void Ucm::set_tag_value(tag_t tag, const char *value) {
	if (tag == IGNORED)
		return;
	if ((tag_values[tag].str = safe_strdup(value)) == NULL)
		OOM();
	tag_values[tag].line_number = line_number;
}

const char *Ucm::get_tag_value(tag_t tag) {
	return tag_values[tag].str;
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

#define ENTRY(low, high, next_state, action) Entry(low, high, next_state, action, 0, 0)
void Ucm::process_header(void) {
	if (tag_values[UCONV_CLASS].str == NULL)
		fatal("%s: <uconv_class> unspecified\n", name);

	if (strcmp(tag_values[UCONV_CLASS].str, "SBCS") == 0)
		uconv_class = CLASS_SBCS;
	else if (strcmp(tag_values[UCONV_CLASS].str, "DBCS") == 0)
		uconv_class = CLASS_DBCS;
	else if (strcmp(tag_values[UCONV_CLASS].str, "MBCS") == 0)
		uconv_class = CLASS_MBCS;
	else if (strcmp(tag_values[UCONV_CLASS].str, "EBCDIC_STATEFUL") == 0)
		uconv_class = CLASS_EBCDIC_STATEFUL;
	else
		fatal("%s: <uconv_class> specifies an unknown class\n", name);

	if (tag_values[MB_MAX].str == NULL)
		fatal("%s: <mb_cur_max> unspecified\n", name);
	if (tag_values[MB_MIN].str == NULL)
		fatal("%s: <mb_cur_min> unspecified\n", name);

	if (tag_values[INTERNAL].str != NULL) {
		flags |= INTERNAL_TABLE;
		variant.flags |= INTERNAL_TABLE;
	}

	if (flags & INTERNAL_TABLE) {
		if (tag_values[SUBCHAR1].str != NULL && tag_values[SUBCHAR].str == NULL)
			fatal("%s: internal table specifies <subchar1>, but not <subchar>\n");
	} else {
		/* Internal tables don't need subchars */
		if (tag_values[SUBCHAR].str == NULL)
			fatal("%s: <subchar> unspecified\n", name);
	}

	if (tag_values[SUBCHAR1].str != NULL)
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
		fatal("%s: No states specified and no implicit states defined through <uconv_class> either\n", name);

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

int Ucm::check_codepage_bytes(vector<uint8_t> &bytes) {
	int state, count = 0;
	size_t i, j;

	/* Some stateful converters are treated specially: single byte characters can not
	   be part of a multi-byte sequence && must be defined in state 0. See
	   process_header_part2() to see what conditions a converter must satisfy for this
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
					fatal("%s:%d: Illegal sequence '%s'\n", file_name, line_number - 1, sprint_sequence(bytes));
				case ACTION_UNASSIGNED:
					fatal("%s:%d: Unassigned sequence '%s'\n", file_name, line_number - 1, sprint_sequence(bytes));
				case ACTION_SHIFT:
					fatal("%s:%d: Shift in sequence '%s'\n", file_name, line_number - 1, sprint_sequence(bytes));
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
	if (count == 0)
		fatal("%s:%d: Sequence too short: '%s'\n", file_name, line_number - 1, sprint_sequence(bytes));
	return count;
}

void Ucm::remove_generic_fallbacks(void) {
	if (option_verbose)
		fprintf(stderr, "Removing generic fallbacks\n");

	remove_generic_fallbacks_internal(this, NULL);
	for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
		remove_generic_fallbacks_internal(*variant_iter, *variant_iter);
}

void Ucm::remove_generic_fallbacks_internal(UcmBase *check, Variant *current_variant) {
	for (vector<Mapping *>::iterator iter = check->simple_mappings.begin(); iter != check->simple_mappings.end(); ) {
		vector<Mapping *>::const_iterator search_iter;
		uint32_t search_for;

		if ((*iter)->precision != 1 || (*iter)->codepoints.size() > 1 ||
				(search_for = transcript_get_generic_fallback((*iter)->codepoints[0])) == 0xFFFF)
		{
			iter++;
			continue;
		}

		for (search_iter = simple_mappings.begin(); search_iter != simple_mappings.end(); search_iter++) {
			if ((*search_iter)->codepoints[0] == search_for)
				break;
		}

		if (search_iter == simple_mappings.end()) {
			if (current_variant != NULL) {
				for (search_iter = current_variant->simple_mappings.begin();
						search_iter != current_variant->simple_mappings.end(); search_iter++)
				{
					if ((*search_iter)->codepoints[0] == search_for)
						break;
				}
				if (search_iter == current_variant->simple_mappings.end()) {
					iter++;
					continue;
				}
			} else {
				iter++;
				continue;
			}
		}

		if ((*search_iter)->precision != 0 ||
				(*iter)->codepage_bytes.size() != (*search_iter)->codepage_bytes.size() ||
				!equal((*iter)->codepage_bytes.begin(), (*iter)->codepage_bytes.end(), (*search_iter)->codepage_bytes.begin()))
		{
			iter++;
			continue;
		}

		iter = check->simple_mappings.erase(iter);
	}
}

void Ucm::remove_private_use_fallbacks(void) {
	/* The fallbacks from private-use codepoints are only useful if you have
	   previously converted texts in which the private-use codepoints were actually
	   saved, and then mostly if the use of private-use codepoints is standardized
	   between all converters. The first is something that should not occur because
	   private-use codepoints should not be used without context, and the second is
	   unenforcable. If a unicode codepoint is finally assigned, it should be used
	   in all relevant codepages. */
	if (option_verbose)
		fprintf(stderr, "Removing fallbacks from private-use codepoints\n");
	remove_private_use_fallbacks_internal(this);
	for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
		remove_private_use_fallbacks_internal(*variant_iter);
}

void Ucm::remove_private_use_fallbacks_internal(UcmBase *check) {
	for (vector<Mapping *>::iterator iter = check->simple_mappings.begin(); iter != check->simple_mappings.end(); ) {
		if ((*iter)->precision == 1 && ((*iter)->to_unicode_flags & Mapping::TO_UNICODE_PRIVATE_USE)) {
			iter = check->simple_mappings.erase(iter);
			continue;
		}
		iter++;
	}
}

void Ucm::ensure_ascii_controls(void) {
	Mapping *mapping;
	int mb_min, mb_max;

	if (tag_values[CHARSET_FAMILY].str != NULL && strcmp(tag_values[CHARSET_FAMILY].str, "ASCII") != 0)
		return;

	if (tag_values[SUBCHAR].str != NULL && strcmp(tag_values[SUBCHAR].str, "\\x7F") != 0)
		return;

	mb_max = atoi(tag_values[MB_MAX].str);
	mb_min = atoi(tag_values[MB_MIN].str);

	if (mb_min != 1 || mb_max != 1)
		return;

	if ((mapping = find_mapping_by_codepoint(0x1a, WHERE_MAIN | WHERE_VARIANTS, 1)) == 0 ||
			mapping->codepage_bytes.size() != 1 || mapping->codepage_bytes[0] != 0x7f)
		return;
	if ((mapping = find_mapping_by_codepoint(0x1c, WHERE_MAIN | WHERE_VARIANTS, 1)) == 0 ||
			mapping->codepage_bytes.size() != 1 || mapping->codepage_bytes[0] != 0x1a)
		return;
	if ((mapping = find_mapping_by_codepoint(0x7f, WHERE_MAIN | WHERE_VARIANTS, 1)) == 0 ||
			mapping->codepage_bytes.size() != 1 || mapping->codepage_bytes[0] != 0x1c)
		return;

	fprintf(stderr, "%s: WARNING: correcting IBM specific control code mappings.\n", name);
	for (vector<Mapping *>::const_iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if ((*iter)->codepage_bytes.size() > 1)
			continue;
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

void Ucm::minimize_state_machines(void) {
	StateMachineInfo *info = new CodepageBytesStateMachineInfo(*this);
	minimize_state_machine(info, flags);
	delete info;
	info = new UnicodeStateMachineInfo(*this);
	minimize_state_machine(info, 0);
	delete info;
}


const vector<State *> &Ucm::CodepageBytesStateMachineInfo::get_state_machine(void) {
	return source.codepage_states;
}

void Ucm::CodepageBytesStateMachineInfo::replace_state_machine(vector<State *> &states) {
	for (vector<State *>::const_iterator iter = source.codepage_states.begin();
			iter != source.codepage_states.end(); iter++)
		delete (*iter);

	source.codepage_states = states;
}

bool Ucm::CodepageBytesStateMachineInfo::get_next_byteseq(uint8_t *bytes, size_t &length, action_t &mark_action) {
	vector<Mapping *> *mappings;

	while (1) {
		if (variant_iter != source.variants.end())
			mappings = iterating_simple_mappings ? &(*variant_iter)->simple_mappings : &(*variant_iter)->multi_mappings;
		else
			mappings = iterating_simple_mappings ? &source.simple_mappings : &source.multi_mappings;

		for (; idx < mappings->size(); idx++) {
			if ((*mappings)[idx]->precision != 0 && (*mappings)[idx]->precision != 3)
				continue;
			copy((*mappings)[idx]->codepage_bytes.begin(), (*mappings)[idx]->codepage_bytes.end(), bytes);
			length = (*mappings)[idx]->codepage_bytes.size();
			mark_action = (*mappings)[idx]->precision != 0 || !iterating_simple_mappings || variant_iter != source.variants.end() ||
				((*mappings)[idx]->to_unicode_flags & Mapping::TO_UNICODE_PRIVATE_USE) != 0 ? ACTION_FINAL : ACTION_FINAL_NOFLAGS;
			if (iterating_simple_mappings && (*mappings)[idx]->codepoints[0] > UINT32_C(0xffff))
				mark_action = (action_t) (mark_action | ACTION_FLAG_PAIR);
			idx++;
			return true;
		}
		if (!iterating_simple_mappings) {
			if (variant_iter == source.variants.end())
				return false;
			else
				variant_iter++;
		}
		iterating_simple_mappings = !iterating_simple_mappings;
		idx = 0;
	}
}

double Ucm::CodepageBytesStateMachineInfo::get_single_cost(void) {
	return source.to_flag_costs + 2;
}

bool Ucm::CodepageBytesStateMachineInfo::unassigned_needs_flags(void) {
	return false;
}

const vector<State *> &Ucm::UnicodeStateMachineInfo::get_state_machine(void) {
	return source.unicode_states;
}

void Ucm::UnicodeStateMachineInfo::replace_state_machine(vector<State *> &states) {
	for (vector<State *>::const_iterator iter = source.unicode_states.begin();
			iter != source.unicode_states.end(); iter++)
		delete (*iter);

	source.unicode_states = states;
}

bool Ucm::UnicodeStateMachineInfo::get_next_byteseq(uint8_t *bytes, size_t &length, action_t &mark_action) {
	vector<Mapping *> *mappings;
	uint32_t codepoint;

	while (1) {
		if (variant_iter != source.variants.end())
			mappings = iterating_simple_mappings ? &(*variant_iter)->simple_mappings : &(*variant_iter)->multi_mappings;
		else
			mappings = iterating_simple_mappings ? &source.simple_mappings : &source.multi_mappings;

		for (; idx < mappings->size(); idx++) {
			if (iterating_simple_mappings) {
				if ((*mappings)[idx]->precision == 3)
					continue;
			} else {
				if ((*mappings)[idx]->precision != 0 && (*mappings)[idx]->precision != 1)
					continue;
			}
			codepoint = htonl((*mappings)[idx]->codepoints[0]);
			memcpy(bytes, 1 + (char *) &codepoint, 3);
			length = 3;

			mark_action = (*mappings)[idx]->precision != 0 || !iterating_simple_mappings || variant_iter != source.variants.end() ?
				ACTION_FINAL : (action_t) (ACTION_FINAL_LEN1_NOFLAGS + (*mappings)[idx]->codepage_bytes.size() - 1);

			if (iterating_simple_mappings && (*mappings)[idx]->codepage_bytes.size() > (size_t) source.single_bytes)
				mark_action = (action_t) (mark_action | ACTION_FLAG_PAIR);

			idx++;
			return true;
		}
		if (!iterating_simple_mappings) {
			if (variant_iter == source.variants.end())
				return false;
			else
				variant_iter++;
		}
		iterating_simple_mappings = !iterating_simple_mappings;
		idx = 0;
	}
}

double Ucm::UnicodeStateMachineInfo::get_single_cost(void) {
	return source.from_flag_costs + source.single_bytes;
}

bool Ucm::UnicodeStateMachineInfo::unassigned_needs_flags(void) {
	return true;
}

void Ucm::add_variant(Variant *_variant) {
	for (deque<Variant *>::const_iterator iter = variants.begin(); iter != variants.end(); iter++)
		if (_variant->id == (*iter)->id)
			fatal("%s:%d: Multiple _variants with the same ID specified\n", file_name, line_number);
	variants.push_back(_variant);
}

void Ucm::dump(void) {
	if (tag_values[CODE_SET_NAME].str != NULL)
		printf("<code_set_name>\t\"%s\"\n", tag_values[CODE_SET_NAME].str);
	if (tag_values[UCONV_CLASS].str != NULL)
		printf("<uconv_class>\t\"%s\"\n", tag_values[UCONV_CLASS].str);
	if (tag_values[SUBCHAR].str != NULL)
		printf("<subchar>\t\"%s\"\n", tag_values[SUBCHAR].str);
	if (tag_values[SUBCHAR1].str != NULL)
		printf("<subchar1>\t\"%s\"\n", tag_values[SUBCHAR1].str);
	if (tag_values[MB_MAX].str != NULL)
		printf("<mb_cur_max>\t\"%s\"\n", tag_values[MB_MAX].str);
	if (tag_values[MB_MIN].str != NULL)
		printf("<mb_cur_min>\t\"%s\"\n", tag_values[MB_MIN].str);
	if (tag_values[CHARSET_FAMILY].str != NULL)
		printf("<charset_family>\t\"%s\"\n", tag_values[CHARSET_FAMILY].str);
	if (tag_values[INTERNAL].str != NULL && variants.size() < 2)
		printf("<ltc:internal>\t\"%s\"\n", tag_values[INTERNAL].str);

	sort(simple_mappings.begin(), simple_mappings.end(), compare_codepoints);
	sort(multi_mappings.begin(), multi_mappings.end(), compare_codepoints);
	printf("\nCHARMAP\n");
	for (vector<Mapping *>::const_iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++)
		printf("%s %s |%d\n", sprint_codepoints((*iter)->codepoints), sprint_sequence((*iter)->codepage_bytes), (*iter)->precision);

	for (vector<Mapping *>::const_iterator iter = multi_mappings.begin(); iter != multi_mappings.end(); iter++)
		printf("%s %s |%d\n", sprint_codepoints((*iter)->codepoints), sprint_sequence((*iter)->codepage_bytes), (*iter)->precision);
	printf("END CHARMAP\n");

	for (deque<Variant *>::const_iterator iter = variants.begin(); iter != variants.end(); iter++) {
		printf("\n");
		(*iter)->dump();
	}
}

void Ucm::write_namelist_entries(FILE *output) {
	if (variants.empty()) {
		fprintf(output, "\t\"%s\",\n", variant.id);
	} else {
		for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
			fprintf(output, "\t\"%s\",\n", (*variant_iter)->id);
	}
}

void Ucm::ensure_subchar_mapping(void) {
	Mapping *mapping;
	vector<uint8_t> subchar;

	if (option_verbose)
		fprintf(stderr, "Checking that subchar (and subchar1 if applicable) have round-trip mappings\n");

	// This can only happen if the table is an internal table
	if (tag_values[SUBCHAR].str == NULL)
		return;

	parse_byte_sequence(tag_values[SUBCHAR].str, subchar);
	if ((mapping = find_mapping_by_codepage_bytes(subchar, WHERE_MAIN, 1)) == NULL) {
		if (find_mapping_by_codepage_bytes(subchar, WHERE_VARIANTS, 1) != NULL)
			fatal("%s: Not all variants define the same round-trip mapping for <subchar>\n", name);
		if (find_mapping_by_codepoint(UINT32_C(0xfffd), WHERE_MAIN | WHERE_VARIANTS, 1) != 0)
			fatal("%s: No mapping defined for <subchar> but round-trip replacement character has a mapping defined\n", name);
		if (option_verbose)
			fprintf(stderr, "  Adding mapping from <subchar> to replacement char\n");
		mapping = new Mapping();
		mapping->codepage_bytes.reserve(subchar.size());
		copy(subchar.begin(), subchar.end(), mapping->codepage_bytes.begin());
		mapping->codepoints.push_back(UINT32_C(0xfffd));
	}

	if (tag_values[SUBCHAR1].str == NULL)
		return;

	subchar.clear();

	parse_byte_sequence(tag_values[SUBCHAR1].str, subchar);
	if ((mapping = find_mapping_by_codepage_bytes(subchar, WHERE_MAIN, 1)) == NULL) {
		if (find_mapping_by_codepage_bytes(subchar, WHERE_VARIANTS, 1) != NULL)
			fatal("%s: Not all variants define the same round-trip mapping for <subchar1>\n", name);
		if (find_mapping_by_codepoint(UINT32_C(0xfffd), WHERE_MAIN | WHERE_VARIANTS, 1) != 0)
			fatal("%s: No mapping defined for <subchar1> but replacement character has a round-trip mapping defined\n", name);
		if (option_verbose)
			fprintf(stderr, "  Adding mapping from <subchar1> to replacement char\n");
		mapping = new Mapping();
		mapping->codepage_bytes.reserve(subchar.size());
		copy(subchar.begin(), subchar.end(), mapping->codepage_bytes.begin());
		mapping->codepoints.push_back(UINT32_C(0xfffd));
	}
}

static Mapping *find_mapping_by_codepoint_internal(const vector<Mapping *> &mappings,
		const vector<uint32_t> &codepoints, int precision_types)
{
	for (vector<Mapping *>::const_iterator iter = mappings.begin(); iter != mappings.end(); iter++) {
		if (((1 << (*iter)->precision) & precision_types) && codepoints.size() == (*iter)->codepoints.size() &&
				equal(codepoints.begin(), codepoints.end(), (*iter)->codepoints.begin()))
			return *iter;
	}
	return NULL;
}

Mapping *Ucm::find_mapping_by_codepoints(const vector<uint32_t> &codepoints, int where, int precision_types) {
	Mapping *result;
	if (where & WHERE_MAIN) {
		if ((result = find_mapping_by_codepoint_internal(simple_mappings, codepoints, precision_types)) != NULL)
			return result;
	}

	if (where & WHERE_VARIANTS) {
		for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
			if ((result = find_mapping_by_codepoint_internal((*variant_iter)->simple_mappings,
					codepoints, precision_types)) != NULL)
				return result;
	}
	return NULL;
}

Mapping *Ucm::find_mapping_by_codepoint(uint32_t codepoint, int where, int precision_types) {
	vector<uint32_t> codepoints;
	codepoints.push_back(codepoint);
	return find_mapping_by_codepoints(codepoints, where, precision_types);
}

static Mapping *find_mapping_by_codepage_bytes_internal(const vector<Mapping *> &mappings,
		const vector<uint8_t> &codepage_bytes, int precision_types)
{
	for (vector<Mapping *>::const_iterator iter = mappings.begin(); iter != mappings.end(); iter++) {
		if (((1 << (*iter)->precision) & precision_types) && codepage_bytes.size() == (*iter)->codepage_bytes.size() &&
				equal(codepage_bytes.begin(), codepage_bytes.end(), (*iter)->codepage_bytes.begin()))
			return *iter;
	}
	return NULL;
}

Mapping *Ucm::find_mapping_by_codepage_bytes(const vector<uint8_t> &codepage_bytes, int where, int precision_types) {
	Mapping *result;
	if (where & WHERE_MAIN) {
		if ((result = find_mapping_by_codepage_bytes_internal(simple_mappings, codepage_bytes, precision_types)) != NULL)
			return result;
	}

	if (where & WHERE_VARIANTS) {
		for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
			if ((result = find_mapping_by_codepage_bytes_internal((*variant_iter)->simple_mappings,
					codepage_bytes, precision_types)) != NULL)
				return result;
	}
	return NULL;
}
