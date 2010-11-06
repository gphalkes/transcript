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
#include <cstdlib>
#include <climits>
#include <algorithm>
#include <cstring>
#include "ucm2cct.h"

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
			if (codepage_states[i]->entries[j].next_state >= (int) codepage_states.size())
				fatal("%s: State %zd:%x-%x designates a non-existant state as next state\n", name, i,
					codepage_states[i]->entries[j].low, codepage_states[i]->entries[j].high);

			if (codepage_states[i]->entries[j].action == ACTION_VALID) {
				if (codepage_states[codepage_states[i]->entries[j].next_state]->flags & State::INITIAL)
					fatal("%s: State %d:%x-%x designates an initial state as next state for non-final transition\n",
						name, i, codepage_states[i]->entries[j].low, codepage_states[i]->entries[j].high);
			} else {
				if (!(codepage_states[codepage_states[i]->entries[j].next_state]->flags & State::INITIAL))
					fatal("%s: State %zd:%x-%x designates a non-initial state as next state for final/unassigned/illegal/shift transition\n",
						name, i, codepage_states[i]->entries[j].low, codepage_states[i]->entries[j].high);
			}
		}
	}

	mb_cur_max = atoi(tag_values[MB_MAX]);
	mb_cur_min = atoi(tag_values[MB_MIN]);

	if (mb_cur_max > 4 || mb_cur_max < 1)
		fatal("%s: <mb_cur_max> is out of range\n", name);
	if (mb_cur_min > mb_cur_max || mb_cur_min < 1)
		fatal("%s: <mb_cur_min> is out of range\n", name);

	for (i = 0; i < codepage_states.size(); i++) {
		if (!(codepage_states[i]->flags & State::INITIAL))
			continue;

		for (j = 0; j < codepage_states[i]->entries.size(); j++) {
			int depth = calculate_depth(&codepage_states[i]->entries[j]);
			if (depth > 0 && depth > mb_cur_max)
				fatal("%s: State machine specifies byte sequences longer than <mb_cur_max>\n", name);
			if (depth > 0 && depth < mb_cur_min)
				fatal("%s: State machine specifies byte sequences shorter than <mb_cur_min>\n", name);
		}
	}

	vector<uint8_t> bytes;
	#warning FIXME: line number is not correct at this point, so the error messages generated from the functions below will be confusing.

	parse_byte_sequence(tag_values[SUBCHAR], bytes);
	check_codepage_bytes(bytes);
}


static const int reorder_precision[4] = {0, 2, 3, 1};
static int compare_codepage_bytes_simple(Mapping *a, Mapping *b) {
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

bool compare_codepage_bytes(Mapping *a, Mapping *b) {
	int result = compare_codepage_bytes_simple(a, b);

	if (result == 0)
		return reorder_precision[a->precision] < reorder_precision[b->precision];
	return result < 0;
}

static int compare_codepoints_simple(Mapping *a, Mapping *b) {
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

bool compare_codepoints(Mapping *a, Mapping *b) {
	int result = compare_codepoints_simple(a, b);

	if (result == 0)
		return a->precision < b->precision;
	return result < 0;
}

void Ucm::check_duplicates(vector<Mapping *> &mappings, const char *variant_name) {
	vector<Mapping *>::iterator iter;
	if (mappings.size() != 0) {
		sort(mappings.begin(), mappings.end(), compare_codepoints);
		for (iter = mappings.begin() + 1; iter != mappings.end(); iter++) {
			if (compare_codepoints_simple(*iter, *(iter - 1)) == 0) {
				if ((*iter)->precision > 1 || (*(iter - 1))->precision > 1)
					continue;
				fatal("%s: Duplicate mapping defined for %s%s%s\n", name, sprint_codepoints((*iter)->codepoints),
					variant_name == NULL ? "" : " in variant ", variant_name == NULL ? "" : variant_name);
			}
		}

		sort(mappings.begin(), mappings.end(), compare_codepage_bytes);
		for (iter = mappings.begin() + 1; iter != mappings.end(); iter++) {
			if (compare_codepage_bytes_simple(*iter, *(iter - 1)) == 0) {
				if (reorder_precision[(*iter)->precision] > 1 || reorder_precision[(*(iter - 1))->precision] > 1)
					continue;
				fatal("%s: Duplicate mapping defined for %s%s%s\n", name, sprint_sequence((*iter)->codepage_bytes),
					variant_name == NULL ? "" : " in variant ", variant_name == NULL ? "" : variant_name);
			}
		}
	}
}

void Ucm::check_variant_duplicates(vector<Mapping *> &base_mappings, vector<Mapping *> &variant_mappings, const char *variant_id) {
	/* We use the simple way to check the consistency of the combination: combine and check. */
	vector<Mapping *> combined;

	combined.insert(combined.end(), base_mappings.begin(), base_mappings.end());
	combined.insert(combined.end(), variant_mappings.begin(), variant_mappings.end());
	check_duplicates(combined, variant_id);
}

void Ucm::check_duplicates(void) {
	if (option_verbose)
		fprintf(stderr, "Checking for duplicate mappings\n");
	check_duplicates(simple_mappings, NULL);
	check_duplicates(multi_mappings, NULL);
	for (list<Variant *>::iterator iter = variants.begin(); iter != variants.end(); iter++) {
		check_variant_duplicates(simple_mappings, (*iter)->simple_mappings, (*iter)->id);
		check_variant_duplicates(multi_mappings, (*iter)->multi_mappings, (*iter)->id);
	}
}

void Ucm::find_used_flags(vector<Mapping *> &mappings, int *length_counts) {
	for (vector<Mapping *>::iterator iter = mappings.begin(); iter != mappings.end(); iter++) {
		uint8_t change = from_unicode_flags ^ (*iter)->from_unicode_flags;
		if ((*iter)->from_unicode_flags & Mapping::FROM_UNICODE_SUBCHAR1)
			change &= ~Mapping::FROM_UNICODE_LENGTH_MASK;
		used_from_unicode_flags |= change;

		used_to_unicode_flags |= to_unicode_flags ^ (*iter)->to_unicode_flags;

		if (length_counts != NULL)
			length_counts[(*iter)->codepage_bytes.size() - 1]++;
	}
}

void Ucm::calculate_item_costs(void) {
	from_unicode_flags = simple_mappings[0]->from_unicode_flags;
	to_unicode_flags = simple_mappings[0]->to_unicode_flags;

	int i, j, best_size;
	double size;
	int length_counts[4] = { 0, 0, 0, 0 };

	find_used_flags(simple_mappings, length_counts);
	for (list<Variant *>::iterator iter = variants.begin(); iter != variants.end(); iter++) {
		if ((*iter)->simple_mappings.size() > 0) {
			used_from_unicode_flags |= Mapping::FROM_UNICODE_VARIANT;
			used_to_unicode_flags |= Mapping::TO_UNICODE_VARIANT;
		}
		find_used_flags((*iter)->simple_mappings, NULL);
		used_from_unicode_flags |= (*iter)->used_from_unicode_flags;
		used_to_unicode_flags |= (*iter)->used_to_unicode_flags;
	}

	if (option_verbose)
		fprintf(stderr, "Items to save:\n");

	from_flag_costs = to_flag_costs = 0.0;
	from_flag_costs += 0.25; /* FIXME: when there are no unassigned mappings in the range, and there
		are no FROM_UNICODE_FALLBACK characters, this should be 0. However, we don't know whether there
		are unassigned mappings, because that will be calculated based on the costs calculated here.
		Chicken, egg, etc. */
	from_unicode_flags &= ~(Mapping::FROM_UNICODE_NOT_AVAIL | Mapping::FROM_UNICODE_FALLBACK);
	from_unicode_flags_save = 2;
	if (option_verbose)
		fprintf(stderr, "- from unicode not available/fallback flags\n");
	if (used_from_unicode_flags & (Mapping::FROM_UNICODE_SUBCHAR1 | Mapping::FROM_UNICODE_MULTI_START)) {
		from_flag_costs += 0.25;
		from_unicode_flags &= ~(Mapping::FROM_UNICODE_SUBCHAR1 | Mapping::FROM_UNICODE_MULTI_START);
		from_unicode_flags_save |= 4;
		if (option_verbose)
			fprintf(stderr, "- from unicode M:N mappings/subchar1 flags\n");
	}
	if (used_from_unicode_flags & Mapping::FROM_UNICODE_LENGTH_MASK) {
		from_flag_costs += 0.25;
		from_unicode_flags &= ~Mapping::FROM_UNICODE_LENGTH_MASK;
		from_unicode_flags_save |= 1;
		if (option_verbose)
			fprintf(stderr, "- from unicode length\n");
	}
	if (from_unicode_flags_save == 7)
		from_unicode_flags_save = 15;

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
	if (variants.size() > 1)
		flags |= VARIANTS_AVAILABLE;
}

void Ucm::trace_back(size_t idx, shift_sequence_t &shift_sequence) {
	if (codepage_states[idx]->flags & State::INITIAL) {
		shift_sequence.from_state = idx;
		if (shift_sequence.from_state != shift_sequence.to_state)
			shift_sequences.push_back(shift_sequence);
		return;
	}

	for (size_t i = 0; i != codepage_states.size(); i++) {
		for (vector<Entry>::iterator entry_iter = codepage_states[i]->entries.begin();
				entry_iter != codepage_states[i]->entries.end(); entry_iter++)
		{
			if (entry_iter->action == ACTION_VALID && entry_iter->next_state == (int) idx) {
				shift_sequence.bytes.push_front(entry_iter->low);
				trace_back(i, shift_sequence);
				shift_sequence.bytes.pop_front();
			}
		}
	}
}

void Ucm::find_shift_sequences(void) {
	if (!(flags & MULTIBYTE_START_STATE_1))
		return;

	for (size_t i = 0; i != codepage_states.size(); i++) {
		for (vector<Entry>::iterator entry_iter = codepage_states[i]->entries.begin();
				entry_iter != codepage_states[i]->entries.end(); entry_iter++)
		{
			if (entry_iter->action == ACTION_SHIFT) {
				shift_sequence_t shift_sequence;
				shift_sequence.bytes.push_front(entry_iter->low);
				shift_sequence.to_state = entry_iter->next_state;
				trace_back(i, shift_sequence);
			}
		}
	}
}

void Ucm::check_state_machine(Ucm *other, int this_state, int other_state) {
	vector<Entry>::iterator this_iter = codepage_states[this_state]->entries.begin();
	vector<Entry>::iterator other_iter = other->codepage_states[other_state]->entries.begin();

	while (this_iter != codepage_states[this_state]->entries.end() &&
			other_iter != other->codepage_states[other_state]->entries.end())
	{
		switch (this_iter->action) {
			case ACTION_VALID:
				if (other_iter->action != ACTION_VALID)
					goto not_compat;
				check_state_machine(other, this_iter->next_state, other_iter->next_state);
				break;
			case ACTION_FINAL:
			case ACTION_FINAL_PAIR:
			case ACTION_UNASSIGNED:
				if (other_iter->action != ACTION_FINAL && other_iter->action != ACTION_FINAL_PAIR &&
						other_iter->action != ACTION_UNASSIGNED)
					goto not_compat;
				if (this_iter->next_state != other_iter->next_state)
					goto not_compat;
				break;
			case ACTION_SHIFT:
			case ACTION_ILLEGAL:
				if (other_iter->action != this_iter->action)
					goto not_compat;

				if (this_iter->next_state != other_iter->next_state)
					goto not_compat;
				break;
			default:
				PANIC();
		}

		if (this_iter->high < other_iter->high) {
			this_iter++;
		} else if (this_iter->high > other_iter->high) {
			other_iter++;
		} else {
			this_iter++;
			other_iter++;
		}
	}
	return;

not_compat:
	fatal("%s: State machine in %s is not compatible\n", name, other->name);
}

void Ucm::check_compatibility(Ucm *other) {
	if (uconv_class != other->uconv_class)
		fatal("%s: Convertor in %s has different uconv_class\n", name, other->name);
	if (strcmp(tag_values[MB_MAX], other->tag_values[MB_MAX]) != 0)
		fatal("%s: Convertor in %s has different mb_cur_max\n", name, other->name);
	if (strcmp(tag_values[MB_MIN], other->tag_values[MB_MIN]) != 0)
		fatal("%s: Convertor in %s has different mb_cur_min\n", name, other->name);
	if (flags != other->flags)
		fatal("%s: Convertor in %s is incompatible\n", name, other->name);
	if (strcmp(tag_values[SUBCHAR], other->tag_values[SUBCHAR]) != 0)
		fatal("%s: Convertor in %s has different subchar\n", name, other->name);
	if (tag_values[SUBCHAR1] == NULL) {
		if (other->tag_values[SUBCHAR1] != NULL)
			fatal("%s: Convertor in %s has different subchar1\n", name, other->name);
	} else {
		if (other->tag_values[SUBCHAR1] == NULL || strcmp(tag_values[SUBCHAR1], other->tag_values[SUBCHAR1]) != 0)
			fatal("%s: Convertor in %s has different subchar1\n", name, other->name);
	}

	check_state_machine(other, 0, 0);
	if (flags & MULTIBYTE_START_STATE_1)
		check_state_machine(other, 1, 1);
}


static bool compareMapping(Mapping *a, Mapping *b) {
	int result = compare_codepage_bytes_simple(a, b);

	if (result != 0)
		return result < 0;
	result = compare_codepoints_simple(a, b);
	if (result != 0)
		return result < 0;

	return a->precision < b->precision;
}

void Ucm::prepare_subtract(void) {
	sort(simple_mappings.begin(), simple_mappings.end(), compareMapping);
}

void Ucm::subtract(vector<Mapping *> &this_mappings, vector<Mapping *> &other_mappings,
		vector<Mapping *> &this_variant_mappings)
{
	int bytes_result, codepoints_result;
	vector<Mapping *>::iterator this_iter = this_mappings.begin();
	vector<Mapping *>::iterator other_iter = other_mappings.begin();

	while (this_iter != this_mappings.end() && other_iter != other_mappings.end()) {
		bytes_result = compare_codepage_bytes_simple(*this_iter, *other_iter);
		codepoints_result = compare_codepoints_simple(*this_iter, *other_iter);

		if (bytes_result < 0) {
			this_variant_mappings.push_back(*this_iter);
			this_iter = this_mappings.erase(this_iter);
		} else if (bytes_result > 0) {
			other_iter++;
		} else if (codepoints_result < 0) {
			this_variant_mappings.push_back(*this_iter);
			this_iter = this_mappings.erase(this_iter);
		} else if (codepoints_result > 0) {
			other_iter++;
		} else if ((*this_iter)->precision < (*other_iter)->precision) {
			this_variant_mappings.push_back(*this_iter);
			this_iter = this_mappings.erase(this_iter);
		} else if ((*this_iter)->precision > (*other_iter)->precision) {
			other_iter++;
		} else {
			this_iter++;
			other_iter++;
		}
	}
}

void Ucm::subtract(Ucm *other) {
	subtract(simple_mappings, other->simple_mappings, variant.simple_mappings);
	subtract(multi_mappings, other->multi_mappings, variant.multi_mappings);
}

void Ucm::fixup_variants(void) {
	for (list<Variant *>::iterator iter = variants.begin(); iter != variants.end(); iter++) {
		(*iter)->simple_mappings.insert((*iter)->simple_mappings.end(), variant.simple_mappings.begin(), variant.simple_mappings.end());
		(*iter)->multi_mappings.insert((*iter)->multi_mappings.end(), variant.multi_mappings.begin(), variant.multi_mappings.end());
	}
}

void Ucm::merge_variants(Ucm *other) {
	if (other->variants.size() == 0) {
		variants.push_back(new Variant(other->variant));
		other->variant.simple_mappings.clear();
		other->variant.multi_mappings.clear();
	} else {
		variants.insert(variants.end(), other->variants.begin(), other->variants.end());
		other->variants.clear();
	}
	delete other;
}

void Ucm::variants_done(void) {
	/* Add the local variant, but only if no others are defined. */
	if (variant.simple_mappings.size() == 0 || variant.multi_mappings.size() == 0) {
		if (variants.size() != 0)
			return;
	}
	variants.push_back(new Variant(variant));
	variant.simple_mappings.clear();
	variant.multi_mappings.clear();
}
