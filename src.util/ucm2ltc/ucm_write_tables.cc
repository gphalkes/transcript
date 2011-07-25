/* Copyright (C) 2011 G.P. Halkes
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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <transcript.h>

#include "ucm2ltc.h"

// FIXME: we should really add the size of the different arrays such that we can check whether the
// referenced values are really present! Otherwise we open up a security hole (read-only, but still)!

static int unique;
static char *to_unicode_flags_initializer, *from_unicode_flags_initializer;

static void write_byte_data(FILE *output, uint8_t *data, size_t size, int indent_level) {
	static const char tabs[] = "\t\t\t\t\t\t\t\t";
	size_t i;

	for (i = 0; i < size; i++) {
		if ((i & 0xf) == 0) {
			if (i != 0)
				fprintf(output, ",\n");
			fprintf(output, "%.*s", indent_level, tabs);
		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "0x%02x", data[i]);
	}
}

static void write_word_data(FILE *output, uint16_t *data, size_t size, int indent_level) {
	static const char tabs[] = "\t\t\t\t\t\t\t\t";
	size_t i;

	for (i = 0; i < size; i++) {
		if ((i & 0x7) == 0) {
			if (i != 0)
				fprintf(output, ",\n");
			fprintf(output, "%.*s", indent_level, tabs);
		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "0x%04x", data[i]);
	}
}

void Ucm::write_entries(FILE *output, vector<State *> &states, unsigned int &total_entries) {
	int action_mask;

	for (vector<State *>::const_iterator state_iter = states.begin(); state_iter != states.end(); state_iter++) {
		(*state_iter)->entries_start = total_entries;
		for (vector<Entry>::const_iterator entry_iter = (*state_iter)->entries.begin();
				entry_iter != (*state_iter)->entries.end(); entry_iter++)
		{
			if (total_entries != 0)
				fprintf(output, ",\n");

			action_mask = (entry_iter->action & ACTION_FLAG_PAIR) && entry_iter->action != ACTION_FINAL_PAIR_NOFLAGS ?
				ACTION_FLAG_PAIR : 0;

			fprintf(output, "\t{ UINT16_C(0x%08x), UINT16_C(0x%08x), 0x%02x, 0x%02x, 0x%02x }",
				entry_iter->base, entry_iter->mul, entry_iter->low, entry_iter->next_state,
					entry_iter->action & ~action_mask);
			total_entries++;
		}
	}
}

void Ucm::write_states(FILE *output, vector<State *> &states, const char *converter_name) {
	vector<Entry>::const_iterator entry_iter;

	fprintf(output, "static const state_v1_t %s_states_%d[] = {\n", converter_name, unique);
	for (vector<State *>::const_iterator state_iter = states.begin(); state_iter != states.end(); state_iter++) {
		if (state_iter != states.begin())
			fprintf(output, ",\n");
		fprintf(output, "\t{ entries_%d + %d, UINT16_C(0x%08x), {\n", unique, (*state_iter)->entries_start, (*state_iter)->base);
		entry_iter = (*state_iter)->entries.begin();
		for (int i = 0, entry_nr = 0; i < 256; i++) {
			if ((i & 0xf) == 0) {
				if (i != 0)
					fprintf(output, ",\n");
				fprintf(output, "\t\t");
			} else {
				fprintf(output, ", ");
			}
			fprintf(output, "0x%02x", entry_nr);
			if (i == entry_iter->high) {
				entry_iter++;
				entry_nr++;
			}
		}
		fprintf(output, " }}");
	}
	fprintf(output, "\n};\n\n");
}

void Ucm::write_multi_mappings(FILE *output, vector<Mapping *> &mappings, unsigned int &mapping_idx) {
	static const int precision_to_multi_flag[4] = { 0, 1, 0, 2 };

	for (vector<Mapping *>::const_iterator mapping_iter = mappings.begin(); mapping_iter != mappings.end(); mapping_iter++) {
		if (mapping_idx != 0)
			fprintf(output, ",\n");
		(*mapping_iter)->idx = mapping_idx++;
		fprintf(output, "\t{{ ");
		for (vector<uint32_t>::const_iterator codepoint_iter = (*mapping_iter)->codepoints.begin();
				codepoint_iter != (*mapping_iter)->codepoints.end(); codepoint_iter++)
		{
			if (codepoint_iter != (*mapping_iter)->codepoints.begin())
				fprintf(output, ", ");

			if (*codepoint_iter >= UINT32_C(0x10000)) {
				fprintf(output, "0x%04x, 0x%04x", UINT32_C(0xd800) + ((*codepoint_iter - 0x10000) >> 10),
					UINT32_C(0xdc00) + ((*codepoint_iter - 0x10000) & 0x3ff));
			} else {
				fprintf(output, "0x%04x", *codepoint_iter);
			}
		}
		fprintf(output, " },\n\t\t{ ");
		for (vector<uint8_t>::const_iterator byte_iter = (*mapping_iter)->codepage_bytes.begin();
				byte_iter != (*mapping_iter)->codepage_bytes.end(); byte_iter++)
		{
			if (byte_iter != (*mapping_iter)->codepage_bytes.begin())
				fprintf(output, ", ");
			fprintf(output, "0x%02x", *byte_iter);
		}
		fprintf(output, " },\n\t\t%d, %d, %d }", (int) (*mapping_iter)->codepoints.size(),
			(int) (*mapping_iter)->codepage_bytes.size(),
			precision_to_multi_flag[(*mapping_iter)->precision]);
	}
}

static int compare_multi_mapping_codepage(const Mapping **a, const Mapping **b) {
	if ((*a)->codepage_bytes.size() < (*b)->codepage_bytes.size())
		return 1;
	if ((*a)->codepage_bytes.size() > (*b)->codepage_bytes.size())
		return -1;
	return 0;
}

static int compare_multi_mapping_codepoints(const Mapping **a, const Mapping **b) {
	vector<uint32_t>::const_iterator end_iter = (*a)->codepoints.begin() + min((*a)->codepoints.size(), (*b)->codepoints.size());
	pair<vector<uint32_t>::const_iterator, vector<uint32_t>::const_iterator> diff =
		mismatch((*a)->codepoints.begin(), end_iter,
			(*b)->codepoints.begin());
	if (diff.first == end_iter) {
		if ((*a)->codepoints.size() < (*b)->codepoints.size())
			return 1;
		if ((*a)->codepoints.size() > (*b)->codepoints.size())
			return -1;
	} else {
		return *diff.first < *diff.second ? 1 : -1;
	}
	return 0;
}

typedef int (*compare_fn)(const void *, const void *);

void Ucm::write_sorted_multi_mappings(FILE *output, int variant_nr) {
	vector<Mapping *>::const_iterator mapping_iter;
	Mapping **sorted_multi_mappings;
	unsigned int idx = 0, i;

	if (multi_mappings.size() == 0 && variant_nr < 0) {
		fprintf(output, "static const multi_mapping_v1_t * const codepoint_sorted_multi_mappings_%d[] = { NULL };\n", unique);
		fprintf(output, "static const multi_mapping_v1_t * const codepage_sorted_multi_mappings_%d[] = { NULL };\n", unique);
		return;
	}

	if (variant_nr >= 0 && variants[variant_nr]->multi_mappings.size() == 0)
		return;

	if (variant_nr < 0)
		sorted_multi_mappings = (Mapping **) safe_malloc(sizeof(Mapping *) * multi_mappings.size());
	else
		sorted_multi_mappings = (Mapping **) safe_malloc(sizeof(Mapping *) *
			(multi_mappings.size() + variants[variant_nr]->multi_mappings.size()));

	for (mapping_iter = multi_mappings.begin(); mapping_iter != multi_mappings.end(); mapping_iter++)
		sorted_multi_mappings[idx++] = *mapping_iter;

	if (variant_nr >= 0) {
		for (mapping_iter = variants[variant_nr]->multi_mappings.begin();
				mapping_iter != variants[variant_nr]->multi_mappings.end(); mapping_iter++)
			sorted_multi_mappings[idx++] = *mapping_iter;
	}

	qsort(sorted_multi_mappings, idx, sizeof(Mapping *), (compare_fn) compare_multi_mapping_codepoints);

	if (variant_nr < 0)
		fprintf(output, "static const multi_mapping_v1_t * const codepoint_sorted_multi_mappings_%d[] = {\n", unique);
	else
		fprintf(output, "static const multi_mapping_v1_t * const variant%d_codepoint_sorted_multi_mappings_%d[] = {\n",
			variant_nr, unique);

	for (i = 0; i < idx; i++) {
		if ((i & 0x3) == 0) {

			if (i != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t");

		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "multi_mappings_%d + %d", unique, sorted_multi_mappings[i]->idx);
	}
	fprintf(output, "\n};\n\n");

	qsort(sorted_multi_mappings, idx, sizeof(Mapping *), (compare_fn) compare_multi_mapping_codepage);

	if (variant_nr < 0)
		fprintf(output, "static const multi_mapping_v1_t * const codepage_sorted_multi_mappings_%d[] = {\n", unique);
	else
		fprintf(output, "static const multi_mapping_v1_t * const variant%d_codepage_sorted_multi_mappings_%d[] = {\n",
			variant_nr, unique);

	for (i = 0; i < idx; i++) {
		if ((i & 0x3) == 0) {

			if (i != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t");

		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "multi_mappings_%d + %d", unique, sorted_multi_mappings[i]->idx);
	}
	fprintf(output, "\n};\n\n");
	free(sorted_multi_mappings);
}

void Ucm::write_to_unicode_table(FILE *output) {
	uint16_t *codepoints;
	uint8_t buffer[32];
	uint32_t idx;

	codepoints = (uint16_t *) safe_malloc(codepage_range * sizeof(uint16_t));
	memset(codepoints, 0xff, codepage_range * sizeof(uint16_t));

	for (vector<Mapping *>::const_iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
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

	fprintf(output, "static const uint16_t codepage_mappings_%d[] = {\n", unique);
	write_word_data(output, codepoints, codepage_range, 1);
	fprintf(output, "\n};\n\n");
	free(codepoints);
}

void Ucm::write_from_unicode_table(FILE *output) {
	uint8_t *codepage_bytes;
	uint32_t idx, codepoint;

	codepage_bytes = (uint8_t *) safe_malloc(unicode_range * single_bytes);
	memset(codepage_bytes, 0x00, unicode_range * single_bytes);

	for (vector<Mapping *>::const_iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if ((*iter)->precision != 0 && (*iter)->precision != 1)
			continue;

		codepoint = htonl((*iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		copy((*iter)->codepage_bytes.begin(), (*iter)->codepage_bytes.end(), codepage_bytes + idx * single_bytes);
	}

	fprintf(output, "static const uint8_t unicode_mappings_%d[] = {\n", unique);
	write_byte_data(output, codepage_bytes, unicode_range * single_bytes, 1);
	fprintf(output, "\n};\n\n");
	free(codepage_bytes);
}

void Variant::write_simple_mappings(FILE *output, int variant_nr) {
	sort_simple_mappings();
	fprintf(output, "static const variant_mapping_v1_t variant%d_mappings_%d[] = {\n", variant_nr, unique);
	for (vector<Mapping *>::const_iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if (iter != simple_mappings.begin())
			fprintf(output, ",\n");
		fprintf(output, "\t{ UINT32_C(0x%08x), { ", (*iter)->codepoints[0]);
		for (vector<uint8_t>::const_iterator byte_iter = (*iter)->codepage_bytes.begin();
				byte_iter != (*iter)->codepage_bytes.end(); byte_iter++)
		{
			if (byte_iter != (*iter)->codepage_bytes.begin())
				fprintf(output, ", ");
			fprintf(output, "0x%02x", *byte_iter);
		}
		fprintf(output, " }, 0x%04x, 0x%02x, 0x%02x }", (*iter)->idx, (*iter)->from_unicode_flags, (*iter)->to_unicode_flags);
	}
	fprintf(output, "\n};\n\n");
}

static void fill_conversion_table(uint8_t *table, int mask) {
	int entry;
	int i, j, k;

	for (i = 0; i < 256; i++) {
		entry = 0;
		if ((i & mask) == i) {
			for (j = 0, k = 0; j < 8; j++) {
				if (!(mask & (1 << j)))
					continue;

				if (i & (1 << j))
					entry |= (1 << k);
				k++;
			}
		}
		table[i] = entry;
	}
}

#define BLOCKSIZE 16
static const char *merge_and_write_flags(FILE *output, uint8_t *data, uint32_t range, uint8_t used_flags,
		uint8_t default_flags, const char *name)
{
	static char result[1024];
	static uint8_t conversion_table[256];
	size_t store_idx = 0;
	uint8_t byte, mask;
	uint32_t i;
	int j, bits;
	uint16_t *indices;
	uint8_t *blocks;
	uint32_t nr_of_blocks;
	int saved_blocks = 0;
	uint8_t flag_code;

	/*
		- create mask
		- create convertion table
		- store bytes
	*/
	mask = create_mask(used_flags);
	bits = popcount(mask);
	fill_conversion_table(conversion_table, mask);
	ASSERT(bits == 1 || bits == 2 || bits == 4 || bits == 8);

	for (i = 0; i < range; ) {
		byte = 0;
		for (j = 0; j < (8 / bits); j++)
			byte |= conversion_table[data[i++] & used_flags] << (bits * j);
		data[store_idx++] = byte;
	}

	nr_of_blocks = (store_idx + BLOCKSIZE - 1) / BLOCKSIZE;
	indices = (uint16_t *) safe_malloc(nr_of_blocks * 2);
	blocks = (uint8_t *) safe_malloc(nr_of_blocks * BLOCKSIZE);

	// Ensure that the last block is filled up with 0 bytes
	memset(data + store_idx, 0, nr_of_blocks * BLOCKSIZE - store_idx);

	// Find all unique blocks.
	for (i = 0; i < nr_of_blocks; i++) {
		for (j = 0; j < saved_blocks; j++) {
			if (memcmp(data + i * BLOCKSIZE, blocks + j * BLOCKSIZE, BLOCKSIZE) == 0)
				break;
		}
		indices[i] = j;
		if (j >= saved_blocks) {
			memcpy(blocks + saved_blocks * BLOCKSIZE, data + i * BLOCKSIZE, BLOCKSIZE);
			saved_blocks++;
		}
	}

	if (option_verbose)
		fprintf(stderr, "Trie size: %d, flat table size: %zd\n", nr_of_blocks * 2 + saved_blocks * BLOCKSIZE, store_idx);

	switch (bits) {
		case 8:
			flag_code = 0;
			break;
		case 4:
			flag_code = 1;
			break;
		case 2:
			flag_code = 71;
			break;
		case 1:
			flag_code = 99;
			break;
		default:
			PANIC();
	}


	for (i = 0; i < 256; i++) {
		if (i == mask)
			break;
		if (popcount(i) == bits)
			flag_code++;
	}

	if (nr_of_blocks * 2 + saved_blocks * BLOCKSIZE > store_idx) {
		fprintf(output, "static const uint8_t %s_unicode_flags_bytes_%d[] = {\n", name, unique);
		write_byte_data(output, data, store_idx, 1);
		fprintf(output, "\n};\n\n");
		snprintf(result, sizeof(result), "{ %s_unicode_flags_bytes_%d, NULL, 0x%02x, 0x%02x }",
			name, unique, default_flags, flag_code);
	} else {
		fprintf(output, "static const uint8_t %s_unicode_flags_bytes_%d[] = {\n", name, unique);
		write_byte_data(output, blocks, saved_blocks * BLOCKSIZE, 1);
		fprintf(output, "\n};\n\n");
		fprintf(output, "static const uint16_t %s_unicode_flags_indices_%d[] = {\n", name, unique);
		write_word_data(output, indices, nr_of_blocks, 1);
		fprintf(output, "\n};\n\n");

		snprintf(result, sizeof(result), "{ %s_unicode_flags_bytes_%d, %s_unicode_flags_indices_%d, 0x%02x, 0x%02x }",
			name, unique, name, unique, default_flags, flag_code | 0x80);
	}
	free(indices);
	free(blocks);
	return result;
}

void Ucm::write_to_unicode_flags(FILE *output) {
	uint32_t idx;
	uint8_t buffer[32];
	uint8_t *save_flags;
	vector<Mapping *>::const_iterator mapping_iter;

	save_flags = (uint8_t *) safe_malloc(codepage_range + BLOCKSIZE - 1);
	memset(save_flags, 0, codepage_range + BLOCKSIZE - 1);

	for (mapping_iter = simple_mappings.begin(); mapping_iter != simple_mappings.end(); mapping_iter++) {
		if ((*mapping_iter)->precision == 1 || (*mapping_iter)->precision == 2)
			continue;

		copy((*mapping_iter)->codepage_bytes.begin(), (*mapping_iter)->codepage_bytes.end(), buffer);
		idx = map_charseq(codepage_states, buffer, (*mapping_iter)->codepage_bytes.size(), flags);
		save_flags[idx] = (*mapping_iter)->to_unicode_flags;
	}

	for (mapping_iter = multi_mappings.begin(); mapping_iter != multi_mappings.end(); mapping_iter++) {
		copy((*mapping_iter)->codepage_bytes.begin(), (*mapping_iter)->codepage_bytes.end(), buffer);
		idx = map_charseq(codepage_states, buffer, (*mapping_iter)->codepage_bytes.size(), flags);
		save_flags[idx] |= Mapping::TO_UNICODE_MULTI_START;
	}

	for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++) {
		for (mapping_iter = (*variant_iter)->simple_mappings.begin();
				mapping_iter != (*variant_iter)->simple_mappings.end(); mapping_iter++)
		{
			if ((*mapping_iter)->precision != 0 && (*mapping_iter)->precision != 3)
				continue;

			copy((*mapping_iter)->codepage_bytes.begin(), (*mapping_iter)->codepage_bytes.end(), buffer);
			idx = map_charseq(codepage_states, buffer, (*mapping_iter)->codepage_bytes.size(), flags);
			save_flags[idx] |= Mapping::TO_UNICODE_VARIANT;
		}

		for (mapping_iter = (*variant_iter)->multi_mappings.begin();
				mapping_iter != (*variant_iter)->multi_mappings.end(); mapping_iter++)
		{
			if ((*mapping_iter)->precision != 0 && (*mapping_iter)->precision != 3)
				continue;
			copy((*mapping_iter)->codepage_bytes.begin(), (*mapping_iter)->codepage_bytes.end(), buffer);
			idx = map_charseq(codepage_states, buffer, (*mapping_iter)->codepage_bytes.size(), flags);
			save_flags[idx] |= Mapping::TO_UNICODE_MULTI_START;
		}
	}

	to_unicode_flags_initializer = safe_strdup(merge_and_write_flags(output, save_flags, codepage_range,
		used_to_unicode_flags, to_unicode_flags, "to"));
	free(save_flags);
}

void Ucm::write_from_unicode_flags(FILE *output) {
	uint32_t idx, codepoint;
	uint8_t *save_flags;
	vector<Mapping *>::const_iterator mapping_iter;

	save_flags = (uint8_t *) safe_malloc(unicode_range + BLOCKSIZE - 1);
	memset(save_flags, Mapping::FROM_UNICODE_NOT_AVAIL, unicode_range + BLOCKSIZE - 1);

	for (mapping_iter = simple_mappings.begin(); mapping_iter != simple_mappings.end(); mapping_iter++) {
		if ((*mapping_iter)->precision == 3)
			continue;

		codepoint = htonl((*mapping_iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		save_flags[idx] &= ~Mapping::FROM_UNICODE_NOT_AVAIL;
		save_flags[idx] |= (*mapping_iter)->from_unicode_flags;
	}

	for (mapping_iter = multi_mappings.begin(); mapping_iter != multi_mappings.end(); mapping_iter++) {
		codepoint = htonl((*mapping_iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		save_flags[idx] |= Mapping::FROM_UNICODE_MULTI_START;
	}

	for (deque<Variant *>::const_iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++) {
		for (mapping_iter = (*variant_iter)->simple_mappings.begin();
				mapping_iter != (*variant_iter)->simple_mappings.end(); mapping_iter++)
		{
			if ((*mapping_iter)->precision == 3)
				continue;

			codepoint = htonl((*mapping_iter)->codepoints[0]);
			idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
			if (!(save_flags[idx] & Mapping::FROM_UNICODE_NOT_AVAIL))
				PANIC();
			save_flags[idx] |= Mapping::FROM_UNICODE_VARIANT;
		}

		for (mapping_iter = (*variant_iter)->multi_mappings.begin();
				mapping_iter != (*variant_iter)->multi_mappings.end(); mapping_iter++)
		{
			if ((*mapping_iter)->precision != 0 && (*mapping_iter)->precision != 1)
				continue;
			codepoint = htonl((*mapping_iter)->codepoints[0]);
			idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
			save_flags[idx] |= Mapping::FROM_UNICODE_MULTI_START;
		}
	}
	from_unicode_flags_initializer = safe_strdup(merge_and_write_flags(output, save_flags, unicode_range,
		used_from_unicode_flags, from_unicode_flags, "from"));
	free(save_flags);
}
#undef BLOCKSIZE

void Ucm::write_interface(FILE *output, const char *normalized_name, int variant_nr) {
	fprintf(output, "TRANSCRIPT_EXPORT int transcript_get_iface_%s(void) { return TRANSCRIPT_STATE_TABLE_V1; }\n", normalized_name);
	fprintf(output, "TRANSCRIPT_EXPORT const converter_tables_v1_t *transcript_get_table_%s(void) {\n", normalized_name);
	fprintf(output, "\tstatic const converter_tables_v1_t _converter = {\n");
	fprintf(output, "\t\t&converter_%d, ", unique);
	if (variant_nr < 0)
		fprintf(output, "NULL,\n");
	else
		fprintf(output, "variants_%d + %d,\n", unique, variant_nr);

	if (variant_nr < 0 || variants[variant_nr]->multi_mappings.size() == 0) {
		if (multi_mappings.empty()) {
			fprintf(output, "\t\tNULL, NULL, ");
		} else {
			fprintf(output, "\t\tcodepage_sorted_multi_mappings_%d, codepoint_sorted_multi_mappings_%d, ", unique, unique);
		}
	} else {
		fprintf(output, "\t\tvariant%d_codepage_sorted_multi_mappings_%d,\n", variant_nr, unique);
		fprintf(output, "\t\tvariant%d_codepoint_sorted_multi_mappings_%d, ", variant_nr, unique);
	}
	fprintf(output, "%d\n\t};\n", (int) multi_mappings.size() +
		(variant_nr < 0 ? 0 : (int) variants[variant_nr]->multi_mappings.size()));
	fprintf(output, "\treturn &_converter;\n}\n\n");
}

void Ucm::write_table(FILE *output) {
	deque<Variant *>::const_iterator variant_iter;
	unsigned int count;
	size_t i;
	char normalized_name[160];

	/* Make sure the variables for this converter are unique */
	unique++;

	/* Write all entries into a single array. */
	fprintf(output, "static const entry_v1_t entries_%d[] = {\n", unique);
	count = 0;
	write_entries(output, codepage_states, count);
	write_entries(output, unicode_states, count);
	fprintf(output, "\n};\n\n");

	/* Write state arrays. */
	write_states(output, codepage_states, "codepage");
	write_states(output, unicode_states, "unicode");

	/* Write shift sequences. */
	if (shift_sequences.size() > 0) {
		fprintf(output, "static const shift_state_v1_t shift_states_%d[] = {\n", unique);
		for (vector<shift_sequence_t>::const_iterator shift_iter = shift_sequences.begin();
				shift_iter != shift_sequences.end(); shift_iter++)
		{
			if (shift_iter != shift_sequences.begin())
				fprintf(output, ",\n");
			fprintf(output, "\t{ { 0x%02x", shift_iter->bytes[0]);
			for (i = 1; i < shift_iter->bytes.size(); i++)
				fprintf(output, ", 0x%02x", shift_iter->bytes[i]);
			fprintf(output, " }, 0x%02x, 0x%02x, 0x%02x }", shift_iter->from_state, shift_iter->to_state, (int) shift_iter->bytes.size());
		}
		fprintf(output, "\n};\n\n");
	}

	/* Write the simple mapping tables. */
	write_to_unicode_table(output);
	write_from_unicode_table(output);

	/* Write all multi mappings in a single table (that is including the ones from
	   the variants). We have to include sorted lists anyway, so the sorted lists
	   will be built such that they only include the correct items. */
	bool has_multi_mappings = !multi_mappings.empty();
	for (variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
		has_multi_mappings |= !(*variant_iter)->multi_mappings.empty();

	if (has_multi_mappings) {
		fprintf(output, "static const multi_mapping_v1_t multi_mappings_%d[] = {\n", unique);
		count = 0;
		write_multi_mappings(output, multi_mappings, count);
		for (variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++)
			write_multi_mappings(output, (*variant_iter)->multi_mappings, count);
		fprintf(output, "\n};\n\n");
		write_sorted_multi_mappings(output, -1);
		for (variant_iter = variants.begin(), count = 0; variant_iter != variants.end(); variant_iter++, count++)
			write_sorted_multi_mappings(output, count);
	}

	/* Write variant simple mappings. */
	for (variant_iter = variants.begin(), count = 0; variant_iter != variants.end(); variant_iter++, count++)
		(*variant_iter)->write_simple_mappings(output, count);

	/* Write variants table. */
	if (!variants.empty()) {
		fprintf(output, "static const variant_v1_t variants_%d[] = {\n", unique);
		for (variant_iter = variants.begin(), count = 0; variant_iter != variants.end(); variant_iter++, count++) {
			if (count != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t{ variant%d_mappings_%d, 0x%04x, 0x%04x }",
				count, unique, (int) (*variant_iter)->simple_mappings.size(), (*variant_iter)->flags);
		}
		fprintf(output, "\n};\n\n");
	}

	/* Write flags, if necessary. */
	if (used_to_unicode_flags != 0)
		write_to_unicode_flags(output);
	if (used_from_unicode_flags != 0)
		write_from_unicode_flags(output);

	fprintf(output, "static const converter_v1_t converter_%d = {\n", unique);
	fprintf(output, "\tcodepage_states_%d, unicode_states_%d, ", unique, unique);
	if (shift_sequences.empty())
		fprintf(output, "NULL, ");
	else
		fprintf(output, "shift_states_%d, ", unique);
	fprintf(output, "codepage_mappings_%d, unicode_mappings_%d,\n", unique, unique);
	fprintf(output, "\t%s,\n", to_unicode_flags_initializer == NULL ? "{ NULL, NULL, 0, 0 }" : to_unicode_flags_initializer);
	fprintf(output, "\t%s,\n", from_unicode_flags_initializer == NULL ? "{ NULL, NULL, 0, 0 }" : from_unicode_flags_initializer);
	fprintf(output, "\t{ ");
	vector<uint8_t> subchar;
	if (tag_values[Ucm::SUBCHAR].str == NULL)
		subchar.push_back(0);
	else
		parse_byte_sequence(tag_values[Ucm::SUBCHAR].str, subchar);
	for (i = 0; i < subchar.size(); i++) {
		if (i != 0)
			fprintf(output, ", ");
		fprintf(output, "0x%02x", subchar[i]);
	}
	fprintf(output, " },\n");
	fprintf(output, "\t0x%04x, 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", flags, (int) subchar.size(),
		(int) (tag_values[Ucm::SUBCHAR1].str != NULL ? strtol(tag_values[Ucm::SUBCHAR1].str + 2, NULL, 16) : 0),
		(int) shift_sequences.size(), single_bytes);
	fprintf(output, "};\n\n");

	if (variants.empty()) {
		transcript_normalize_name(variant.id, normalized_name, sizeof(normalized_name));
		write_interface(output, normalized_name, -1);
	} else {
		for (variant_iter = variants.begin(), count = 0; variant_iter != variants.end(); variant_iter++, count++) {
			transcript_normalize_name((*variant_iter)->id, normalized_name, sizeof(normalized_name));
			write_interface(output, normalized_name, count);
		}
	}
}
