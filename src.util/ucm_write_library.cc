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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>

#include "ucm2cct.h"

/*
typedef struct convertor_t {
	entry_t *entries; //done
	state_t *codepage_states; //done
	state_t *unicode_states; //done
	shift_state_t *shift_states; //done

	uint16_t *codepage_mappings; //done
	uint8_t *unicode_mappings; //done
	multi_mapping_t *multi_mappings; //done
	multi_mapping_t **codepage_sorted_multi_mappings; //done
	multi_mapping_t **codepoint_sorted_multi_mappings; //done

	variant_t *variants;

	uint32_t nr_multi_mappings;
	uint16_t nr_variants;

	uint16_t flags;

	uint8_t subchar_len;
	uint8_t subchar[MAX_CHAR_BYTES];
	uint8_t subchar1;
	uint8_t nr_shift_states;
	uint8_t single_size;
	flags_t codepage_flags;
	flags_t unicode_flags;
} convertor_t;

typedef struct {
	variant_mapping_t *simple_mappings;
	multi_mapping_t **codepage_sorted_multi_mappings; //done
	multi_mapping_t **codepoint_sorted_multi_mappings; //done
	char *id;
	uint8_t flags;
} variant_t;

typedef struct {
	uint32_t codepoint;
	char codepage_bytes[4];
	uint16_t sort_idx;
	uint8_t from_unicode_flags;
	uint8_t to_unicode_flags;
} variant_mapping_t;

typedef struct flags_t {
	uint8_t *flags;
	uint16_t *indices;
	uint8_t default_flags;
	uint8_t flags_type;
} flags_t;


//========= DONE ==========
typedef struct {
	uint8_t bytes[MAX_CHAR_BYTES];
	uint8_t len;
	uint8_t from_state;
	uint8_t to_state;
} shift_state_t;

typedef struct {
	uint16_t codepoints[19];
	uint8_t bytes[31];
	uint8_t codepoints_length;
	uint8_t bytes_length;
} multi_mapping_t;

*/
//static
void Ucm::write_entries(FILE *output, vector<State *> &states, unsigned int &total_entries) {
	for (vector<State *>::iterator state_iter = states.begin(); state_iter != states.end(); state_iter++) {
		state_iter->entries_start = total_entries;
		for (vector<Entry>::iterator entry_iter = (*state_iter)->entries.begin();
				entry_iter != (*state_iter)->entries.end(); entry_iter++)
		{
			if (total_entries != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t{ UINT32_C(0x%08x), UINT32_C(0x%08x), 0x%02x, 0x%02x, 0x%02x }",
				entry_iter->base, entry_iter->mul, entry_iter->low, entry_iter->next_state, entry_iter->action);
			total_entries++;
		}
	}
}
//static
void Ucm::write_states(FILE *output, vector<State *> &states, const char *name) {
	vector<Entry>::iterator entry_iter;

	fprintf(output, "static const state_t %s_states[] = {\n", name);
	for (vector<State *>::iterator state_iter = states.begin(); state_iter != states.end(); state_iter++) {
		if (state_iter != states.begin())
			fprintf(output, ",\n");
		fprintf(output, "\t{ entries + %d, UINT32_C(0x%08x), {\n", (*state_iter)->entries_start, (*state_iter)->base);
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

//static
void Ucm::write_multi_mappings(FILE *output, vector<Mapping *> &mappings, unsigned int &mapping_idx) {
	for (vector<Mapping *> mapping_iter = mappings.begin(); mapping_iter != multi_mappings.end(); mapping_iter++) {
		if (mapping_idx != 0)
			fprintf(output, ",\n");
		mapping_iter->idx = mapping_idx++;
		fprintf(output, "\t{{ ");
		for (vector<uint32_t>::iterator codepoint_iter = (*mapping_iter)->codepoints.begin();
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
		for (vector<uint8_t>::iterator byte_iter = (*mapping_iter)->codepage_bytes.begin();
				byte_iter != (*mapping_iter)->codepage_bytes.end(); byte_iter++)
		{
			if (byte_iter != (*mapping_iter)->codepage_bytes.begin())
				fprintf(output, ", ");
			fprintf(output, "0x%02x", *byte_iter);
		}
		fprintf(output, " },\n\t\t%d, %d }", (*mapping_iter)->codepoints.size(), (*mapping_iter)->codepage_bytes.size());
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
	if ((*a)->codepoints.size() < (*b)->codepoints.size())
		return 1;
	if ((*a)->codepoints.size() > (*b)->codepoints.size())
		return -1;
	return 0;
}

typedef int (*compare_fn)(const void *, const void *);

void Ucm::write_sorted_multi_mappings(FILE *output, int variant_nr) {
	vector<Mapping *>::iterator mapping_iter;
	Mapping **sorted_multi_mappings;
	unsigned int idx = 0;

	if ((multi_mappings.size() == 0 && variant_nr < 0) || (variant_nr >= 0 &&
			variants[variant_nr]->multi_mappings.size() == 0))
		return;

	if (variant_nr < 0)
		sorted_multi_mappings = malloc(sizeof(Mapping *) * multi_mappings.size());
	else
		sorted_multi_mappings = malloc(sizeof(Mapping *) *
			(multi_mappings.size() + variants[variant_nr]->multi_mappings.size()));

	if (sorted_multi_mappings == NULL)
		OOM();

	for (mapping_iter = multi_mappings.begin(); mapping_iter != multi_mappings.end(); mapping_iter++)
		sorted_multi_mappings[idx++] = *mapping_iter;

	if (variant_nr >= 0) {
		for (mapping_iter = variants[variant_nr]->multi_mappings.begin();
				mapping_iter != variants[variant_nr]->multi_mappings.end(); mapping_iter++)
			sorted_multi_mappings[idx++] = *mapping_iter;
	}

	qsort(sorted_multi_mappings, idx, sizeof(Mapping *), (compare_fn) compare_multi_mapping_codepoints);

	if (variant_nr < 0)
		fprintf(output, "static const multi_mapping_t *unicode_sorted_multi_mappings[] = {\n");
	else
		fprintf(output, "static const multi_mapping_t *variant%d_unicode_sorted_multi_mappings[] = {\n", variant_nr);

	for (i = 0; i < idx; i++) {
		if ((i & 0x3) == 0) {

			if (i != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t");

		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "multi_mappings + %d", sorted_multi_mappings[i]->idx);
	}
	fprintf(output, "\n};\n\n");

	qsort(sorted_multi_mappings, idx, sizeof(Mapping *), (compare_fn) compare_multi_mapping_codepage);

	if (variant_nr < 0)
		fprintf(output, "static const multi_mapping_t *codepage_sorted_multi_mappings[] = {\n");
	else
		fprintf(output, "static const multi_mapping_t *variant%d_codepage_sorted_multi_mappings[] = {\n", variant_nr);

	for (i = 0; i < idx; i++) {
		if ((i & 0x3) == 0) {

			if (i != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t");

		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "multi_mappings + %d", sorted_multi_mappings[i]->idx);
	}
	fprintf(output, "\n};\n\n");
	free(sorted_multi_mappings);
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

	fprintf(output, "static const uint16_t codepage_mappings[] = {\n");
	for (idx = 0; idx < codepage_range; idx++) {
		if ((idx & 0x7) == 0) {
			if (idx != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t");
		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "0x%04x", codepoints[idx]);
	}
	fprintf(output, "\n};\n\n");
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

	fprintf(output, "static const uint8_t unicode_mappings[] = {\n");
	for (idx = 0; idx < unicode_range * single_bytes; idx++) {
		if ((idx & 0xf) == 0) {
			if (idx != 0)
				fprintf(output, ",\n");
			fprintf(output, "\t");
		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "0x%02x", codepage_bytes[idx]);
	}
	fprintf(output, "\n};\n\n");
	free(codepage_bytes);
}

void Variant::write_simple_mappings(FILE *output, int variant_nr) {
	sort_simple_mappings();
	fprintf(output, "static const variant_mapping_t variant%d_mappings[] = {\n");
	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if (iter != simple_mappings.begin())
			fprintf(output, ",\n");
		fprintf(output, "\t{ UINT32_C(0x%08x), { ", (*iter)->codepoints[0]);
		for (vector<uint8_t> byte_iter = (*iter)->codepage_bytes.begin();
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

void Ucm::write_table(FILE *output) {
	unsigned int count;
	size_t i;
	vector<Variant *>::iterator variant_iter;

	fprintf(output, "/* This file has been automatically generated by ucm2cct. DO NOT EDIT. */\n");
	fprintf(output, "#include <transcript/tabledefs.h>\n\n");

	/* Write all entries into a single array. */
	fprintf(output, "static const entry_t entries[] = {\n");
	count = 0;
	write_entries(output, codepage_states, count);
	write_entries(output, unicode_states, count);
	fprintf("\n};\n\n");

	/* Write state arrays. */
	write_states(output, codepage_states, "codepage");
	write_states(output, unicode_states, "unicode");

	/* Write shift sequences. */
	if (shift_sequences.size() > 0) {
		fprintf(output, "static const shift_state_t shift_states[] = {\n");
		for (vector<shift_sequence_t>::iterator shift_iter = shift_sequences.begin();
				shift_iter != shift_sequences.end(); shift_iter++)
		{
			if (shift_iter != shift_sequences.begin())
				fprintf(output, ",\n");
			fprintf(output, "\t{ 0x%02x, 0x%02x, 0x%02x, { 0x%02x",
				shift_iter->from_state, shift_iter->to_state, shift_iter->bytes.size(), shift_iter->bytes[0]);

			for (i = 1; i < shift_iter->bytes.size(); i++)
				fprintf(output, ", 0x%02x", shift_iter->bytes[i]);
			fprintf(output, "}}");
		}
		fprintf(output, "\n{;\n\n");
	}

	/* Write the simple mapping tables. */
	write_to_unicode_table(output);
	write_from_unicode_table(output);

	/* Write all multi mappings in a single table (that is including the ones from
	   the variants). We have to include sorted lists anyway, so the sorted lists
	   will be built such that they only include the correct items. */
	//FIXME: set the HAS_MULTI_MAPPINGS flag elsewhere in the code if either the UCM itself or one of the variants has multi-mappings
	if (flags & HAS_MULTI_MAPPINGS) {
		fprintf(output, "static const multi_mapping_t multi_mappings[] = {\n");
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

	WRITE(4, magic); // magic (4)
	WRITE_DWORD(0); // version (4)
	WRITE_WORD(flags); // flags (2)
	vector<uint8_t> subchar;
	parse_byte_sequence(tag_values[Ucm::SUBCHAR], subchar);
	WRITE_BYTE(subchar.size()); // subchar length (1)
	for (i = 0; i < subchar.size(); i++)
		WRITE_BYTE(subchar[i]); // subchar byte (1)
	for (; i < 4; i++)
		WRITE_BYTE(0);
	WRITE_BYTE(tag_values[Ucm::SUBCHAR1] != NULL ? strtol(tag_values[Ucm::SUBCHAR1] + 2, NULL, 16) : 0); // subchar1 (1)
	WRITE_BYTE(shift_sequences.size()); //FIXME: nr of shift sequences
	WRITE_BYTE(codepage_states.size() - 1); // nr of states in codepage state machine (1)
	total_entries = 0;
	for (vector<State *>::iterator state_iter = codepage_states.begin();
			state_iter != codepage_states.end(); state_iter++)
		total_entries += (*state_iter)->entries.size();
	WRITE_WORD(total_entries - 1); // total nr of entries (code page) (2)
	WRITE_DWORD(codepage_range);
	WRITE_BYTE(unicode_states.size() - 1); // nr of states in unicode state machine (1)
	total_entries = 0;
	for (vector<State *>::iterator state_iter = unicode_states.begin();
			state_iter != unicode_states.end(); state_iter++)
		total_entries += (*state_iter)->entries.size();
	WRITE_WORD(total_entries - 1); // total nr of entries (unicode) (2)
	WRITE_DWORD(unicode_range);
	WRITE_BYTE(to_unicode_flags); // default to-unicode flags (1)
	WRITE_BYTE(from_unicode_flags); // default from-unicode flags (1)
	WRITE_BYTE(single_bytes); // Final codepage action size (1)

	if (used_to_unicode_flags != 0)
		write_to_unicode_flags(output);
	if (used_from_unicode_flags != 0)
		write_from_unicode_flags(output);

	if (variants.size() > 1) {
		WRITE_WORD(variants.size());
		for (list<Variant *>::iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++) {
			WRITE_BYTE(strlen((*variant_iter)->id));
			WRITE(strlen((*variant_iter)->id), (*variant_iter)->id);
			//FIXME: write variant flags (interal use is the only flag we have so far!
			WRITE_BYTE(0);
			WRITE_WORD((*variant_iter)->simple_mappings.size());
			(*variant_iter)->sort_simple_mappings();
			for (vector<Mapping *>::iterator mapping_iter = (*variant_iter)->simple_mappings.begin();
					mapping_iter != (*variant_iter)->simple_mappings.end(); mapping_iter++)
			{
				uint8_t buffer[4];

				WRITE_BYTE((*mapping_iter)->to_unicode_flags);
				WRITE_BYTE((*mapping_iter)->from_unicode_flags);

				copy((*mapping_iter)->codepage_bytes.begin(), (*mapping_iter)->codepage_bytes.end(), buffer);
				WRITE((*mapping_iter)->codepage_bytes.size(), buffer);
				if ((*mapping_iter)->codepoints[0] < UINT32_C(0x10000)) {
					WRITE_WORD((*mapping_iter)->codepoints[0]);
				} else {
					uint32_t codepoint = ((*mapping_iter)->codepoints[0]) - 0x10000;
					WRITE_WORD(UINT32_C(0xd800) + (codepoint >> 10));
					WRITE_WORD(UINT32_C(0xdc00) + (codepoint & 0x3ff));
				}
				WRITE_WORD((*mapping_iter)->idx);
			}
			WRITE_WORD((*variant_iter)->multi_mappings.size());
			write_multi_mappings(output, (*variant_iter)->multi_mappings);
		}
	}
}

void Ucm::write_multi_mappings(FILE *output, vector<Mapping *> &mappings) {
	for (vector<Mapping *>::iterator multi_iter = mappings.begin();
			multi_iter != mappings.end(); multi_iter++)
	{
		vector<uint32_t>::iterator codepoint_iter;
		uint8_t count = 0;
		for (codepoint_iter = (*multi_iter)->codepoints.begin();
				codepoint_iter != (*multi_iter)->codepoints.end(); codepoint_iter++)
			count += 1 + ((*codepoint_iter) >= UINT32_C(0x10000));

		WRITE_BYTE(count);
		for (codepoint_iter = (*multi_iter)->codepoints.begin();
				codepoint_iter != (*multi_iter)->codepoints.end(); codepoint_iter++)
		{
			if (*codepoint_iter < UINT32_C(0x10000)) {
				WRITE_WORD(*codepoint_iter);
			} else {
				uint32_t codepoint = (*codepoint_iter) - 0x10000;
				WRITE_WORD(UINT32_C(0xd800) + (codepoint >> 10));
				WRITE_WORD(UINT32_C(0xdc00) + (codepoint & 0x3ff));
			}
		}

		WRITE_BYTE((*multi_iter)->codepage_bytes.size());
		for (vector<uint8_t>::iterator byte_iter = (*multi_iter)->codepage_bytes.begin();
				byte_iter != (*multi_iter)->codepage_bytes.end(); byte_iter++)
			WRITE_BYTE(*byte_iter);
	}
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
		WRITE_WORD(codepoints[idx]);

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

	WRITE(unicode_range * single_bytes, codepage_bytes);
	free(codepage_bytes);
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
static void merge_and_write_flags(FILE *output, uint8_t *data, uint32_t range, uint8_t used_flags) {
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
	if ((indices = (uint16_t *) malloc(nr_of_blocks * 2)) == NULL)
		OOM();
	if ((blocks = (uint8_t *) malloc(nr_of_blocks * BLOCKSIZE)) == NULL)
		OOM();

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
		WRITE_BYTE(flag_code);
		WRITE(store_idx, data);
	} else {
		WRITE_BYTE(flag_code | 0x80);
		for (i = 0; i < nr_of_blocks; i++)
			WRITE_WORD(indices[i]);
		WRITE_WORD(saved_blocks - 1);
		WRITE(saved_blocks * BLOCKSIZE, blocks);
	}
	free(indices);
	free(blocks);
}
#undef BLOCKSIZE

void Ucm::write_to_unicode_flags(FILE *output) {
	uint32_t idx;
	uint8_t buffer[32];
	uint8_t *save_flags;
	vector<Mapping *>::iterator mapping_iter;

	if ((save_flags = (uint8_t *) malloc(codepage_range + 7)) == NULL)
		OOM();

	memset(save_flags, 0, codepage_range + 7);

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

	for (list<Variant *>::iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++) {
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

	merge_and_write_flags(output, save_flags, codepage_range, used_to_unicode_flags);
	free(save_flags);
}

void Ucm::write_from_unicode_flags(FILE *output) {
	uint32_t idx, codepoint;
	uint8_t *save_flags;
	vector<Mapping *>::iterator mapping_iter;

	if ((save_flags = (uint8_t *) malloc(unicode_range + 7)) == NULL)
		OOM();

	memset(save_flags, Mapping::FROM_UNICODE_NOT_AVAIL, unicode_range + 7);

	for (mapping_iter = simple_mappings.begin(); mapping_iter != simple_mappings.end(); mapping_iter++) {
		if ((*mapping_iter)->precision == 3)
			continue;

		codepoint = htonl((*mapping_iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		save_flags[idx] |= (*mapping_iter)->from_unicode_flags;
		save_flags[idx] &= ~Mapping::FROM_UNICODE_NOT_AVAIL;
	}

	for (mapping_iter = multi_mappings.begin(); mapping_iter != multi_mappings.end(); mapping_iter++) {
		codepoint = htonl((*mapping_iter)->codepoints[0]);
		idx = map_charseq(unicode_states, 1 + (uint8_t *) &codepoint, 3, 0);
		save_flags[idx] |= Mapping::FROM_UNICODE_MULTI_START;
	}

	for (list<Variant *>::iterator variant_iter = variants.begin(); variant_iter != variants.end(); variant_iter++) {
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
	merge_and_write_flags(output, save_flags, unicode_range, used_from_unicode_flags);
	free(save_flags);
}
