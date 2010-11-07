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

#define WRITE(count, bytes) do { if (fwrite(bytes, 1, count, output) != (size_t) count) fatal("%s: Error writing file\n", file_name); } while (0)
#define WRITE_BYTE(value) do { uint8_t _write_value = value; WRITE(1, &_write_value); } while (0)
#define WRITE_WORD(value) do { uint16_t _write_value = htons(value); WRITE(2, &_write_value); } while (0)
#define WRITE_DWORD(value) do { uint32_t _write_value = htonl(value); WRITE(4, &_write_value); } while (0)

void Ucm::write_table(FILE *output) {
	const char magic[] = "T3CM";
	size_t total_entries;
	size_t i;

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
	for (vector<shift_sequence_t>::iterator shift_iter = shift_sequences.begin();
			shift_iter != shift_sequences.end(); shift_iter++)
	{
		WRITE_BYTE(shift_iter->from_state);
		WRITE_BYTE(shift_iter->to_state);
		WRITE_BYTE(shift_iter->bytes.size());

		for (i = 0; i < shift_iter->bytes.size(); i++)
			WRITE_BYTE(shift_iter->bytes[i]);
		for (; i < 4; i++)
			WRITE_BYTE(0);
	}

	for (vector<State *>::iterator state_iter = codepage_states.begin();
			state_iter != codepage_states.end(); state_iter++)
	{
		WRITE_BYTE((*state_iter)->entries.size() - 1);
		for (vector<Entry>::iterator entry_iter = (*state_iter)->entries.begin();
				entry_iter != (*state_iter)->entries.end(); entry_iter++)
		{
			WRITE_BYTE(entry_iter->low);
			WRITE_BYTE(entry_iter->next_state);
			WRITE_BYTE(entry_iter->action);
		}
	}

	for (vector<State *>::iterator state_iter = unicode_states.begin();
		state_iter != unicode_states.end(); state_iter++)
	{
		WRITE_BYTE((*state_iter)->entries.size() - 1);
		for (vector<Entry>::iterator entry_iter = (*state_iter)->entries.begin();
			entry_iter != (*state_iter)->entries.end(); entry_iter++)
		{
			WRITE_BYTE(entry_iter->low);
			WRITE_BYTE(entry_iter->next_state);
			WRITE_BYTE(entry_iter->action);
		}
	}

	write_to_unicode_table(output);
	write_from_unicode_table(output);

	if (used_to_unicode_flags != 0)
		write_to_unicode_flags(output);
	if (used_from_unicode_flags != 0)
		write_from_unicode_flags(output);

	if (multi_mappings.size() > 0) {
		WRITE_DWORD(multi_mappings.size());
		write_multi_mappings(output, multi_mappings);
	}

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
