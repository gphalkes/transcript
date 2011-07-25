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

static int unique;

static void write_byte_data(FILE *output, uint8_t *data, size_t size, int indent_level) {
	static const char tabs[] = "\t\t\t\t\t\t\t\t";
	size_t i;

	for (i = 0; i < size; i++) {
		if ((i & 0xf) == 0) {
			if (i != 0)
				fprintf(output, ",\n%.*s", indent_level, tabs);
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
				fprintf(output, ",\n%.*s", indent_level, tabs);
		} else {
			fprintf(output, ", ");
		}
		fprintf(output, "0x%04x", data[i]);
	}
}

uint8_t *Ucm::write_simple_from_unicode(FILE *output) {
	uint8_t (*map)[32], *flag_data, *level0_indices;
	uint8_t level1_indices[64][32];
	int level0_map_used, level1_map_used;
	int i, j;
	vector<Mapping *>::const_iterator iter;

	map = (uint8_t (*)[32]) safe_malloc(65536);
	level0_indices = (uint8_t *) safe_malloc(64);
	memset(map, 0, 65536);
	for (iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++)
		((uint8_t *) map)[(*iter)->codepoints[0]] = (*iter)->codepage_bytes[0];

	level1_map_used = 1;
	level1_indices[0][0] = 0;
	for (i = 1; i < 2048; i++) {
		for (j = 0; j < level1_map_used; j++) {
			if (memcmp(map[i], map[j], 32) == 0) {
				((uint8_t *) level1_indices)[i] = j;
				break;
			}
		}
		if (j == level1_map_used) {
			if (i != j)
				memcpy(map[level1_map_used], map[i], 32);
			((uint8_t *) level1_indices)[i] = j;
			level1_map_used++;
		}
	}
	/* This can only happen if all the mappings are in different 32-codepoint
	   ranges. Although technically not impossible, this is seriously unlikely.
	   So we don't check for it beforehand, but only make sure here that we
	   don't generate a bogus table. */
	if (level1_map_used > 255)
		PANIC();

	level0_map_used = 1;
	level0_indices[0] = 0;
	for (i = 1; i < 64; i++) {
		for (j = 0; j < level0_map_used; j++) {
			if (memcmp(level1_indices[i], level1_indices[j], 32) == 0) {
				level0_indices[i] = j;
				break;
			}
		}
		if (j == level0_map_used) {
			if (i != j)
				memcpy(level1_indices[level0_map_used], level1_indices[i], 32);
			level0_indices[i] = j;
			level0_map_used++;
		}
	}

	fprintf(output, "static const uint8_t codepoint_to_byte_data_%d[%d][32] = {\n", unique, level1_map_used);
	for (i = 0; i < level1_map_used; i++) {
		if (i != 0)
			fprintf(output, " },\n");
		fprintf(output, "\t{ ");
		write_byte_data(output, map[i], 32, 2);
	}
	fprintf(output, " }\n};\n\n");
	fprintf(output, "static const uint8_t codepoint_to_byte_idx1_%d[%d][32] = {\n", unique, level0_map_used);
	for (i = 0; i < level0_map_used; i++) {
		if (i != 0)
			fprintf(output, " },\n");
		fprintf(output, "\t{ ");
		write_byte_data(output, level1_indices[i], 32, 2);
	}
	fprintf(output, " }\n};\n\n");
	free(map);

	if (used_from_unicode_flags & Mapping::FROM_UNICODE_FALLBACK) {
		flag_data = (uint8_t *) safe_malloc(level1_map_used * 4);
		memset(flag_data, 0, level1_map_used * 4);
		for (iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
			if ((*iter)->from_unicode_flags & Mapping::FROM_UNICODE_FALLBACK) {
				uint16_t codepoint = (*iter)->codepoints[0];
				uint16_t idx = ((uint16_t) level1_indices[level0_indices[codepoint >> 10]][(codepoint >> 5) & 0x1f] << 5)
					+ (codepoint & 0x1f);
				flag_data[idx >> 3] |= 1 << (idx & 7);
			}
		}
		fprintf(output, "static const uint8_t codepoint_to_byte_flags_%d[%d] = {\n\t", unique, level1_map_used * 4);
		write_byte_data(output, flag_data, level1_map_used * 4, 1);
		fprintf(output, "\n};\n\n");
		free(flag_data);
	}
	return level0_indices;
}

void Ucm::write_simple(FILE *output) {
	uint16_t byte_to_codepoint[256];
	uint8_t *level0_indices;
	vector<Mapping *>::const_iterator iter;
	char normalized_name[160];

	unique++;
	transcript_normalize_name(variant.id, normalized_name, sizeof(normalized_name));

	memset(byte_to_codepoint, 0xff, sizeof(byte_to_codepoint));
	for (iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
		if (!((*iter)->from_unicode_flags & Mapping::FROM_UNICODE_FALLBACK))
			byte_to_codepoint[(unsigned int) (*iter)->codepage_bytes[0]] = (*iter)->codepoints[0];
	}

	/* Set entries for illegal to 0xfffe */
	for (vector<Entry>::const_iterator entry_iter = codepage_states.front()->entries.begin();
				entry_iter != codepage_states.front()->entries.end(); entry_iter++)
	{
		if (entry_iter->action == ACTION_ILLEGAL) {
			for (int i = entry_iter->low; i <= entry_iter->high; i++)
				byte_to_codepoint[i] = 0xfffe;
		}
	}

	level0_indices = write_simple_from_unicode(output);
	fprintf(output, "static const sbcs_converter_v1_t sbcs_converter_%d = {\n", unique);
	if (used_from_unicode_flags & Mapping::FROM_UNICODE_FALLBACK)
		fprintf(output, "\tcodepoint_to_byte_flags_%d, ", unique);
	else
		fprintf(output, "\tNULL, ");
	fprintf(output, "codepoint_to_byte_data_%d, codepoint_to_byte_idx1_%d,\n", unique, unique);
	fprintf(output, "\t{ ");
	write_byte_data(output, level0_indices, 64, 2);
	fprintf(output, " },\n\t{ ");
	write_word_data(output, byte_to_codepoint, 256, 2);
	fprintf(output, " },\n\t{ ");

	if (used_to_unicode_flags & Mapping::TO_UNICODE_FALLBACK) {
		uint8_t byte_to_codepoint_flags[32];

		memset(byte_to_codepoint_flags, 0xff, sizeof(byte_to_codepoint_flags));
		for (iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++) {
			if ((*iter)->to_unicode_flags & Mapping::TO_UNICODE_FALLBACK)
				byte_to_codepoint_flags[((unsigned int) (*iter)->codepage_bytes[0]) >> 3] = 1 << ((*iter)->codepage_bytes[0] & 7);
		}
		write_byte_data(output, byte_to_codepoint_flags, 32, 2);
	} else {
		fprintf(output, "0");
	}
	vector<uint8_t> subchar;
	if (tag_values[Ucm::SUBCHAR].str == NULL)
		subchar.push_back(0);
	else
		parse_byte_sequence(tag_values[Ucm::SUBCHAR].str, subchar);
	fprintf(output, " },\n\t0x%02x, 0x%02x\n};\n\n", !!(flags & INTERNAL_TABLE), subchar[0]);

	fprintf(output, "TRANSCRIPT_EXPORT int transcript_get_iface_%s(void) { return TRANSCRIPT_SBCS_TABLE_V1; }\n", normalized_name);
	fprintf(output, "TRANSCRIPT_EXPORT const sbcs_converter_v1_t *transcript_get_table_%s(void) { return &sbcs_converter_%d; }\n\n",
		normalized_name, unique);
}
