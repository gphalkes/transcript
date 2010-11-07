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
#include <algorithm>

#include "ucm2cct.h"

Variant::Variant(Ucm *_base, const char *_id, bool internal) : base(_base) {
	size_t len;

	while (strpbrk(_id, DIRSEPS) != NULL)
		_id = strpbrk(_id, DIRSEPS) + 1;

	if ((id = strdup(_id)) == NULL)
		OOM();

	len = strlen(id);
	if (len < 4 || strcmp(id + len - 4, ".ucm") == 0) {
		len -= 4;
		id[len] = 0;
	}

	flags = (base->flags & Ucm::INTERNAL_TABLE);
	if (internal)
		flags |= Ucm::INTERNAL_TABLE;

	if (len > 255)
		fatal("%s: Variant name %s too long\n", file_name, id);
}

int Variant::check_codepage_bytes(vector<uint8_t> &bytes) {
	return base->check_codepage_bytes(bytes);
}

const char *Variant::get_tag_value(tag_t tag) {
	return base->get_tag_value(tag);
}

void Variant::sort_simple_mappings(void) {
	uint16_t *indices;
	sort(simple_mappings.begin(), simple_mappings.end(), compare_codepage_bytes);
	for (size_t idx = 0; idx < simple_mappings.size(); idx++)
		simple_mappings[idx]->idx = idx;

	sort(simple_mappings.begin(), simple_mappings.end(), compare_codepoints);
	if ((indices = (uint16_t *) malloc(sizeof(uint16_t) * simple_mappings.size())) == NULL)
		OOM();

	for (size_t idx = 0; idx < simple_mappings.size(); idx++)
		indices[simple_mappings[idx]->idx] = idx;
	for (size_t idx = 0; idx < simple_mappings.size(); idx++)
		simple_mappings[idx]->idx = indices[idx];

	free(indices);
}

void Variant::dump(void) {
	sort(simple_mappings.begin(), simple_mappings.end(), compare_codepoints);
	sort(multi_mappings.begin(), multi_mappings.end(), compare_codepoints);

	printf("VARIANT %s\"%s\"\n", flags & Ucm::INTERNAL_TABLE ? "INTERNAL " : "", id);

	for (vector<Mapping *>::iterator iter = simple_mappings.begin(); iter != simple_mappings.end(); iter++)
		printf("%s %s |%d\n", sprint_codepoints((*iter)->codepoints), sprint_sequence((*iter)->codepage_bytes), (*iter)->precision);

	for (vector<Mapping *>::iterator iter = multi_mappings.begin(); iter != multi_mappings.end(); iter++)
		printf("%s %s |%d\n", sprint_codepoints((*iter)->codepoints), sprint_sequence((*iter)->codepage_bytes), (*iter)->precision);

	printf("END VARIANT\n");
}
