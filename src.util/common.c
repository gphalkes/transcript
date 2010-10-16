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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>

#include "common.h"

const int data_size[3] = {1, 2, 4};
int min_bits = 1;

char *pathconcat(const char *a, const char *b) {
	char *result;
	if ((result = malloc(strlen(a) + strlen(b) + 2)) == NULL)
		fatal("Out of memory\n");
	strcpy(result, a);
	strcat(result, "/");
	return strcat(result, b);
}

/** Alert the user of a fatal error and quit.
    @param fmt The format string for the message. See fprintf(3) for details.
    @param ... The arguments for printing.
*/
void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

table_info_t calculate_compressed_table(uint8_t *data, data_fmt_t fmt, data_fmt_t mem_fmt, uint32_t range, int depth) {
	uint8_t *table_data = malloc(4 * range);
	int *index = malloc(range * sizeof(int));
	int bits, table_size, data_start, stored_table_size;
	uint32_t max_table, i, j, tables, index_size;
	table_info_t result;
	data_fmt_t index_fmt;

	result.size = INT_MAX;
	memset(result.bits, 0, sizeof(result.bits));

	for (bits = min_bits; bits < 16; bits++) {
		table_size = (1 << bits) * data_size[mem_fmt];
		stored_table_size = (1 << bits) * data_size[fmt];
		memcpy(table_data, data, table_size);
		max_table = range >> bits;
		if ((max_table << bits) != range)
			break;
		tables = 1;
		index[0] = 0;
		for (i = 1; i < max_table; i++) {
			data_start = table_size * i;
			for (j = 0; j < tables; j++) {
				if (memcmp(table_data + j * table_size, data + data_start, table_size) == 0) {
					index[i] = j;
					break;
				}
			}
			if (j == tables) {
				memcpy(table_data + tables * table_size, data + data_start, table_size);
				index[i] = tables++;
			}
		}
		if (tables < 256) {
			index_size = 1;
			index_fmt = DATAFMT_BYTE;
		} else if (tables < 65536) {
			index_size = 2;
			index_fmt = DATAFMT_INT16;
		} else {
			index_size = 4;
			index_fmt = DATAFMT_INT32;
		}

		if (depth > 0) {
			table_info_t next_depth_result;
			uint8_t *index_data;
			index_data = calloc(1, range * index_size);
			for (i = 0; i < max_table; i++) {
				union { unsigned char c; unsigned short s; unsigned int i; } overlap;
				switch (index_size) {
					case 1:
						overlap.c = index[i];
						break;
					case 2:
						overlap.s = index[i];
						break;
					case 4:
						overlap.i = index[i];
						break;
					default:
						PANIC();
				}
				memcpy(index_data + i * index_size, &overlap, index_size);
			}
			next_depth_result = calculate_compressed_table(index_data, index_fmt, index_fmt, max_table, depth - 1);
			if (next_depth_result.size < index_size * max_table) {
				if (next_depth_result.size + tables * stored_table_size < result.size) {
					result = next_depth_result;
					result.size = next_depth_result.size + tables * stored_table_size;
					result.bits[depth] = bits;
				}
			} else if (index_size * max_table + tables * stored_table_size < result.size) {
				memset(result.bits, 0, sizeof(result.bits));
				result.size = index_size * max_table + tables * stored_table_size;
				result.bits[depth] = bits;
			}
			free(index_data);
		} else {
			if (index_size * max_table + tables * stored_table_size < result.size) {
				memset(result.bits, 0, sizeof(result.bits));
				result.size = index_size * max_table + tables * stored_table_size;
				result.bits[depth] = bits;
			}
		}
	}
	free(index);
	free(table_data);
	return result;
}

