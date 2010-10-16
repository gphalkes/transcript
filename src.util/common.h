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
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#define CODEPOINTS_MAX 0x110000

typedef struct {
	int bits[11];
	uint32_t size;
} table_info_t;

typedef enum {
	DATAFMT_BYTE,
	DATAFMT_INT16,
	DATAFMT_INT32
} data_fmt_t;


char *pathconcat(const char *a, const char *b);

void fatal(const char *fmt, ...);
#define PANIC() fatal("Program logic error at line: %s:%d\n", __FILE__, __LINE__)
#define OOM() fatal("Out of memory\n")

/* Default value is 1, but can be overriden per program. */
extern int min_bits;
extern const int data_size[3];
table_info_t calculate_compressed_table(uint8_t *data, data_fmt_t fmt, data_fmt_t mem_fmt, uint32_t range, int depth);

#endif