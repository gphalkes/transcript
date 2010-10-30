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
#ifndef CHARCONV_INTERNAL_H
#define CHARCONV_INTERNAL_H

#define ARRAY_SIZE(name) (sizeof(name) / sizeof(name[0]))

charconv_t *fill_utf(charconv_t *handle, int utf_type);
int element_strcmp(const void *a, const void *b);

#ifndef DB_DIRECTORY
#define DB_DIRECTORY "/usr/local/share/libcharconv"
#endif

#endif
