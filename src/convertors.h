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
#ifndef CONVERTORS_H
#define CONVERTORS_H
#include <stdlib.h>

/* CCT based convertors */
void *open_cct_convertor(const char *name, int flags, int *error);
size_t get_cct_saved_state_size(void);

/* Unicode UTF convertors */
void *open_unicode_convertor(const char *name, int flags, int *error);
size_t get_unicode_saved_state_size(void);

/* ISO-8859-1 convertor */
void *open_iso8859_1_convertor(const char *name, int flags, int *error);
size_t get_iso8859_1_saved_state_size(void);

#endif