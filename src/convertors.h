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
#include "charconv_internal.h"

/* CCT based convertors */
CHARCONV_LOCAL void *_charconv_open_cct_convertor(const char *name, int flags, charconv_error_t *error);
CHARCONV_LOCAL void *_charconv_open_cct_convertor_internal(const char *name, int flags, charconv_error_t *error, bool internal_use);

/* Unicode UTF convertors */
CHARCONV_LOCAL void *_charconv_open_unicode_convertor(const char *name, int flags, charconv_error_t *error);

/* ISO-8859-1 convertor */
CHARCONV_LOCAL void *_charconv_open_iso8859_1_convertor(const char *name, int flags, charconv_error_t *error);

#endif