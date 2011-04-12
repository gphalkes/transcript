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
#ifndef TRANSCRIPT_BOOL_H
#define TRANSCRIPT_BOOL_H

/* Define a bool type if not already defined (C++ and C99 do)*/
#if !(defined(__cplusplus) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 19990601L))
typedef enum {false, true} bool;
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 19990601L
#include <stdbool.h>
#endif

#endif
