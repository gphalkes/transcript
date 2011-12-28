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
#ifndef TRANSCRIPT_DLFCN_H
#define TRANSCRIPT_DLFCN_H

#ifdef HAS_DLFCN
#include <dlfcn.h>
typedef void *lt_dlhandle;
#ifdef _WIN32
#define LT_PATHSEP_CHAR ';'
#else
#define LT_PATHSEP_CHAR ':'
#endif
#define lt_dlinit() 0
#define lt_dlexit()
#define lt_dlopen(name) dlopen(name, RTLD_NOW | RTLD_LOCAL)
#define lt_dlsym dlsym
#define lt_dlclose dlclose
#define lt_dlerror dlerror
#else
#include <ltdl.h>
#endif

#endif
