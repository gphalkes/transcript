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
#ifndef TRANSCRIPT_API_H
#define TRANSCRIPT_API_H

#if defined _WIN32 || defined __CYGWIN__
	#define TRANSCRIPT_EXPORT __declspec(dllexport)
	#define TRANSCRIPT_IMPORT __declspec(dllimport)
	#define TRANSCRIPT_LOCAL
#else
	#if __GNUC__ >= 4
		#define TRANSCRIPT_EXPORT __attribute__((visibility("default")))
		#define TRANSCRIPT_IMPORT __attribute__((visibility("default")))
		#define TRANSCRIPT_LOCAL __attribute__((visibility("hidden")))
	#else
		#define TRANSCRIPT_EXPORT
		#define TRANSCRIPT_IMPORT
		#define TRANSCRIPT_LOCAL
	#endif
#endif

#ifdef TRANSCRIPT_BUILD_DSO
	#define TRANSCRIPT_API TRANSCRIPT_EXPORT
#else
	#define TRANSCRIPT_API TRANSCRIPT_IMPORT
#endif

#endif
