/* Copyright (C) 2011-2012 G.P. Halkes
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <transcript/transcript.h>

#include "optionMacros.h"
#include "transcript/transcript_dlfcn.h"

#define OOM() fatal("Out of memory\n")

static char dirseps[3] = { '/' };
static int option_verbose;

static void make_links(const char *name);

/** Alert the user of a fatal error and quit.
    @param fmt The format string for the message. See fprintf(3) for details.
    @param ... The arguments for printing.
*/
static void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

static char *safe_strdup(const char *str) {
	size_t len = strlen(str) + 1;
	char *retval;

	/* Not all systems may have strdup, so just implement it here based on malloc. */
	if ((retval = (char *) malloc(len)) == NULL)
		OOM();
	memcpy(retval, str, len);
	return retval;
}

static PARSE_FUNCTION(parse_args)
	OPTIONS
		OPTION('v', "verbose", NO_ARG)
			option_verbose = 1;
		END_OPTION
		DOUBLE_DASH
			NO_MORE_OPTIONS;
		END_OPTION
	NO_OPTION
	END_OPTIONS
END_FUNCTION

static PARSE_FUNCTION(load_files)
	OPTIONS
		OPTION('v', "verbose", NO_ARG)
		END_OPTION
		DOUBLE_DASH
			NO_MORE_OPTIONS;
		END_OPTION
	NO_OPTION
		if (strlen(optcurrent) < 5 || strcmp(optcurrent + strlen(optcurrent) - 4, ".ltc") != 0)
			fprintf(stderr, "File %s does not end in .ltc\n", optcurrent);
		else
			make_links(optcurrent);
	END_OPTIONS
END_FUNCTION

static char *strcat_autoalloc(char *base, const char *append) {
	size_t orig_len = 0, len;

	if (base != NULL)
		orig_len = strlen(base);
	len = strlen(append) + orig_len + 1;

	if ((base = realloc(base, len)) == NULL)
		OOM();

	strcpy(base + orig_len, append);
	return base;
}

static const char *strpbrk_reverse(const char *str, const char *seps) {
	const char *tmp;
	if ((tmp = strpbrk(str, seps)) == NULL)
		return NULL;

	do {
		str = tmp;
	} while ((tmp = strpbrk(str + 1, seps)) != NULL);
	return str;
}

static const char *filename(const char *str) {
	const char *tmp;
	return (tmp = strpbrk_reverse(str, dirseps)) == NULL ? str : tmp + 1;
}

static void make_links(const char *name) {
	lt_dlhandle handle;
	const char * const *(*get_namelist)(void);
	const char * const *namelist;
	char *base_name, *sym_name;
	char normalized_name[160];
	struct stat statbuf;

	if (strpbrk(name, dirseps) != NULL) {
		base_name = safe_strdup(name);
	} else {
		base_name = strcat_autoalloc(NULL, "./");
		base_name = strcat_autoalloc(base_name, name);
	}

	if (lstat(base_name, &statbuf) != 0) {
		fprintf(stderr, "%s: could not get file meta information: %s\n", name, strerror(errno));
		free(base_name);
		return;
	}

	if (S_ISLNK(statbuf.st_mode)) {
		free(base_name);
		return;
	}

	if ((handle = lt_dlopen(base_name)) == NULL) {
		fprintf(stderr, "%s: error loading converter: %s\n", name, lt_dlerror());
		free(base_name);
		return;
	}
	free(base_name);

	base_name = safe_strdup(filename(name));
	base_name[strlen(base_name) - 4] = 0;
	transcript_normalize_name(base_name, normalized_name, sizeof(normalized_name));
	free(base_name);
	sym_name = strcat_autoalloc(NULL, "transcript_namelist_");
	sym_name = strcat_autoalloc(sym_name, normalized_name);

	if ((get_namelist = lt_dlsym(handle, sym_name)) == NULL) {
		fprintf(stderr, "%s: converter does not provide a name list %s\n", name, sym_name);
		lt_dlclose(handle);
		free(sym_name);
		return;
	}
	free(sym_name);

	for (namelist = get_namelist(); namelist != NULL && *namelist != NULL; namelist++) {
		const char *tmp;

		base_name = NULL;
		if ((tmp = strpbrk_reverse(name, dirseps)) != NULL) {
			base_name = strcat_autoalloc(base_name, name);
			base_name[tmp - name + 1] = 0;
		}
		transcript_normalize_name(*namelist, normalized_name, sizeof(normalized_name));
		base_name = strcat_autoalloc(base_name, normalized_name);
		base_name = strcat_autoalloc(base_name, ".ltc");

		if (option_verbose)
			fprintf(stderr, "%s -> %s\n", base_name, filename(name));

		if (lstat(base_name, &statbuf) != 0) {
			if (errno == ENOENT)
				symlink(filename(name), base_name);
		} else if (S_ISLNK(statbuf.st_mode)) {
			unlink(base_name);
			symlink(filename(name), base_name);
		}
		free(base_name);
	}
	lt_dlclose(handle);
}

int main(int argc, char *argv[]) {
	parse_args(argc, argv);

	transcript_init();

	if (lt_dlinit() != 0)
		fatal("Error initializing dynamic linker: %s\n", lt_dlerror());
#ifdef LT_DIRSEP_CHAR
	dirseps[1] = LT_DIRSEP_CHAR;
#endif
	load_files(argc, argv);
	lt_dlexit();
	return EXIT_SUCCESS;
}
