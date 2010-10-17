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
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <unistd.h>

#include "ucm2cct.h"
#include "ucmparser.h"

bool option_verbose = false;
const char *option_output_name = NULL;
extern FILE *yyin;

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

Ucm::tag_t string_to_tag(const char *str) {
	if (strcmp(str, "<code_set_name>") == 0)
		return Ucm::CODE_SET_NAME;
	if (strcmp(str, "<uconv_class>") == 0)
		return Ucm::UCONV_CLASS;
	if (strcmp(str, "<subchar>") == 0)
		return Ucm::SUBCHAR;
	if (strcmp(str, "<subchar1>") == 0)
		return Ucm::SUBCHAR1;
	if (strcmp(str, "<icu:base>") == 0)
		return Ucm::ICU_BASE;
	return Ucm::IGNORED;
}


static void print_usage(void) {
	printf("Usage: ucm2ctt [<options>] <ucm file>\n"
		"  -h                  Display this help message\n"
		"  -o <output>         Specify the output file name\n"
		"  -v                  Increase verbosity\n");
	exit(EXIT_SUCCESS);
}

static void print_state_machine(Ucm *ucm) {
	for (size_t i = 0; i < ucm->codepage_states.size(); i++) {
		printf("State %zd:", i);
		for (size_t j = 0; j < ucm->codepage_states[i]->entries.size(); j++) {
			if (j != 0)
				putchar(',');
			printf(" %d", ucm->codepage_states[i]->entries[j].low);
			if (ucm->codepage_states[i]->entries[j].low != ucm->codepage_states[i]->entries[j].high)
				printf("-%d", ucm->codepage_states[i]->entries[j].high);

			if (ucm->codepage_states[i]->entries[j].next_state != 0)
				printf(":%d", ucm->codepage_states[i]->entries[j].next_state);

			switch (ucm->codepage_states[i]->entries[j].action) {
				case ACTION_FINAL:
					putchar('.');
					break;
				case ACTION_FINAL_PAIR:
					printf(".p");
					break;
				case ACTION_ILLEGAL:
					printf(".i");
					break;
				case ACTION_UNASSIGNED:
					printf(".u");
					break;
				case ACTION_SHIFT:
					printf(".s");
					break;
				case ACTION_VALID:
					break;
				default:
					PANIC();
			}
		}
		putchar('\n');
	}
}


int main(int argc, char *argv[]) {
	Ucm *ucm;
	int c;

	while ((c = getopt(argc, argv, "ho:v")) != -1) {
		switch (c) {
			case 'h':
				print_usage();
			case 'o':
				option_output_name = optarg;
				break;
			case 'v':
				option_verbose = true;
				break;
			default:
				fatal("Error in option parsing\n");
		}
	}


	if (argc - optind != 1)
		print_usage();

	if ((yyin = fopen(argv[optind], "r")) == NULL)
		fatal("Could not open '%s': %s\n", argv[optind], strerror(errno));
	file_name = argv[optind];

	parse_ucm((void **) &ucm);
	print_state_machine(ucm);
	//~ ucm->check_duplicates();
	ucm->minimize_state_machines();
}
