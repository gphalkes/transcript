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
#include <arpa/inet.h>

#include "ucm2cct.h"
#include "ucmparser.h"

bool option_verbose = false, option_internal_table = false;
#ifdef DEBUG
#define NO_ABORT_OPTION "a"
bool option_abort = true;
#endif
const char *option_output_name = NULL;
char *output_name;
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
#ifdef DEBUG
	if (option_abort)
		abort();
#endif
	exit(EXIT_FAILURE);
}

Ucm::tag_t string_to_tag(const char *str) {
	if (strcmp(str, "<code_set_name>") == 0)
		return UcmBase::CODE_SET_NAME;
	if (strcmp(str, "<uconv_class>") == 0)
		return UcmBase::UCONV_CLASS;
	if (strcmp(str, "<subchar>") == 0)
		return UcmBase::SUBCHAR;
	if (strcmp(str, "<subchar1>") == 0)
		return UcmBase::SUBCHAR1;
	if (strcmp(str, "<mb_cur_max>") == 0)
		return UcmBase::MB_MAX;
	if (strcmp(str, "<mb_cur_min>") == 0)
		return UcmBase::MB_MIN;
	if (strcmp(str, "<icu:charsetFamily>") == 0)
		return UcmBase::CHARSET_FAMILY;
	if (strcmp(str, "<cct:internal>") == 0)
		return UcmBase::_INTERNAL;
	return Ucm::IGNORED;
}

void parse_byte_sequence(char *charseq, vector<uint8_t> &store) {
	long value;

	while (*charseq != 0) {
		charseq += 2; /* Skip \x */
		value = strtol(charseq, &charseq, 16);
		if (value > 255 || value < 0)
			fatal("%s:%d: byte value out of range\n", file_name, line_number);
		store.push_back(value);
		if (*charseq == '+')
			charseq++;
	}
	if (store.size() > 31)
		fatal("%s:%d: character sequence too long\n", file_name, line_number);
}

static void print_usage(void) {
	printf("Usage: ucm2ctt [<options>] <ucm file>+\n"
		"  -h                  Display this help message\n"
		"  -i                  The ucm file is an internal use table\n"
		"  -o <output>         Specify the output file name\n"
		"  -v                  Increase verbosity\n");
	exit(EXIT_SUCCESS);
}

char *safe_strdup(const char *str) {
	size_t len = strlen(str) + 1;
	char *retval;

	if ((retval = (char *) malloc(len)) == NULL)
		OOM();
	memcpy(retval, str, len);
	return retval;
}

void print_state_machine(const vector<State *> &states) {
	for (size_t i = 0; i < states.size(); i++) {
		printf("State %zx:", i);
		for (size_t j = 0; j < states[i]->entries.size(); j++) {
			if (j != 0)
				putchar(',');
			printf(" %02x", states[i]->entries[j].low);
			if (states[i]->entries[j].low != states[i]->entries[j].high)
				printf("-%02x", states[i]->entries[j].high);

			if (states[i]->entries[j].next_state != 0)
				printf(":%x", states[i]->entries[j].next_state);

			switch (states[i]->entries[j].action) {
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

const char *sprint_sequence(vector<uint8_t> &bytes) {
	static char sequence_buffer[31 * 4 + 1];
	size_t i;
	for (i = 0; i < 31 && i < bytes.size(); i++)
		sprintf(sequence_buffer + i * 4, "\\x%02X", bytes[i]);
	return sequence_buffer;
}

const char *sprint_codepoints(vector<uint32_t> &codepoints) {
	static char codepoint_buffer[19 * 7 + 1];
	size_t i, idx = 0;
	for (i = 0; i < 31 && i < codepoints.size(); i++)
		idx += sprintf(codepoint_buffer + idx, "<U%04X>", codepoints[i] & 0x1fffff);
	return codepoint_buffer;
}


static void update_state_attributes(vector<State *> &states, size_t idx) {
	size_t i, sum = 0;

	if (states[idx]->complete)
		return;

	for (i = 0; i < states[idx]->entries.size(); i++) {
		switch (states[idx]->entries[i].action) {
			case ACTION_VALID:
				update_state_attributes(states, states[idx]->entries[i].next_state);
				states[idx]->entries[i].base = sum;
				states[idx]->entries[i].mul = states[states[idx]->entries[i].next_state]->range;
				sum += (states[idx]->entries[i].high - states[idx]->entries[i].low + 1) *
					states[idx]->entries[i].mul;
				break;
			case ACTION_FINAL_PAIR:
				states[idx]->entries[i].mul = 2;
				goto action_final_shared;
			case ACTION_FINAL:
				states[idx]->entries[i].mul = 1;
			action_final_shared:
				states[idx]->entries[i].base = sum;
				sum += (states[idx]->entries[i].high - states[idx]->entries[i].low + 1) * states[idx]->entries[i].mul;
				break;
			default:
				break;
		}
	}
	states[idx]->range = sum;
	states[idx]->complete = true;
}

static uint32_t calculate_state_attributes(vector<State *> &states) {
	uint32_t range = 0;
	size_t i;

	for (i = 0; i < states.size(); i++) {
		if (states[i]->flags & State::INITIAL) {
			update_state_attributes(states, i);
			states[i]->base = range;
			range += states[i]->range;
		}
	}
	return range;
}

uint32_t map_charseq(vector<State *> &states, uint8_t *charseq, int length, int flags) {
	uint32_t value;
	int i, state;
	size_t j;

	/* Some stateful converters are treated specially: single byte characters can not
	   be part of a multi-byte sequence && must be defined in state 0. See
	   process_header_part2() to see what conditions a convertor must satisfy for this
	   special treatment.

	   The spec is really deficient in this respect: there is no way to know what initial
	   state a byte-sequence belongs to. Because of this, several hacks were construed to
	   allow the parser to determine this. However, this is not a nice clean general
	   solution, but rather a work-around for certain types of converters (i.e. the EBCDIC
	   stateful converters and similar ones).
	*/
	state = (flags & Ucm::MULTIBYTE_START_STATE_1) && length > 1 ? 1 : 0;
	value = states[state]->base;

	for (i = 0; i < length; i++) {
		for (j = 0; j < states[state]->entries.size(); j++) {
			if (!(charseq[i] >= states[state]->entries[j].low && charseq[i] <= states[state]->entries[j].high))
				continue;

			value += states[state]->entries[j].base + (uint32_t)(charseq[i] - states[state]->entries[j].low) *
				states[state]->entries[j].mul;
			switch (states[state]->entries[j].action) {
				case ACTION_VALID:
					state = states[state]->entries[j].next_state;
					goto next_char;
				case ACTION_FINAL_PAIR:
				case ACTION_FINAL:
					return value;
				default:
					printf("action %d\n", states[state]->entries[j].action);
					PANIC();
			}
		}
		PANIC();
next_char:;
	}
	return true;
}


int main(int argc, char *argv[]) {
	FILE *output;
	vector<Ucm *> ucms;
	Ucm *ucm;
	int c;

	while ((c = getopt(argc, argv, "hio:v" NO_ABORT_OPTION)) != -1) {
		switch (c) {
			case 'h':
				print_usage();
			case 'i':
				option_internal_table = true;
				break;
			case 'o':
				option_output_name = optarg;
				break;
			case 'v':
				option_verbose = true;
				break;
#ifdef DEBUG
			case 'a':
				option_abort = false;
				break;
#endif
			default:
				fatal("Error in option parsing\n");
		}
	}


	if (argc - optind == 0)
		print_usage();
	else if (argc - optind > 1 && option_output_name == NULL)
		fatal("-o is required when using multiple input files\n");

	for (; optind != argc; optind++) {
		if ((yyin = fopen(argv[optind], "r")) == NULL)
			fatal("Could not open '%s': %s\n", argv[optind], strerror(errno));
		file_name = argv[optind];
		line_number = 1;

		parse_ucm((void **) &ucm);
		if (ucm->variants.size() == 1)
			fatal("%s: Only a single variant defined\n", ucm->name);
		ucm->check_duplicates();
		ucm->ensure_ascii_controls();
		ucm->remove_fullwidth_fallbacks();
		ucm->remove_private_use_fallbacks();

		ucms.push_back(ucm);
		fclose(yyin);
	}

	ucm = ucms.front();
	if (ucms.size() > 1) {
		for (vector<Ucm *>::iterator iter = ucms.begin() + 1; iter != ucms.end(); iter++)
			ucm->check_compatibility(*iter);

		for (vector<Ucm *>::iterator iter = ucms.begin(); iter != ucms.end(); iter++)
			(*iter)->prepare_subtract();

		/* Remove from ucm all the mappings that are different from mappings in other
		   Ucms or that are only present in ucm. */
		for (vector<Ucm *>::iterator iter = ucms.begin() + 1; iter != ucms.end(); iter++)
			ucm->subtract(*iter);
		ucm->fixup_variants();
		/* If there is only a single map defined in the .ucm file, add it to the list of
		   variants now. */
		ucm->variants_done();
		/* ucm now contains the largest common set. Now we must make sure that all other
		   sets are properly split such that their base sets contain nothing but the
		   largest common set. */
		for (vector<Ucm *>::iterator iter = ucms.begin() + 1; iter != ucms.end(); iter++) {
			(*iter)->subtract(ucm);
			(*iter)->fixup_variants();
			ucm->merge_variants(*iter);
		}
		ucms.clear();
	}
	ucm->calculate_item_costs();

	ucm->minimize_state_machines();

	if (option_verbose) {
		printf("Codepage state machine\n");
		print_state_machine(ucm->codepage_states);
		printf("Unicode state machine\n");
		print_state_machine(ucm->unicode_states);
	}

	ucm->codepage_range = calculate_state_attributes(ucm->codepage_states);
	ucm->unicode_range = calculate_state_attributes(ucm->unicode_states);
	if (option_verbose) {
		fprintf(stderr, "Codepage range: %" PRId32 "\n", ucm->codepage_range);
		fprintf(stderr, "Unicode range: %" PRId32 "\n", ucm->unicode_range);
	}

	ucm->find_shift_sequences();

	if (option_output_name != NULL) {
		output_name = safe_strdup(option_output_name);
	} else {
		size_t len;
		while (strpbrk(file_name, DIRSEPS) != NULL)
			file_name = strpbrk(file_name, DIRSEPS) + 1;
		len = strlen(file_name);
		if (len < 4 || strcmp(file_name + len - 4, ".ucm") != 0)
			fatal("Input file does not end in .ucm. Please use explicit output name (-o)\n");
		output_name = safe_strdup(file_name);
		strcpy(output_name + len - 3, "cct");
	}

	if ((output = fopen(output_name, "w+b")) == NULL)
		fatal("Could not open output file: %s\n", strerror(errno));

/*	for (list<Variant *>::iterator iter = ucm->variants.begin(); iter != ucm->variants.end(); iter++)
		(*iter)->dump(); */

	ucm->write_table(output);
	return EXIT_SUCCESS;
}
