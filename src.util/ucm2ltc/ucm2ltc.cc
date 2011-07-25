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
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <climits>
#include <transcript.h>

#include "ucm2ltc.h"
#include "ucmparser.h"
#include "optionMacros.h"

#warning FIXME: check names in different UCM sets against each other for clashes

int option_verbose;
bool option_internal_table, option_dump, option_allow_ibm_rotate;
#ifdef DEBUG
bool option_abort;
#endif
const char *option_output_name;
const char *option_converter_name;
extern FILE *yyin;

static vector<Ucm *> completed_ucms;

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
	if (strcmp(str, "<transcript:internal>") == 0)
		return UcmBase::INTERNAL;
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
	printf("Usage: ucm2ctt [<options>] <ucm file>+\n");
	printf("  -D,--dump                     Dump a ucm file representing the input\n");
	printf("  -h,--help                     Display this help message\n");
	printf("  -i,--internal                 The ucm file is an internal use table\n");
	printf("  -o<output>, --output=<output> Specify the output file name\n");
	printf("  -v,--verbose                  Increase verbosity\n");
	printf("  -n<name>,--name=<name>        Set converter name to <name>\n");
	printf("  -c,--concatenate              Concatenate the following converters\n");
	printf("       Use this to write multiple unrelated converters to a single file\n");
	printf("  -I,--allow-ibm-rotate         Allow IBM specific rotation of control chars\n");
	exit(EXIT_SUCCESS);
}

char *safe_strdup(const char *str) {
	size_t len = strlen(str) + 1;
	char *retval;

	/* Not all systems may have strdup, so just implement it here based on malloc. */
	if ((retval = (char *) malloc(len)) == NULL)
		OOM();
	memcpy(retval, str, len);
	return retval;
}

void *safe_malloc(size_t size) {
	void *retval;
	if ((retval = malloc(size)) == NULL)
		OOM();
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
				case ACTION_FINAL_NOFLAGS:
				case ACTION_FINAL:
					putchar('.');
					break;
				case ACTION_FINAL_PAIR_NOFLAGS:
				case ACTION_FINAL_PAIR:
					printf(".p");
					break;
				case ACTION_FINAL_LEN1_NOFLAGS:
					printf(".[1]");
					break;
				case ACTION_FINAL_LEN2_NOFLAGS:
					printf(".[2]");
					break;
				case ACTION_FINAL_LEN3_NOFLAGS:
					printf(".[3]");
					break;
				case ACTION_FINAL_LEN4_NOFLAGS:
					printf(".[4]");
					break;
				case ACTION_FINAL_LEN1_NOFLAGS | ACTION_FLAG_PAIR:
					printf(".[1]p");
					break;
				case ACTION_FINAL_LEN2_NOFLAGS | ACTION_FLAG_PAIR:
					printf(".[2]p");
					break;
				case ACTION_FINAL_LEN3_NOFLAGS | ACTION_FLAG_PAIR:
					printf(".[3]p");
					break;
				case ACTION_FINAL_LEN4_NOFLAGS | ACTION_FLAG_PAIR:
					printf(".[4]p");
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
			case ACTION_FINAL_LEN1_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_LEN2_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_LEN3_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_LEN4_NOFLAGS | ACTION_FLAG_PAIR:
			case ACTION_FINAL_PAIR_NOFLAGS:
			case ACTION_FINAL_PAIR:
				states[idx]->entries[i].mul = 2;
				goto action_final_shared;
			case ACTION_FINAL_LEN1_NOFLAGS:
			case ACTION_FINAL_LEN2_NOFLAGS:
			case ACTION_FINAL_LEN3_NOFLAGS:
			case ACTION_FINAL_LEN4_NOFLAGS:
			case ACTION_FINAL_NOFLAGS:
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
	   process_header_part2() to see what conditions a converter must satisfy for this
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
			switch (states[state]->entries[j].action & ~ACTION_FLAG_PAIR) {
				case ACTION_VALID:
					state = states[state]->entries[j].next_state;
					goto next_char;
				case ACTION_FINAL_LEN1_NOFLAGS:
				case ACTION_FINAL_LEN2_NOFLAGS:
				case ACTION_FINAL_LEN3_NOFLAGS:
				case ACTION_FINAL_LEN4_NOFLAGS:
				case ACTION_FINAL_NOFLAGS:
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

int popcount(int x) {
	int result = 0;
	while (x) {
		result++;
		x &= x - 1;
	}
	return result;
}

uint8_t create_mask(uint8_t used_flags) {
	int bits = popcount(used_flags);
	int i;

	if (bits == 1 || bits == 2 || bits == 4 || bits == 8)
		return used_flags;

	/* Two possible cases left: bits == 5-7, or bits == 3. */
	if (bits > 4)
		return 0xff;

	/* Bits == 3: pick the first bit that is not set in used_flags to make it 4. */
	for (i = 0; i < 8; i++) {
		if (!(used_flags & (1 << i)))
			break;
	}
	return used_flags | (1 << i);
}

static void analyse_ucm_set(vector<Ucm *> &ucms) {
	Ucm *ucm;

	if (ucms.size() > 1) {
		if (option_output_name == NULL)
			fatal("--output/-o is required when using multiple input files\n");
		if (option_converter_name != NULL)
			fatal("--name/-n is only allowed with a single input file\n");
	}

	ucm = ucms.front();
	if (ucms.size() > 1) {
		for (vector<Ucm *>::const_iterator iter = ucms.begin() + 1; iter != ucms.end(); iter++)
			ucm->check_compatibility(*iter);

		for (vector<Ucm *>::const_iterator iter = ucms.begin(); iter != ucms.end(); iter++)
			(*iter)->prepare_subtract();

		/* Remove from ucm all the mappings that are different from mappings in other
		   Ucms or that are only present in ucm. */
		for (vector<Ucm *>::const_iterator iter = ucms.begin() + 1; iter != ucms.end(); iter++)
			ucm->subtract(*iter);
		ucm->fixup_variants();
		/* If there is only a single map defined in the .ucm file, add it to the list of
		   variants now. */
		ucm->variants_done();
		/* ucm now contains the largest common set. Now we must make sure that all other
		   sets are properly split such that their base sets contain nothing but the
		   largest common set. */
		for (vector<Ucm *>::const_iterator iter = ucms.begin() + 1; iter != ucms.end(); iter++) {
			(*iter)->subtract(ucm);
			(*iter)->fixup_variants();
			ucm->merge_variants(*iter);
		}
	}
	ucm->calculate_item_costs();

	if (option_dump) {
		ucm->dump();
		exit(EXIT_SUCCESS);
	}

	if (ucms.size() == 1 && ucm->is_simple_table()) {
		completed_ucms.push_back(ucm);
		ucms.clear();
		return;
	}

	ucm->minimize_state_machines();

	if (option_verbose > 1) {
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
	ucm->check_base_mul_ranges();
	completed_ucms.push_back(ucm);
	ucms.clear();
}

PARSE_FUNCTION(parse_options)
	vector<Ucm *> ucms;
	Ucm *ucm;

	OPTIONS
		OPTION('h', "help", NO_ARG)
			print_usage();
		END_OPTION
		OPTION('i', "internal", NO_ARG)
			option_internal_table = true;
		END_OPTION
		OPTION('o', "output", REQUIRED_ARG)
			char normalized_output_name[160], *base_name;
			if (option_output_name != NULL)
				fatal("Only a single " OPTFMT " option may be specified\n", OPTPRARG);
			if (strlen(optArg) < 3 || strcmp(optArg + strlen(optArg) - 2, ".c") != 0)
				fatal("Output file name must end in .c\n");
			base_name = optArg;
			while (strpbrk(base_name, DIRSEPS) != NULL)
				base_name = strpbrk(base_name, DIRSEPS) + 1;
			transcript_normalize_name(base_name, normalized_output_name, sizeof(normalized_output_name));
			if (strncmp(base_name, normalized_output_name, strlen(base_name) - 2) != 0)
				fatal("Output file name is not normalized (should be '%.*s')\n", strlen(normalized_output_name) - 1, normalized_output_name);
			option_output_name = optArg;
		END_OPTION
		OPTION('v', "verbose", NO_ARG)
			option_verbose++;
		END_OPTION
		OPTION('D', "dump", NO_ARG)
			option_dump = true;
		END_OPTION
		OPTION('n', "name", REQUIRED_ARG)
			option_converter_name = optArg;
		END_OPTION
		OPTION('c', "concatenate", NO_ARG)
			if (ucms.empty())
				fatal("No input file specified before " OPTFMT "\n", OPTPRARG);
			if (option_output_name == NULL)
				fatal("--output/-o is required with " OPTFMT "\n", OPTPRARG);
			analyse_ucm_set(ucms);
			option_internal_table = false;
			option_converter_name = NULL;
		END_OPTION
		OPTION('I', "allow-ibm-rotate", NO_ARG)
			option_allow_ibm_rotate = true;
		END_OPTION
#ifdef DEBUG
		OPTION('a', "abort", NO_ARG)
			option_abort = true;
		END_OPTION
#endif
		DOUBLE_DASH
			NO_MORE_OPTIONS;
		END_OPTION

		fatal("Unknown option " OPTFMT "\n", OPTPRARG);
	NO_OPTION
		if ((yyin = fopen(optcurrent, "r")) == NULL)
			fatal("Could not open '%s': %s\n", optcurrent, strerror(errno));
		file_name = optcurrent;
		line_number = 1;

		parse_ucm((void **) &ucm);
		if (ucm->variants.size() == 1)
			fatal("%s: Only a single variant defined\n", ucm->name);
		ucm->check_duplicates();
		if (!option_allow_ibm_rotate)
			ucm->ensure_ascii_controls();
		ucm->remove_generic_fallbacks();
		ucm->remove_private_use_fallbacks();
		ucm->ensure_subchar_mapping();

		ucms.push_back(ucm);
		fclose(yyin);
	END_OPTIONS
	if (ucms.empty()) {
		if (completed_ucms.empty())
			print_usage();
		fatal("No input file specified after --concatenate/-c\n");
	}
	analyse_ucm_set(ucms);
END_FUNCTION


int main(int argc, char *argv[]) {
	FILE *output;
	vector<Ucm *>::const_iterator iter;
	char normalized_output_name[160];
	char *output_name, *base_name;

	parse_options(argc, argv);

	if (option_output_name != NULL) {
		output_name = safe_strdup(option_output_name);
	} else {
		size_t len;
		base_name = file_name;
		while (strpbrk(base_name, DIRSEPS) != NULL)
			base_name = strpbrk(base_name, DIRSEPS) + 1;
		len = strlen(base_name);
		if (len < 4 || strcmp(base_name + len - 4, ".ucm") != 0)
			fatal("Input file does not end in .ucm. Please use explicit output name (-o)\n");
		transcript_normalize_name(base_name, normalized_output_name, sizeof(normalized_output_name));
		output_name = safe_strdup(normalized_output_name);
		strcpy(output_name + len - 3, ".c");
	}

	if ((output = fopen(output_name, "w+t")) == NULL)
		fatal("Could not open output file: %s\n", strerror(errno));

	fprintf(output, "/* This file has been automatically generated by ucm2ltc. DO NOT EDIT. */\n");
	fprintf(output, "#include <transcript/moduledefs.h>\n\n");

	for (iter = completed_ucms.begin(); iter != completed_ucms.end(); iter++) {
		if ((*iter)->is_simple_table())
			(*iter)->write_simple(output);
		else
			(*iter)->write_table(output);
	}

	base_name = output_name;
	while (strpbrk(base_name, DIRSEPS) != NULL)
		base_name = strpbrk(base_name, DIRSEPS) + 1;
	// Remove ".c" at the end;
	base_name[strlen(base_name) - 2] = 0;
	transcript_normalize_name(base_name, normalized_output_name, sizeof(normalized_output_name));

	fprintf(output, "static const char * const namelist[] = {\n");
	for (iter = completed_ucms.begin(); iter != completed_ucms.end(); iter++)
		(*iter)->write_namelist_entries(output);
	fprintf(output, "\tNULL\n};\n\n");
	fprintf(output, "TRANSCRIPT_EXPORT const char * const *transcript_namelist_%s(void) { return namelist; }\n", normalized_output_name);

	fclose(output);
	free(output_name);
	return EXIT_SUCCESS;
}
