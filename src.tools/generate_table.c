#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <iconv.h>
#include <arpa/inet.h>
#include <string.h>

#include "transcript.h"
#include "optionMacros.h"

static const char *option_convertor_name;
static int option_generate_fallbacks;

static void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

static void print_usage(void) {
	printf("Usage: generate_table [<options>] <convertor name>\n");
	exit(EXIT_SUCCESS);
}

PARSE_FUNCTION(parse_options)
	OPTIONS
		OPTION('f', "generate-fallbacks", NO_ARG)
			option_generate_fallbacks = 1;
		END_OPTION
		OPTION('n', "help", NO_ARG)
			print_usage();
		END_OPTION
		DOUBLE_DASH
			NO_MORE_OPTIONS;
		END_OPTION

		printf("Unknown option " OPTFMT "\n", OPTPRARG);
	NO_OPTION
		if (option_convertor_name == NULL)
			option_convertor_name = optcurrent;
		else
			fatal("Only one convertor name allowed\n");
	END_OPTIONS
	if (option_convertor_name == NULL)
		fatal("No convertor specified\n");
END_FUNCTION

static int convert(transcript_t *handle, uint32_t codepoint, char *result, int *fallback) {
	const char *codepoint_ptr = (char *) &codepoint;
	char *result_limit = result + 80;

	switch (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4,
			&result, result_limit, TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE))
	{
		case TRANSCRIPT_SUCCESS:
			if (transcript_from_unicode_flush(handle, &result, result_limit) != TRANSCRIPT_SUCCESS) {
				transcript_from_unicode_reset(handle);
				return -1;
			}
			break;
		case TRANSCRIPT_FALLBACK:
			if (!option_generate_fallbacks)
				return -1;

			*fallback = 1;
			if (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4,
					&result, result_limit, TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE |
					TRANSCRIPT_ALLOW_FALLBACK) != TRANSCRIPT_SUCCESS)
			{
				return -1;
				transcript_from_unicode_reset(handle);
			}
			if (transcript_from_unicode_flush(handle, &result, result_limit) != TRANSCRIPT_SUCCESS) {
				transcript_from_unicode_reset(handle);
				return -1;
			}
			break;
		default:
			return -1;
	}
	return 80 - (result_limit - result);
}

int main(int argc, char *argv[]) {
	transcript_t *handle;
	uint32_t i;
	int j;

	parse_options(argc, argv);

	if ((handle = transcript_open_convertor(option_convertor_name,
			htons(1) == 1 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF32LE, 0, NULL)) == NULL)
		fatal("Could not open transcript convertor %s\n", option_convertor_name);

	for (i = 0; i < 0x110000; i++) {
		char result[80];
		int result_length;
		int fallback = 0;

		result_length = convert(handle, i, result, &fallback);
		if (result_length < 0)
			continue;

		printf("0x");
		for (j = 0; j < result_length; j++)
			printf("%02X", ((unsigned char *) result)[j]);
		printf("\t0x%04" PRIX32 "\n", i);
	}
	return EXIT_SUCCESS;
}
