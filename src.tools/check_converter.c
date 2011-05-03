#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <iconv.h>
#include <arpa/inet.h>
#include <string.h>

#include "transcript.h"
#include "optionMacros.h"

static const char *option_transcript_name, *option_iconv_name;
static int option_unicode, option_no_private_use, option_check_fallbacks, option_ignore_tag;
static uint32_t option_start;

static void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

static void print_usage(void) {
	printf("Usage: check_converter [<options>] <converter name>\n");
	printf(" -t<name>,--transcript-name=<name>  Use <name> as converter name for transcript\n");
	printf(" -u,--unicode                       Ignore surrogates and non-characters\n");
	printf(" -p,--no-private-use                Ignore private-use mappings\n");
	printf(" -f,--check-fallbacks               Compare fallbacks as well\n");
	printf(" -s<start>,--start=<start>          Start iteration from <start>\n");
	printf(" -T,--ignore-tag                    Ignore tag-character mappings\n");
	exit(EXIT_SUCCESS);
}

PARSE_FUNCTION(parse_options)
	OPTIONS
		OPTION('t', "transcript-name", REQUIRED_ARG)
			option_transcript_name = optArg;
		END_OPTION
		OPTION('u', "unicode", NO_ARG)
			option_unicode = 1;
		END_OPTION
		OPTION('p', "no-private-use", NO_ARG)
			option_no_private_use = 1;
		END_OPTION
		OPTION('h', "help", NO_ARG)
			print_usage();
		END_OPTION
		OPTION('f', "check-fallbacks", NO_ARG)
			option_check_fallbacks = 1;
		END_OPTION
		OPTION('s', "start", REQUIRED_ARG)
			option_start = strtol(optArg, NULL, 16);
		END_OPTION
		OPTION('T', "ignore-tag", NO_ARG)
			option_ignore_tag = 1;
		END_OPTION
		DOUBLE_DASH
			NO_MORE_OPTIONS;
		END_OPTION

		printf("Unknown option " OPTFMT "\n", OPTPRARG);
	NO_OPTION
		if (option_iconv_name == NULL)
			option_iconv_name = optcurrent;
		else
			fatal("Only one converter name allowed\n");
	END_OPTIONS
	if (option_iconv_name == NULL)
		fatal("No converter specified\n");
	if (option_transcript_name == NULL)
		option_transcript_name = option_iconv_name;
END_FUNCTION


static int iconv_convert(iconv_t handle, uint32_t codepoint, char *result, int *fallback) {
	char *codepoint_ptr = (char *) &codepoint;
	size_t codepoint_len = 4, result_len = 80;
	size_t call_result;

	if ((call_result = iconv(handle, &codepoint_ptr, &codepoint_len, &result, &result_len)) == (size_t) -1) {
		iconv(handle, NULL, NULL, NULL, NULL);
		return -1;
	}
	*fallback = call_result != 0;
	if (iconv(handle, NULL, NULL, &result, &result_len) == (size_t) -1) {
		iconv(handle, NULL, NULL, NULL, NULL);
		return -1;
	}
	return 80 - result_len;
}

static uint32_t iconv_revert(iconv_t handle, char *seq, int length) {
	uint32_t codepoint_buffer[20];
	char *codepoint_ptr = (char *) codepoint_buffer;
	size_t seq_len = length, codepoint_len = 80;
	size_t iconv_result;

	iconv_result = iconv(handle, &seq, &seq_len, &codepoint_ptr, &codepoint_len);
	iconv(handle, NULL, NULL, NULL, NULL);
	if (iconv_result == (size_t) -1)
		return UINT32_C(0xffffffff);
	if ((80 - codepoint_len) != 4)
		return UINT32_C(0xffffffff);
	return codepoint_buffer[0];
}

static int transcript_convert(transcript_t *handle, uint32_t codepoint, char *result, int *fallback) {
	const char *codepoint_ptr = (char *) &codepoint;
	char *result_limit = result + 80;

	switch (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4,
			&result, result_limit, TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE | TRANSCRIPT_END_OF_TEXT))
	{
		case TRANSCRIPT_SUCCESS:
			if (transcript_from_unicode_flush(handle, &result, result_limit) != TRANSCRIPT_SUCCESS) {
				transcript_from_unicode_reset(handle);
				return -1;
			}
			break;
		case TRANSCRIPT_FALLBACK:
			if (!option_check_fallbacks)
				return -1;

			if (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4,
					&result, result_limit, TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE |
					TRANSCRIPT_END_OF_TEXT | TRANSCRIPT_ALLOW_FALLBACK) != TRANSCRIPT_SUCCESS)
			{
				return -1;
				transcript_from_unicode_reset(handle);
			}
			*fallback = 1;
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

static uint32_t transcript_revert(transcript_t *handle, const char *seq, int length) {
	uint32_t codepoint_buffer[20];
	char *codepoint_ptr = (char *) codepoint_buffer;

	switch (transcript_to_unicode(handle, &seq, seq + length, &codepoint_ptr, codepoint_ptr + 20,
			TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE)) {
		case TRANSCRIPT_SUCCESS:
			break;
		default:
			transcript_to_unicode_reset(handle);
			return UINT32_C(0xffffffff);
	}
	transcript_to_unicode_reset(handle);
	if ((codepoint_ptr - (char *) codepoint_buffer) != 4)
		return UINT32_C(0xffffffff);
	return codepoint_buffer[0];
}

static void print_result(char *result, int result_length, int fallback) {
	int i;
	if (result_length == -1) {
		printf("<failed>");
	} else {
		if (fallback)
			printf("*");
		for (i = 0; i < result_length; i++)
			printf("%02x", ((unsigned char *) result)[i]);
	}
}

int main(int argc, char *argv[]) {
	iconv_t iconv_handle, iconv_revert_handle;
	transcript_t *transcript_handle;
	uint32_t i, reverted;
	int result = EXIT_SUCCESS;
	transcript_error_t error;

	parse_options(argc, argv);

	if ((iconv_handle = iconv_open(option_iconv_name, htons(1) == 1 ? "UTF-32BE" : "UTF-32LE")) == (iconv_t) -1)
		fatal("Could not open iconv converter %s\n", option_iconv_name);
	if ((iconv_revert_handle = iconv_open(htons(1) == 1 ? "UTF-32BE" : "UTF-32LE", option_iconv_name)) == (iconv_t) -1)
		fatal("Could not open iconv revertor %s\n", option_iconv_name);

	if ((transcript_handle = transcript_open_converter(option_transcript_name,
			htons(1) == 1 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF32LE, 0, &error)) == NULL)
		fatal("Could not open transcript converter %s: %s\n", option_transcript_name, transcript_strerror(error));


	for (i = option_start; i < 0x110000; i++) {
		char iconv_result[80], transcript_result[80];
		int iconv_result_length, transcript_result_length;
		int iconv_fallback = 0, transcript_fallback = 0;

		iconv_result_length = iconv_convert(iconv_handle, i, iconv_result, &iconv_fallback);
		transcript_result_length = transcript_convert(transcript_handle, i, transcript_result, &transcript_fallback);
		if (iconv_result_length != transcript_result_length ||
				(iconv_result_length >= 0 && memcmp(iconv_result, transcript_result, iconv_result_length) != 0) ||
				iconv_fallback != transcript_fallback)
		{
			/* Filter out tag mappings. These can not be mapped, but glibc iconv sometimes simply discards them. */
			if (i >= 0xe0000 && i < 0xe0100 && (option_ignore_tag || iconv_result_length == 0) && transcript_result_length == -1)
				continue;
			/* For unicode: ignore surrogates and non-character mappings */
			if (option_unicode && ((i >= 0xd800 && i < 0xe000) || (i & 0xfffe) == 0xfffe || (i >= 0xfdd0 && i < 0xfdf0)))
				continue;
			/* Ignore private use mappings on request if transcript can't convert them. */
			if (option_no_private_use && ((i >= 0xe000 && i < 0xf900) || i >= 0xf0000) && transcript_result_length == -1)
				continue;

			result |= 1;
			printf("U%04X: different result: iconv: ", i);
			print_result(iconv_result, iconv_result_length, iconv_fallback);
			printf("  transcript: ");
			print_result(transcript_result, transcript_result_length, transcript_fallback);
			putchar('\n');
		}

		if (iconv_result_length > 0 && !iconv_fallback) {
			if ((reverted = iconv_revert(iconv_revert_handle, iconv_result, iconv_result_length)) != i) {
				result |= 2;
				printf("U%04X: iconv revert did not result in original (U%04X)\n", i, reverted);
			}
		}

		if (transcript_result_length > 0 && !transcript_fallback) {
			if ((reverted = transcript_revert(transcript_handle, transcript_result, transcript_result_length)) != i) {
				result |= 4;
				printf("U%04X: transcript revert did not result in original (U%04X)\n", i, reverted);
			}
		}
	}
	return result;
}
