#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <iconv.h>
#include <arpa/inet.h>
#include <string.h>

#include "transcript.h"

static void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

static int iconv_convert(iconv_t handle, uint32_t codepoint, char *result, int *fallback) {
	char *codepoint_ptr = (char *) &codepoint;
	size_t codepoint_len = 4, result_len = 80;
	size_t call_result;

	if ((call_result = iconv(handle, &codepoint_ptr, &codepoint_len, &result, &result_len)) == (size_t) -1)
		return -1;
	*fallback = call_result != 0;
	if (iconv(handle, NULL, NULL, &result, &result_len) == (size_t) -1)
		return -1;
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

static uint32_t transcript_revert(transcript_t *handle, const char *seq, int length) {
	uint32_t codepoint_buffer[20];
	char *codepoint_ptr = (char *) codepoint_buffer;

	switch (transcript_to_unicode(handle, &seq, seq + length, &codepoint_ptr, codepoint_ptr + 20, TRANSCRIPT_ALLOW_PRIVATE_USE)) {
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

static int transcript_convert(transcript_t *handle, uint32_t codepoint, char *result, int *fallback) {
	const char *codepoint_ptr = (char *) &codepoint;
	char *result_limit = result + 80;

	switch (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4,
			&result, result_limit, TRANSCRIPT_ALLOW_PRIVATE_USE))
	{
		case TRANSCRIPT_SUCCESS:
			if (transcript_from_unicode_flush(handle, &result, result_limit) != TRANSCRIPT_SUCCESS)
				return -1;
			break;
		case TRANSCRIPT_FALLBACK:
			*fallback = 1;
			if (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4,
					&result, result_limit, TRANSCRIPT_ALLOW_PRIVATE_USE | TRANSCRIPT_ALLOW_FALLBACK) != TRANSCRIPT_SUCCESS)
				return -1;
			if (transcript_from_unicode_flush(handle, &result, result_limit) != TRANSCRIPT_SUCCESS)
				return -1;
		default:
			return -1;
	}
	return 80 - (result_limit - result);
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

	if (argc != 2)
		fatal("Usage: check_convertor.c <convertor name>\n");

	if ((iconv_handle = iconv_open(argv[1], htons(1) == 1 ? "UTF-32BE" : "UTF-32LE")) == (iconv_t) -1)
		fatal("Could not open iconv convertor %s\n", argv[1]);
	if ((iconv_revert_handle = iconv_open(htons(1) == 1 ? "UTF-32BE" : "UTF-32LE", argv[1])) == (iconv_t) -1)
		fatal("Could not open iconv revertor %s\n", argv[1]);

	if ((transcript_handle = transcript_open_convertor(argv[1], htons(1) == 1 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF32LE,
			0, NULL)) == NULL)
		fatal("Could not open transcript convertor %s\n", argv[1]);


	for (i = 0; i < 0x110000; i++) {
		char iconv_result[80], transcript_result[80];
		int iconv_result_length, transcript_result_length;
		int iconv_fallback = 0, transcript_fallback = 0;

		iconv_result_length = iconv_convert(iconv_handle, i, iconv_result, &iconv_fallback);
		transcript_result_length = transcript_convert(transcript_handle, i, transcript_result, &transcript_fallback);
		if (iconv_result_length != transcript_result_length ||
				(iconv_result_length >= 0 && memcmp(iconv_result, transcript_result, iconv_result_length) != 0)) {
			/* Filter out tag mappings. */
			if (i >= 0xe0000 && i < 0xe0100 && iconv_result_length == 0 && transcript_result_length == -1)
				continue;
			printf("U%04X: different result: iconv: ", i);
			print_result(iconv_result, iconv_result_length, iconv_fallback);
			printf("  transcript: ");
			print_result(transcript_result, transcript_result_length, transcript_fallback);
			putchar('\n');
		}

		if (iconv_result_length > 0 && !iconv_fallback)
			if ((reverted = iconv_revert(iconv_revert_handle, iconv_result, iconv_result_length)) != i)
				printf("U%04X: iconv revert did not result in original (U%04X)\n", i, reverted);

		if (transcript_result_length > 0 && !transcript_fallback)
			if ((reverted = transcript_revert(transcript_handle, transcript_result, transcript_result_length)) != i)
				printf("U%04X: transcript revert did not result in original (U%04X)\n", i, reverted);
	}
	return EXIT_SUCCESS;
}
