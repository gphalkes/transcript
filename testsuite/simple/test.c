#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>

#include "transcript.h"

void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	transcript_error_t error;
	void *conv;
	char inbuf[1024], outbuf[1024], *outbuf_ptr;
	const char *inbuf_ptr;
	size_t i;
	size_t fill = 0;

	int c;
	enum { FROM, TO } dir = FROM;
	transcript_error_t (*convert)(transcript_t *, const char **, const char *, char **, const char *, int) = transcript_from_unicode;
	int utf_type = TRANSCRIPT_UTF8;
	int option_dump = 0;
	int flags = TRANSCRIPT_FILE_START;

	static struct { const char *name; int type; } utf_list[] = {
		{ "UTF-8", TRANSCRIPT_UTF8 },
		{ "UTF-16", TRANSCRIPT_UTF16 },
		{ "UTF-16BE", TRANSCRIPT_UTF16BE },
		{ "UTF-16LE", TRANSCRIPT_UTF16LE },
		{ "UTF-32", TRANSCRIPT_UTF32 },
		{ "UTF-32BE", TRANSCRIPT_UTF32BE },
		{ "UTF-32LE", TRANSCRIPT_UTF32LE }};

	while ((c = getopt(argc, argv, "d:u:D")) != EOF) {
		switch (c) {
			case 'd':
				if (strcasecmp(optarg, "to") == 0) {
					dir = TO;
					convert = transcript_to_unicode;
				} else if (strcasecmp(optarg, "from") == 0) {
					dir = FROM;
					convert = transcript_from_unicode;
				} else {
					fatal("Invalid argument for -d\n");
				}
				break;
			case 'u':
				for (i = 0; i < sizeof(utf_list) / sizeof(utf_list[0]); i++) {
					if (strcasecmp(optarg, utf_list[i].name) == 0) {
						utf_type = utf_list[i].type;
						break;
					}
				}
				if (i == sizeof(utf_list) / sizeof(utf_list[0]))
					fatal("Invalid argument for -u\n");
				break;
			case 'D':
				option_dump = 1;
				break;
			default:
				fatal("Error processing options\n");
		}
	}

	if (argc - optind != 1)
		fatal("Usage: test [-d <direction>] [-u <utf type>] [-D] <codepage name>\n");

	if ((conv = transcript_open_convertor(argv[optind], utf_type, 0, &error)) == NULL)
		fatal("Error opening convertor: %s\n", transcript_strerror(error));

	do {
		while (fill < 1024 && fscanf(stdin, " %2hhx ", inbuf + fill) == 1)
			fill++;
		inbuf_ptr = inbuf;
		outbuf_ptr = outbuf;
		if ((error = convert(conv, &inbuf_ptr, inbuf + fill, &outbuf_ptr, outbuf + 1024, feof(stdin) ? TRANSCRIPT_END_OF_TEXT : 0)) != TRANSCRIPT_SUCCESS)
			fatal("conversion result: %s\n", transcript_strerror(error));
		for (i = 0; i < (size_t) (outbuf_ptr - outbuf); i++)
			printf("%02X", (uint8_t) outbuf[i]);
		putchar('\n');
		fill -= (inbuf_ptr - inbuf);
		memmove(inbuf, inbuf_ptr, fill);
		flags &= ~TRANSCRIPT_FILE_START;
	} while (!feof(stdin));
	return 0;
}
