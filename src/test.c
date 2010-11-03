#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <strings.h>

#include "charconv.h"
#include "utf.h"

void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	abort();
}

int main(int argc, char *argv[]) {
	charconv_error_t error;
	void *conv;
	char inbuf[1024], outbuf[1024], *inbuf_ptr, *outbuf_ptr;
	size_t result, i;
	size_t fill = 0, outleft;

	int c;
	enum { FROM, TO } dir = FROM;
	charconv_error_t (*convert)(charconv_t *, char **, size_t *, char **, size_t *, int) = charconv_from_unicode;
	int utf_type = UTF8;

	static struct { const char *name; int type; } utf_list[] = {
		{ "UTF-8", UTF8 },
		{ "UTF-16", UTF16 },
		{ "UTF-16BE", UTF16BE },
		{ "UTF-16LE", UTF16LE },
		{ "UTF-32", UTF32 },
		{ "UTF-32BE", UTF32BE },
		{ "UTF-32LE", UTF32LE }};

	while ((c = getopt(argc, argv, "d:u:")) != EOF) {
		switch (c) {
			case 'd':
				if (strcasecmp(optarg, "to") == 0) {
					dir = TO;
					convert = charconv_to_unicode;
				} else if (strcasecmp(optarg, "from") == 0) {
					dir = FROM;
					convert = charconv_from_unicode;
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
			default:
				fatal("Error processing options\n");
		}
	}

	if (argc - optind != 1)
		fatal("Usage: test [-d <direction>] [-u <utf type>] <codepage name>\n");

	if ((error = charconv_init()) != CHARCONV_SUCCESS)
		fatal("Error initializing charconv library: %s\n", charconv_strerror(error));


	if ((conv = charconv_open_convertor(argv[optind], utf_type, 0, &error)) == NULL)
		fatal("Error opening convertor: %s\n", charconv_strerror(error));

	while ((result = fread(inbuf, 1, 1024 - fill, stdin)) != 0) {
		inbuf_ptr = inbuf;
		outbuf_ptr = outbuf;
		fill += result;
		outleft = 1024;
		if ((error = convert(conv, &inbuf_ptr, &fill, &outbuf_ptr, &outleft, feof(stdin) ? CHARCONV_END_OF_TEXT : 0)) != CHARCONV_SUCCESS)
			fatal("conversion result: %s\n", charconv_strerror(error));
		printf("fill: %zd, outleft: %zd\n", fill, outleft);
		for (i = 0; i < 1024 - outleft; i++)
			printf("\\x%02X", (uint8_t) outbuf[i]);
		if (dir == TO && utf_type == UTF8)
			printf("\n%.*s", (int) i, outbuf);
	}
	putchar('\n');
	return 0;
}
