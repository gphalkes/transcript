#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <string.h>

#include "charconv.h"
#include "utf.h"

void fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	abort();
}


void show_names(void) {
	int count, i;
	const charconv_name_t *names;
	names = charconv_get_names(&count);
	printf("Display name count: %d\n", count);
	for (i = 0; i < count; i++)
		printf("name: %s (%d)\n", names[i].name, names[i].available);
}

int main(int argc, char *argv[]) {
	charconv_error_t error;
	void *conv;
	char inbuf[1024], outbuf[1024], *outbuf_ptr;
	const char *inbuf_ptr;
	size_t result, i;
	size_t fill = 0;

	int c;
	enum { FROM, TO } dir = FROM;
	charconv_error_t (*convert)(charconv_t *, const char **, const char *, char **, const char *, int) = charconv_from_unicode;
	int utf_type = CHARCONV_UTF8;
	int option_dump = 0;

	static struct { const char *name; int type; } utf_list[] = {
		{ "UTF-8", CHARCONV_UTF8 },
		{ "UTF-16", CHARCONV_UTF16 },
		{ "UTF-16BE", CHARCONV_UTF16BE },
		{ "UTF-16LE", CHARCONV_UTF16LE },
		{ "UTF-32", CHARCONV_UTF32 },
		{ "UTF-32BE", CHARCONV_UTF32BE },
		{ "UTF-32LE", CHARCONV_UTF32LE }};

	while ((c = getopt(argc, argv, "d:u:Dl")) != EOF) {
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
			case 'D':
				option_dump = 1;
				break;
			case 'l':
				show_names();
				exit(EXIT_SUCCESS);
			default:
				fatal("Error processing options\n");
		}
	}

	if (argc - optind != 1)
		fatal("Usage: test [-d <direction>] [-u <utf type>] [-D] <codepage name>\n");

	if ((conv = charconv_open_convertor(argv[optind], utf_type, 0, &error)) == NULL)
		fatal("Error opening convertor: %s\n", charconv_strerror(error));

	while ((result = fread(inbuf + fill, 1, 1024 - fill, stdin)) != 0) {
		inbuf_ptr = inbuf;
		outbuf_ptr = outbuf;
		fill += result;
		if ((error = convert(conv, &inbuf_ptr, inbuf + fill, &outbuf_ptr, outbuf + 1024, feof(stdin) ? CHARCONV_END_OF_TEXT : 0)) > CHARCONV_PART_SUCCESS_MAX)
			fatal("conversion result: %s\n", charconv_strerror(error));

		fill -= inbuf_ptr - inbuf;
		if (!option_dump) {
			printf("fill: %ld, outleft: %ld\n", fill, outbuf + 1024 - outbuf_ptr);
			for (i = 0; i < (size_t) (outbuf_ptr - outbuf); i++)
				printf("\\x%02X", (uint8_t) outbuf[i]);
			putchar('\n');
		}
		if (option_dump || (dir == TO && utf_type == CHARCONV_UTF8))
			printf("%.*s", (int) (outbuf_ptr - outbuf), outbuf);
		memmove(inbuf, inbuf_ptr, fill);
	}
	if (!option_dump && dir == TO && utf_type == CHARCONV_UTF8)
		putchar('\n');
	return 0;
}
