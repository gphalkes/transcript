#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

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
	int error;
	void *conv;
	char inbuf[1024], outbuf[1024], *inbuf_ptr, *outbuf_ptr;
	size_t result, i;
	size_t fill = 0, outleft;

	if (argc != 2)
		fatal("Usage: test <name>\n");

	if ((conv = charconv_open_convertor(argv[1], UTF16BE, 0, &error)) == NULL)
		fatal("Error opening convertor: %d\n", error);
	//~ if (feof(stdin) || getchar() == EOF)
		//~ fatal("WFT\n");

	while ((result = fread(inbuf, 1, 1024 - fill, stdin)) != 0) {
		inbuf_ptr = inbuf;
		outbuf_ptr = outbuf;
		fill += result;
		outleft = 1024;
		if ((error = charconv_to_unicode(conv, &inbuf_ptr, &fill, &outbuf_ptr, &outleft, 0)) != CHARCONV_SUCCESS)
			fatal("conversion result: %d\n", error);
		printf("fill: %zd, outleft: %zd\n", fill, outleft);
		for (i = 0; i < 1024 - outleft; i++)
			printf("\\x%02X", (uint8_t) outbuf[i]);
	}
	printf("\nEnd\n");
	return 0;
}