#include <arpa/inet.h>
#include <iconv.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "optionMacros.h"
#include "transcript/transcript.h"

static const char *option_converter_name;
static int option_generate_fallbacks, option_strip_mbcs_switch;

static void fatal(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  exit(EXIT_FAILURE);
}

static void print_usage(void) {
  printf("Usage: generate_table [<options>] <converter name>\n");
  printf(" -f,--generate-fallbacks         Include fallbacks in the table\n");
  printf(" -s,--strip-mbcs-switch          Strip 0E/0F bytes from MBCS output\n");
  exit(EXIT_SUCCESS);
}

/* clang-format off */
PARSE_FUNCTION(parse_options)
  OPTIONS
    OPTION('f', "generate-fallbacks", NO_ARG)
      option_generate_fallbacks = 1;
    END_OPTION
    OPTION('s', "strip-mbcs-switch", NO_ARG)
      option_strip_mbcs_switch = 1;
    END_OPTION
    OPTION('h', "help", NO_ARG)
      print_usage();
    END_OPTION
    DOUBLE_DASH
      NO_MORE_OPTIONS;
    END_OPTION

    printf("Unknown option " OPTFMT "\n", OPTPRARG);
  NO_OPTION
    if (option_converter_name == NULL)
      option_converter_name = optcurrent;
    else
      fatal("Only one converter name allowed\n");
  END_OPTIONS
  if (option_converter_name == NULL)
    fatal("No converter specified\n");
END_FUNCTION
/* clang-format on */

static int convert(transcript_t *handle, uint32_t codepoint, char *result, int *fallback) {
  const char *codepoint_ptr = (char *)&codepoint;
  char *result_limit = result + 80;

  switch (transcript_from_unicode(
      handle, &codepoint_ptr, codepoint_ptr + 4, &result, result_limit,
      TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE | TRANSCRIPT_END_OF_TEXT)) {
    case TRANSCRIPT_SUCCESS:
      if (transcript_from_unicode_flush(handle, &result, result_limit) != TRANSCRIPT_SUCCESS) {
        transcript_from_unicode_reset(handle);
        return -1;
      }
      break;
    case TRANSCRIPT_FALLBACK:
      if (!option_generate_fallbacks) return -1;

      *fallback = 1;
      if (transcript_from_unicode(handle, &codepoint_ptr, codepoint_ptr + 4, &result, result_limit,
                                  TRANSCRIPT_FILE_START | TRANSCRIPT_ALLOW_PRIVATE_USE |
                                      TRANSCRIPT_ALLOW_FALLBACK) != TRANSCRIPT_SUCCESS) {
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

  if ((handle = transcript_open_converter(option_converter_name,
                                          htons(1) == 1 ? TRANSCRIPT_UTF32BE : TRANSCRIPT_UTF32LE,
                                          0, NULL)) == NULL)
    fatal("Could not open transcript converter %s\n", option_converter_name);

  for (i = 0; i < 0x110000; i++) {
    char result[80];
    int result_length;
    int fallback = 0;

    result_length = convert(handle, i, result, &fallback);
    if (result_length < 0) continue;

    printf("0x");
    for (j = option_strip_mbcs_switch && result[0] == 0x0E ? 1 : 0;
         j < result_length - (option_strip_mbcs_switch && result[result_length - 1] == 0x0F); j++)
      printf("%02X", ((unsigned char *)result)[j]);
    printf("\t0x%04" PRIX32 "\n", i);
  }
  return EXIT_SUCCESS;
}
