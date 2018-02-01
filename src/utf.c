/* Copyright (C) 2011-2012 G.P. Halkes
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
#include <string.h>

#include "transcript_internal.h"
#include "utf.h"

/* Routines for writing and reading 32 and 16 bit integers of different byte orders.
   The code below is written such that it is completely host-machine order agnostic.
   It may not be the very fastest way of doing this, but the differences in run-time
   are small, and this code is very readable.

   Also included are the machine-endian versions, which are essentially just a
   memcpy. This is done to allow the put_utfXX_YY functions to be created for the
   machine-endian versions as well.
*/
static void put32_le(uint32_t value, unsigned char *data) {
  data[0] = value;
  data[1] = value >> 8;
  data[2] = value >> 16;
  data[3] = value >> 24;
}

static void put32_me(uint32_t value, unsigned char *data) { memcpy(data, &value, 4); }

static void put32_be(uint32_t value, unsigned char *data) {
  data[0] = value >> 24;
  data[1] = value >> 16;
  data[2] = value >> 8;
  data[3] = value;
}

static uint32_t get32_le(const unsigned char *data) {
  return (uint32_t)data[0] | (((uint32_t)data[1]) << 8) | (((uint32_t)data[2]) << 16) |
         (((uint32_t)data[3]) << 24);
}

static uint32_t get32_me(const unsigned char *data) {
  uint32_t result;
  memcpy(&result, data, 4);
  return result;
}

static uint32_t get32_be(const unsigned char *data) {
  return (uint32_t)data[3] | (((uint32_t)data[2]) << 8) | (((uint32_t)data[1]) << 16) |
         (((uint32_t)data[0]) << 24);
}

static void put16_le(uint16_t value, unsigned char *data) {
  data[0] = value;
  data[1] = value >> 8;
}

static void put16_me(uint16_t value, unsigned char *data) { memcpy(data, &value, 2); }

static void put16_be(uint16_t value, unsigned char *data) {
  data[0] = value >> 8;
  data[1] = value;
}

static uint16_t get16_le(const unsigned char *data) {
  return (uint16_t)data[0] | (((uint16_t)data[1]) << 8);
}

static uint16_t get16_me(const unsigned char *data) {
  uint16_t result;
  memcpy(&result, data, 2);
  return result;
}

static uint16_t get16_be(const unsigned char *data) {
  return (uint16_t)data[1] | (((uint16_t)data[0]) << 8);
}

/** Simplification macro to check whether a codepoint is valid, and return an error if not. */
#define CHECK_CODEPOINT_RANGE()                                           \
  do {                                                                    \
    if (codepoint > UINT32_C(0x10ffff) ||                                 \
        (codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdfff))) \
      return TRANSCRIPT_INTERNAL_ERROR;                                   \
  } while (0)

/** Simplification macro to make sure that there is enough space in the output buffer, and return an
 * error if not. */
#define CHECK_OUTBYTESLEFT(_x) \
  if ((*outbuf) + (_x) > outbuflimit) return TRANSCRIPT_NO_SPACE;

/** Write a codepoint encoded as UTF-8. */
static transcript_error_t put_utf8(uint_fast32_t codepoint, char **outbuf,
                                   const char *outbuflimit) {
  CHECK_CODEPOINT_RANGE();

  if (codepoint < 0x80) {
    CHECK_OUTBYTESLEFT(1);
    *(*outbuf)++ = codepoint;
  } else if (codepoint < 0x800) {
    CHECK_OUTBYTESLEFT(2);
    *(*outbuf)++ = (codepoint >> 6) | 0xc0;
    *(*outbuf)++ = (codepoint & 0x3f) | 0x80;
  } else if (codepoint < 0x10000) {
    CHECK_OUTBYTESLEFT(3);
    *(*outbuf)++ = (codepoint >> 12) | 0xe0;
    *(*outbuf)++ = ((codepoint >> 6) & 0x3f) | 0x80;
    *(*outbuf)++ = (codepoint & 0x3f) | 0x80;
  } else {
    CHECK_OUTBYTESLEFT(4);
    *(*outbuf)++ = (codepoint >> 18) | 0xf0;
    *(*outbuf)++ = ((codepoint >> 12) & 0x3f) | 0x80;
    *(*outbuf)++ = ((codepoint >> 6) & 0x3f) | 0x80;
    *(*outbuf)++ = (codepoint & 0x3f) | 0x80;
  }
  return TRANSCRIPT_SUCCESS;
}

/** Write a codepoint encoded as CESU-8. */
static transcript_error_t put_cesu8(uint_fast32_t codepoint, char **outbuf,
                                    const char *outbuflimit) {
  CHECK_CODEPOINT_RANGE();

  if (codepoint < 0x80) {
    CHECK_OUTBYTESLEFT(1);
    *(*outbuf)++ = codepoint;
  } else if (codepoint < 0x800) {
    CHECK_OUTBYTESLEFT(2);
    *(*outbuf)++ = (codepoint >> 6) | 0xc0;
    *(*outbuf)++ = (codepoint & 0x3f) | 0x80;
  } else if (codepoint < 0x10000) {
    CHECK_OUTBYTESLEFT(3);
    *(*outbuf)++ = (codepoint >> 12) | 0xe0;
    *(*outbuf)++ = ((codepoint >> 6) & 0x3f) | 0x80;
    *(*outbuf)++ = (codepoint & 0x3f) | 0x80;
  } else {
    uint_fast32_t high_surrogate;
    CHECK_OUTBYTESLEFT(6);
    codepoint -= UINT32_C(0x10000);
    high_surrogate = (codepoint >> 10) + UINT32_C(0xd800);
    *(*outbuf)++ = (high_surrogate >> 12) | 0xe0;
    *(*outbuf)++ = ((high_surrogate >> 6) & 0x3f) | 0x80;
    *(*outbuf)++ = (high_surrogate & 0x3f) | 0x80;

    codepoint = (codepoint & 0x3ff) + UINT32_C(0xdc00);
    *(*outbuf)++ = (codepoint >> 12) | 0xe0;
    *(*outbuf)++ = ((codepoint >> 6) & 0x3f) | 0x80;
    *(*outbuf)++ = (codepoint & 0x3f) | 0x80;
  }
  return TRANSCRIPT_SUCCESS;
}

/** Simplification macro to check whether a codepoint is a legal codepoint, and return an error if
 * not. */
#define CHECK_CODEPOINT_ILLEGAL()                                                                \
  do {                                                                                           \
    if (codepoint >= 0xfdd0 &&                                                                   \
        (codepoint > UINT32_C(0x10ffff) || (codepoint & UINT32_C(0xfffe)) == UINT32_C(0xfffe) || \
         (/* codepoint >= UINT32_C(0xfdd0) && */ codepoint < UINT32_C(0xfdf0))))                 \
      return TRANSCRIPT_UTF_ILLEGAL;                                                             \
  } while (0)
/** Simplification macro to check whether a codepoint is a surrogate, and return an error if not. */
#define CHECK_CODEPOINT_SURROGATES()                                    \
  do {                                                                  \
    if (codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdfff)) \
      return TRANSCRIPT_UTF_ILLEGAL;                                    \
  } while (0)

/** Read a UTF-8 encoded codepoint.
    @param inbuf &nbsp;
    @param inbuflimit &nbsp;
    @param skip &nbsp;
        @param strict Whether to allow overlong sequences and high/low surrogates.
*/
static uint_fast32_t get_utf8internal(const char **inbuf, const char *inbuflimit, bool_t skip,
                                      bool_t strict) {
  const uint8_t *_inbuf = (const uint8_t *)*inbuf;
  uint_fast32_t codepoint = *_inbuf, least;
  size_t bytes;

  /* clang-format off */
  switch (codepoint) {
    case  0: case  1: case  2: case  3: case  4: case  5: case  6: case  7:
    case  8: case  9: case 10: case 11: case 12: case 13: case 14: case 15:
    case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23:
    case 24: case 25: case 26: case 27: case 28: case 29: case 30: case 31:
    case 32: case 33: case 34: case 35: case 36: case 37: case 38: case 39:
    case 40: case 41: case 42: case 43: case 44: case 45: case 46: case 47:
    case 48: case 49: case 50: case 51: case 52: case 53: case 54: case 55:
    case 56: case 57: case 58: case 59: case 60: case 61: case 62: case 63:
    case 64: case 65: case 66: case 67: case 68: case 69: case 70: case 71:
    case 72: case 73: case 74: case 75: case 76: case 77: case 78: case 79:
    case 80: case 81: case 82: case 83: case 84: case 85: case 86: case 87:
    case 88: case 89: case 90: case 91: case 92: case 93: case 94: case 95:
    case  96: case  97: case  98: case  99: case 100: case 101: case 102: case 103:
    case 104: case 105: case 106: case 107: case 108: case 109: case 110: case 111:
    case 112: case 113: case 114: case 115: case 116: case 117: case 118: case 119:
    case 120: case 121: case 122: case 123: case 124: case 125: case 126: case 127:
      (*inbuf)++;
      return codepoint;
    case 128: case 129: case 130: case 131: case 132: case 133: case 134: case 135:
    case 136: case 137: case 138: case 139: case 140: case 141: case 142: case 143:
    case 144: case 145: case 146: case 147: case 148: case 149: case 150: case 151:
    case 152: case 153: case 154: case 155: case 156: case 157: case 158: case 159:
    case 160: case 161: case 162: case 163: case 164: case 165: case 166: case 167:
    case 168: case 169: case 170: case 171: case 172: case 173: case 174: case 175:
    case 176: case 177: case 178: case 179: case 180: case 181: case 182: case 183:
    case 184: case 185: case 186: case 187: case 188: case 189: case 190: case 191:
    case 192: case 193:
      if (!skip)
        return TRANSCRIPT_UTF_ILLEGAL;
      (*inbuf)++;
      return 0;
    case 194: case 195: case 196: case 197: case 198: case 199: case 200: case 201:
    case 202: case 203: case 204: case 205: case 206: case 207: case 208: case 209:
    case 210: case 211: case 212: case 213: case 214: case 215: case 216: case 217:
    case 218: case 219: case 220: case 221: case 222: case 223:
      least = 0x80;
      bytes = 2;
      codepoint &= 0x1F;
      break;
    case 224: case 225: case 226: case 227: case 228: case 229: case 230: case 231:
    case 232: case 233: case 234: case 235: case 236: case 237: case 238: case 239:
      least = 0x800;
      bytes = 3;
      codepoint &= 0x0F;
      break;
    case 240: case 241: case 242: case 243: case 244:
      least = UINT32_C(0x10000);
      bytes = 4;
      codepoint &= 0x07;
      break;
    default:
      if (!skip)
        return TRANSCRIPT_UTF_ILLEGAL;
      (*inbuf)++;
      return 0;
  }
  /* clang-format on */

  if ((*inbuf) + bytes > inbuflimit) return TRANSCRIPT_UTF_INCOMPLETE;

  _inbuf++;
  for (; bytes > 1; _inbuf++, bytes--) {
    if ((*_inbuf & 0xc0) != 0x80) {
      if (!skip) return TRANSCRIPT_UTF_ILLEGAL;
      *inbuf = (const char *)_inbuf;
      return 0;
    }

    codepoint = (codepoint << 6) + (*_inbuf & 0x3f);
  }

  if (strict) {
    if (codepoint < least) {
      if (!skip) return TRANSCRIPT_UTF_ILLEGAL;
      *inbuf = (const char *)_inbuf;
      return 0;
    }
    CHECK_CODEPOINT_SURROGATES();
  }

  if (!skip) CHECK_CODEPOINT_ILLEGAL();

  *inbuf = (const char *)_inbuf;
  return codepoint;
}

/** Read a standard compliant UTF-8 encoded codepoint.

    This function is a wrapper around ::get_utf8internal to make the interface
    the same as for the other @c get_xxx functions.
*/
static uint_fast32_t get_utf8strict(const char **inbuf, const char *inbuflimit, bool_t skip) {
  return get_utf8internal(inbuf, inbuflimit, skip, TRUE);
}

/** Read a non-standard-compliant UTF-8 encoded codepoint.

    This version is permissive in what it accepts, in that it allows overlong
    sequences, and allows CESU-8 encoding using surrogate pairs.
*/
static uint_fast32_t get_utf8(const char **inbuf, const char *inbuflimit, bool_t skip) {
  const char *_inbuf = *inbuf;
  uint_fast32_t codepoint;

  codepoint = get_utf8internal(&_inbuf, inbuflimit, skip, FALSE);
  /* Check for surrogate characters. Low surrogates need to check the next codepoint as
     well to check for a complete surrogate pair. High surrogates are always wrong. */
  if ((codepoint & UINT32_C(0x1ffc00)) == UINT32_C(0xd800)) {
    uint_fast32_t next_codepoint;
    const char *_inbuf_save = _inbuf;

    next_codepoint = get_utf8internal(&_inbuf, inbuflimit, skip, FALSE);

    if (next_codepoint > UINT32_C(0xffff0000)) return next_codepoint;

    if ((next_codepoint & UINT32_C(0x1ffc00)) != UINT32_C(0xdc00)) {
      if (!skip) return TRANSCRIPT_UTF_ILLEGAL;
      *inbuf = _inbuf_save;
      return 0;
    }
    codepoint -= UINT32_C(0xd800);
    codepoint <<= 10;
    codepoint += next_codepoint - UINT32_C(0xdc00) + UINT32_C(0x10000);
  } else if ((codepoint & UINT32_C(0x1ffc00)) == UINT32_C(0xdc00)) {
    if (!skip) return TRANSCRIPT_UTF_ILLEGAL;
    *inbuf = _inbuf;
    return 0;
  }
  *inbuf = (const char *)_inbuf;
  return codepoint;
}

/* We need versions for big, little and machine endian for the UTF-16 and UTF-32
   routines. Of course we could add another layer of indirection, but to allow some optimization
   in these routines (which will be called frequently), we want them to be complete routines.

   However, we don't want code duplication, so we use a header file in which we define the
   (static) functions. In the header file we paste the value of UTF_ENDIAN_H_VERSION to the
   name of both the function and the swap functions they call. This way we create the necessary
   XXX_a and XXX_b routines.
*/
#define UTF_ENDIAN_H_VERSION _le
#include "utf_endian.h"
#undef UTF_ENDIAN_H_VERSION
#define UTF_ENDIAN_H_VERSION _be
#include "utf_endian.h"
#undef UTF_ENDIAN_H_VERSION
#define UTF_ENDIAN_H_VERSION _me
#include "utf_endian.h"
#undef UTF_ENDIAN_H_VERSION

/** @internal
    @brief Retrieve a function pointer for writing Unicode codepoints, encoded in one of the UTF-X
   encodings.
*/
put_unicode_func_t _transcript_get_put_unicode(int type) {
  switch (type) {
    case TRANSCRIPT_UTF8:
    case _TRANSCRIPT_UTF8_LOOSE:
      return put_utf8;
    case TRANSCRIPT_UTF16:
      return put_utf16_me;
    case TRANSCRIPT_UTF32:
      return put_utf32_me;

    case TRANSCRIPT_UTF16BE:
      return put_utf16_be;
    case TRANSCRIPT_UTF16LE:
      return put_utf16_le;
    case TRANSCRIPT_UTF32BE:
      return put_utf32_be;
    case TRANSCRIPT_UTF32LE:
      return put_utf32_le;

    case _TRANSCRIPT_CESU8:
      return put_cesu8;
    default:
      return NULL;
  }
}

/** @internal
    @brief Retrieve a function pointer for reading Unicode codepoints, encoded in one of the UTF-X
   encodings.
*/
get_unicode_func_t _transcript_get_get_unicode(int type) {
  switch (type) {
    case TRANSCRIPT_UTF8:
      return get_utf8strict;
    case TRANSCRIPT_UTF16:
      return get_utf16_me;
    case TRANSCRIPT_UTF32:
      return get_utf32_me;

    case _TRANSCRIPT_UTF8_LOOSE:
    case _TRANSCRIPT_CESU8:
      return get_utf8;

    case TRANSCRIPT_UTF16BE:
      return get_utf16_be;
    case TRANSCRIPT_UTF16LE:
      return get_utf16_le;
    case TRANSCRIPT_UTF32BE:
      return get_utf32_be;
    case TRANSCRIPT_UTF32LE:
      return get_utf32_le;

    case _TRANSCRIPT_UTF32_NO_CHECK:
      return _transcript_get_utf32_no_check;

    default:
      return NULL;
  }
}

/** @internal
    @brief Read a codepoint encoded as UTF-32 (Machine Endian), without validity checking.

    This function is provided for reading back converted output which we know
    to be valid. Should be used mainly for points in the code where this code
    will be called frequently.
*/
uint_fast32_t _transcript_get_utf32_no_check(const char **inbuf, const char *inbuflimit,
                                             bool_t skip) {
  uint32_t codepoint;

  (void)inbuflimit;
  (void)skip;

  memcpy(&codepoint, *inbuf, 4);

  *inbuf += 4;
  return codepoint;
}

/** @internal
    @brief Write a codepoint encoded as UTF-16 (Machine Endian), without validity checking.

    This function is provided for writing back converted input which we know
    to be valid, and for which we know the buffer to be large enough. Should be
    used mainly for points in the code where this code will be called frequently.
*/
transcript_error_t _transcript_put_utf16_no_check(uint_fast32_t codepoint, char **outbuf) {
  uint16_t tmp;

  if (codepoint < UINT32_C(0xffff)) {
    tmp = codepoint;
    memcpy(*outbuf, &tmp, 2);
    *outbuf += 2;
  } else {
    codepoint -= UINT32_C(0x10000);
    tmp = (UINT32_C(0xd800) + (codepoint >> 10));
    memcpy(*outbuf, &tmp, 2);
    tmp = (UINT32_C(0xdc00) + (codepoint & 0x3ff));
    memcpy((*outbuf) + 2, &tmp, 2);
    *outbuf += 4;
  }
  return TRANSCRIPT_SUCCESS;
}
