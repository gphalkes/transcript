/* Copyright (C) 2010 G.P. Halkes
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


/* What do we need to know in the convertor:
	- which sets correspond to GL and GR, and C0 and C1 (if these are actually switchable for any of the supported sets)
	- which sequence selects which set for G0 through G3
per set:
	- #bytes per char
	- CCT convertor
*/
#include <string.h>
#include <search.h>

#include "charconv_internal.h"
#include "convertors.h"
#include "utf.h"

enum {
	CCT_FLAG_WRITE = (1<<0),
	CCT_FLAG_ASCII = (1<<1),
	CCT_FLAGS_SHORT_SEQ = (1<<6),
	CCT_FLAG_LARGE_SET = (1<<7)
};

enum {
	LS0 = (1<<0),
	LS1 = (1<<1),
	LS2 = (1<<2),
	LS3 = (1<<3),
	SS2 = (1<<4),
	SS3 = (1<<5),
};

enum {
	ISO2022_JP,
	ISO2022_JP1,
	ISO2022_JP2,
	ISO2022_JP3,
	ISO2022_JP2004,
	ISO2022_KR,
	ISO2022_CN,
	ISO2022_CNEXT,
	ISO2022_TEST
};

typedef struct {
	const char *name;
	int iso2022_type;
} name_to_iso2022type;

typedef struct _charconv_iso2022_cct_handle_t cct_handle_t;


struct _charconv_iso2022_cct_handle_t {
	charconv_t *cct; /* Handle for the table based convertor. */
	uint_fast8_t bytes_per_char; /* Bytes per character code. */
	uint_fast8_t seq_len; /* Length of the escape sequence used to shift. */
	char escape_seq[7]; /* The escape sequence itselft. */
	uint_fast8_t high_bit; /* Whether the cct has the high bit set for characters. */
	uint_fast8_t flags;
	cct_handle_t *prev, *next; /* Doubly-linked list ptrs. */
};

typedef struct _charconv_iso2022_state_t state_t;


typedef struct {
	charconv_common_t common;
	cct_handle_t *g_initial[4];
	cct_handle_t *g_sets[4]; /* Linked lists of possible tables. */
	cct_handle_t *ascii;
	state_t state;
	int iso2022_type;
	int shift_types;
} convertor_state_t;

typedef struct {
	const char *name;
	uint_fast8_t bytes_per_char;
	char final_byte;
	bool high_bit;
	uint_fast8_t flags;
} cct_descriptor_t ;

/* We use the lower part of the ISO8859-1 convertor for ASCII. */
static cct_descriptor_t ascii = { NULL, 1, '\x42', false, CCT_FLAG_ASCII };
static cct_descriptor_t iso8859_1 = { NULL, 1, '\x41', true, CCT_FLAG_LARGE_SET };//2
static cct_descriptor_t jis_x_0201_1976_kana = { "ibm-897_P100-1995", 1, '\x49', true, 0 };
static cct_descriptor_t jis_x_0201_1976_roman = { "ibm-897_P100-1995", 1, '\x4a', false, 0 };
static cct_descriptor_t jis_x_0208_1978 = { "ibm-955_P110-1997", 2, '\x40', false, 0 };
/* This is the 1990 version, not the 1983 version, which includes two extra characters. */
/* FIXME: gconv simply uses the extra two characters. On the other hand, for JP-3, it
   does use the 2004 version for characters only in the new version... The proper version
   appears to be 13240, but that seems to be missing one character (based on the
   number of characters that IBM says is in there). */
static cct_descriptor_t jis_x_0208_1983 = { "ibm-5048_P100-1995", 2, '\x42', true, 0 };
static cct_descriptor_t jis_x_0212_1990 = { "ibm-5049_P100-1995", 2, '\x44', true, 0 };

//FIXME: use the correct codepage names and check the high_bit flag
static cct_descriptor_t jis_x_0213_2000_1 = { "JIS-X-0213-2000-1", 2, '\x4f', true, 0 };
static cct_descriptor_t jis_x_0213_2000_2 = { "JIS-X-0213-2000-2", 2, '\x50', true, 0 };
static cct_descriptor_t jis_x_0213_2004_1 = { "JIS-X-0213-2004-1", 2, '\x51', true, 0 };
static cct_descriptor_t iso8859_7 = { "ibm-813_P100-1995", 1, '\x4f', true, CCT_FLAG_LARGE_SET }; //2
static cct_descriptor_t ksc5601_1987 = { "KSC5601-1987", 2, '\x43', true, 0 };
static cct_descriptor_t gb2312_1980 = { "GB2312-1980", 2, '\x41', true, 0 };

static cct_descriptor_t cns_11643_1992_1 = { "CNS-11643-1992-1", 2, '\x47', true, 0 };//1
static cct_descriptor_t cns_11643_1992_2 = { "CNS-11643-1992-2", 2, '\x48', true, 0 };//2
static cct_descriptor_t cns_11643_1992_3 = { "CNS-11643-1992-3", 2, '\x49', true, 0 };//3
static cct_descriptor_t cns_11643_1992_4 = { "CNS-11643-1992-4", 2, '\x4a', true, 0 };//3
static cct_descriptor_t cns_11643_1992_5 = { "CNS-11643-1992-5", 2, '\x4b', true, 0 };//3
static cct_descriptor_t cns_11643_1992_6 = { "CNS-11643-1992-6", 2, '\x4c', true, 0 };//3
static cct_descriptor_t cns_11643_1992_7 = { "CNS-11643-1992-7", 2, '\x4d', true, 0 };//3
static cct_descriptor_t iso_ir_165 = { "ISO-IR-165", 2, '\x45', true, 0 };//1

static const char *ls[] = { "\x0f", "\x0e", "\x1b\x6e", "\x1b\x6f", "\x1b\x4e", "\x1b\x4f" };

static void to_unicode_reset(convertor_state_t *handle);
static void from_unicode_reset(convertor_state_t *handle);
static void close_convertor(convertor_state_t *handle);

static int check_escapes(convertor_state_t *handle, char **inbuf, size_t *inbytesleft, bool skip) {
	cct_handle_t *ptr;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t i, max;

	/* Limit the number of bytes to check to 5. No sequence that large has been
	   assigned yet, so that won't be a problem. */
	max = *inbytesleft > 5 ? 5 : *inbytesleft;

	for (i = 1; i < max; i++) {
		if (_inbuf[i] >= 0x20 && _inbuf[i] <= 0x2f)
			continue;
		if (_inbuf[i] >= 0x40 && _inbuf[i] <= 0x7f)
			goto sequence_found;
		if (skip) {
			*inbuf += i - 1;
			*inbytesleft -= i - 1;
		}
		return CHARCONV_ILLEGAL;
	}

	if (i == 5) {
		if (skip) {
			*inbuf += 5;
			*inbytesleft -= 5;
		}
		return CHARCONV_ILLEGAL;
	} else {
		return CHARCONV_INCOMPLETE;
	}

sequence_found:
	max = i;

	if (!skip) {
		for (i = 0; i < 3; i++) {
			for (ptr = handle->g_sets[i]; ptr != NULL; ptr = ptr->next) {
				if (max != ptr->seq_len)
					continue;

				if (memcmp(_inbuf, ptr->escape_seq, ptr->seq_len) != 0)
					continue;

				handle->state.g_to[i] = ptr;
				*inbuf += max;
				*inbytesleft += max;
				return CHARCONV_SUCCESS;
			}
		}
	}
	if (skip) {
		*inbuf += max;
		*inbytesleft += max;
	}
	return CHARCONV_ILLEGAL;
}

#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbytesleft)) != 0) \
		return result; \
} while (0)

static int to_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	uint_fast8_t state;
	int result;

	while (_inbytesleft > 0) {
		/* We accept shift sequences even in non-locking shift states. This
		   follows the 'be liberal in what you accept' policy. */
		if (*_inbuf < 32) {
			/* Control characters. */
			if (*_inbuf == 0x1b) {
				/* Escape sequence. */
				if (_inbytesleft == 1)
					goto incomplete_char;

				/* _inbytesleft at least 2 at this point. */
				switch (_inbuf[1]) {
					case 0x6e:
						state = 2;
						goto state_shift_done;
					case 0x6f:
						state = 3;
						goto state_shift_done;
					case 0x4e:
						state = (handle->state.to & 3) | (2 << 2);
						goto state_shift_done;
					case 0x4f:
						state = (handle->state.to & 3) | (3 << 2);
						goto state_shift_done;

				state_shift_done:
						if (handle->state.g_to[state > 3 ? state >> 2 : state] == NULL)
							return CHARCONV_ILLEGAL;
						handle->state.to = state;

						_inbuf = (uint8_t *) ((*inbuf) += 2);
						_inbytesleft = ((*inbytesleft) -= 2);
						continue;

					default:
						break;
				}

				switch (check_escapes(handle, inbuf, inbytesleft, false)) {
					case CHARCONV_INCOMPLETE:
						goto incomplete_char;
					case CHARCONV_ILLEGAL:
						return CHARCONV_ILLEGAL;
					case CHARCONV_SUCCESS:
						_inbuf = (uint8_t *) *inbuf;
						_inbytesleft = *inbytesleft;
						continue;
					default:
						return CHARCONV_INTERNAL_ERROR;
				}
			} else if (*_inbuf == 0xe) {
				/* Shift out. */
				if (handle->state.g_to[1] == NULL)
					return CHARCONV_ILLEGAL;
				handle->state.to = 1;
				_inbuf = (uint8_t *) ++(*inbuf);
				_inbytesleft = --(*inbytesleft);
				continue;
			} else if (*_inbuf == 0xf) {
				/* Shift in. */
				handle->state.to = 0;
				_inbuf = (uint8_t *) ++(*inbuf);
				_inbytesleft = --(*inbytesleft);
				continue;
			}
			/* Other control.
			   Note that we don't issue a reset of the state after CRNL. Eventhough the state
			   should be re-initialised after CRNL, this doesn't mean we should ignore all
			   previous state. The input may not conform the the standard that well... */
			PUT_UNICODE(*_inbuf);
			_inbuf++;
			_inbytesleft--;
		} else if (*_inbuf & 0x80) {
			/* All ISO-2022 convertors implemented here are 7 bit only. */
			return CHARCONV_ILLEGAL;
		} else {
			char buffer[3];
			char *buffer_ptr = buffer;
			uint32_t codepoint;
			char *codepoint_ptr = (char *) &codepoint;
			size_t codepoint_size = 4;
			int i;

			state = handle->state.to;
			if (state > 3)
				state >>= 2;

			if (_inbytesleft < handle->state.g_to[state]->bytes_per_char)
				goto incomplete_char;

			for (i = 0; i < handle->state.g_to[state]->bytes_per_char; i++)
				buffer[i] = _inbuf[i] | (handle->state.g_to[state]->high_bit << 7);
			size_t buffer_size = handle->state.g_to[state]->bytes_per_char;

			if ((result = handle->state.g_to[state]->cct->convert_to(handle->state.g_to[state]->cct, &buffer_ptr, &buffer_size,
					&codepoint_ptr, &codepoint_size, 0)) != CHARCONV_SUCCESS)
				return result;
			PUT_UNICODE(codepoint);
			_inbuf += handle->state.g_to[state]->bytes_per_char;
			_inbytesleft -= handle->state.g_to[state]->bytes_per_char;
		}

		handle->state.to &= 3;
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;

incomplete_char:
	if (flags & CHARCONV_END_OF_TEXT) {
		if (flags & CHARCONV_SUBST_ILLEGAL) {
			PUT_UNICODE(0xfffd);
			(*inbuf) += _inbytesleft;
			*inbytesleft = 0;
			return CHARCONV_SUCCESS;
		}
		return CHARCONV_ILLEGAL_END;
	}
	return CHARCONV_INCOMPLETE;
}

static charconv_error_t to_unicode_skip(convertor_state_t *handle, char **inbuf, size_t *inbytesleft) {
	uint_fast8_t state;

	if (*inbytesleft == 0)
		return CHARCONV_INCOMPLETE;

	if (**inbuf == 0x1b)
		return check_escapes(handle, inbuf, inbytesleft, true) == CHARCONV_INCOMPLETE ?
			CHARCONV_INCOMPLETE : CHARCONV_SUCCESS;

	state = handle->state.to;
	if (state > 3)
		state >>= 2;


	if (*inbytesleft < handle->state.g_to[state]->bytes_per_char)
		return CHARCONV_INCOMPLETE;

	handle->state.to &= 3;

	*inbuf += handle->state.g_to[state]->bytes_per_char;
	*inbytesleft -= handle->state.g_to[state]->bytes_per_char;
	return CHARCONV_SUCCESS;
}

static void to_unicode_reset(convertor_state_t *handle) {
	memcpy(handle->state.g_to, handle->g_initial, sizeof(handle->g_initial));
	handle->state.to = 0;
}

#define PUT_BYTES(count, buffer) do { size_t _i, _count = count; \
	if (*outbytesleft < _count) \
		return CHARCONV_NO_SPACE; \
	for (_i = 0; _i < _count; _i++) \
		(*outbuf)[_i] = buffer[_i] & 0x7f; \
	*outbuf += _count; \
	*outbytesleft -= _count; \
} while (0)

static charconv_error_t switch_to_set(convertor_state_t *handle, cct_handle_t *cct, uint_fast8_t g,
		char **outbuf, size_t *outbytesleft)
{
	if (handle->state.g_from[g] != cct) {
		PUT_BYTES(cct->seq_len, cct->escape_seq);
		handle->state.g_from[g] = cct;
	}
	if (handle->state.from != g && ((handle->state.from & 3) != (1 << 2))) {
		if (handle->shift_types & (1 << g)) {
			PUT_BYTES(1 + (g >> 1), ls[g]);
			handle->state.from = g;
		} else if (g > 1 && (handle->shift_types & (1 << (g + 2)))) {
			PUT_BYTES(1 + (g >> 1), ls[g]);
			handle->state.from = (handle->state.from & 3) | (g << 2);
		}
	}
	return CHARCONV_SUCCESS;
}

#define SWITCH_TO_SET(cct, g) do { \
	if (switch_to_set(handle, cct, g, outbuf, outbytesleft) != CHARCONV_SUCCESS) \
		return CHARCONV_NO_SPACE; \
} while (0)


static charconv_error_t from_unicode_conversion(convertor_state_t *handle, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft, int flags)
{
	uint32_t codepoint;
	char *codepoint_ptr;
	size_t codepoint_bytesleft;
	uint8_t *_inbuf = (uint8_t *) *inbuf;
	size_t _inbytesleft = *inbytesleft;
	cct_handle_t *ptr;
	char buffer[4], *buffer_ptr;
	size_t buffer_bytesleft;
	struct { cct_handle_t *cct; uint_fast8_t state; } fallback;
	uint_fast8_t state;
	int i;
//FIXME: M:N conversions are sometimes also available!!! Check which ones are and convert multiple codepoints if necessary!!
	while (*inbytesleft > 0) {
		switch (codepoint = handle->common.get_unicode((char **) &_inbuf, &_inbytesleft, false)) {
			case CHARCONV_UTF_ILLEGAL:
				return CHARCONV_ILLEGAL;
			case CHARCONV_UTF_INCOMPLETE:
				if (flags & CHARCONV_END_OF_TEXT) {
					if (!(flags & CHARCONV_SUBST_ILLEGAL))
						return CHARCONV_ILLEGAL_END;
					SWITCH_TO_SET(handle->ascii, 0);
					buffer[0] = 0x1a;
					PUT_BYTES(1, buffer);
					return CHARCONV_SUCCESS;
				}
				return CHARCONV_INCOMPLETE;
			case 0x0d:
			case 0x0a:
				/* Take the simple approach: go to ASCII mode on _any_ possible line ending.
				   This may be a bit too much, it is not wrong, and some convertors may
				   actually be expecting this. */
				SWITCH_TO_SET(handle->ascii, 0);
				//FIXME: reset state, as required for some convertors
				break;
			default:
				break;
		}

		fallback.cct = NULL;
		/* Assume that most codepoints will come from the same character set, so just try to
		   convert using that. If it succeeds, we're done. Otherwise, we need to search for
		   the first set that does encode the character. */
		state = handle->state.from;
		if (state > 3)
			state >>= 2;
		ptr = handle->state.g_from[state];
		codepoint_ptr = (char *) &codepoint;
		codepoint_bytesleft = 4;
		buffer_ptr = buffer;
		buffer_bytesleft = 4;
		switch (ptr->cct->convert_from(ptr->cct, &codepoint_ptr, &codepoint_bytesleft, &buffer_ptr, &buffer_bytesleft, 0)) {
			case CHARCONV_SUCCESS:
				PUT_BYTES(4 - buffer_bytesleft, buffer);
				*inbuf = (char *) _inbuf;
				*inbytesleft = _inbytesleft;
				handle->state.from &= 3;
				continue;
			case CHARCONV_NO_SPACE:
				return CHARCONV_NO_SPACE;
			case CHARCONV_FALLBACK:
				fallback.cct = ptr;
				fallback.state = state;
				break;
			case CHARCONV_UNASSIGNED:
				break;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}

		for (i = 0; i < 4; i++) {
			for (ptr = handle->g_sets[i]; ptr != NULL; ptr = ptr->next) {
				if (!(ptr->flags & CCT_FLAG_WRITE))
					continue;

				codepoint_ptr = (char *) &codepoint;
				codepoint_bytesleft = 4;
				buffer_ptr = buffer;
				buffer_bytesleft = 4;

				switch (ptr->cct->convert_from(ptr->cct, &codepoint_ptr, &codepoint_bytesleft,
						&buffer_ptr, &buffer_bytesleft, 0))
				{
					case CHARCONV_SUCCESS:
						SWITCH_TO_SET(ptr, i);
						PUT_BYTES(4 - buffer_bytesleft, buffer);
						goto next_codepoint;
					case CHARCONV_UNASSIGNED:
						break;
					case CHARCONV_FALLBACK:
						if (fallback.cct != NULL) {
							fallback.cct = ptr;
							fallback.state = i;
						}
						break;
					default:
						return CHARCONV_INTERNAL_ERROR;
				}
			}
		}
		if (fallback.cct == NULL) {
			/* Unassigned */
			if (!(flags & CHARCONV_SUBST_UNASSIGNED))
				return CHARCONV_UNASSIGNED;
			SWITCH_TO_SET(handle->ascii, 0);
			buffer[0] = 0x1a;
			PUT_BYTES(1, buffer);
		} else {
			/* Fallback */
			if (!(flags & CHARCONV_ALLOW_FALLBACK))
				return CHARCONV_FALLBACK;
			SWITCH_TO_SET(fallback.cct, fallback.state);
			codepoint_ptr = (char *) &codepoint;
			codepoint_bytesleft = 4;
			switch (fallback.cct->cct->convert_from(fallback.cct->cct, &codepoint_ptr, &codepoint_bytesleft,
					outbuf, outbytesleft, CHARCONV_ALLOW_FALLBACK))
			{
				case CHARCONV_NO_SPACE:
					return CHARCONV_NO_SPACE;
				case CHARCONV_SUCCESS:
					break;
				default:
					return CHARCONV_INTERNAL_ERROR;
			}
		}

next_codepoint:
		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		handle->state.from &= 3;

		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	return CHARCONV_SUCCESS;
}

static charconv_error_t from_unicode_flush(convertor_state_t *handle, char **outbuf, size_t *outbytesleft) {
	SWITCH_TO_SET(handle->ascii, 0);
	return CHARCONV_SUCCESS;
}

static void from_unicode_reset(convertor_state_t *handle) {
	memcpy(handle->state.g_from, handle->g_initial, sizeof(handle->g_initial));
	handle->state.from = 0;
}

static void save_iso2022_state(convertor_state_t *handle, state_t *save) {
	memcpy(save, &handle->state, sizeof(state_t));
}

static void load_iso2022_state(convertor_state_t *handle, state_t *save) {
	memcpy(&handle->state, save, sizeof(state_t));
}



static bool load_table(convertor_state_t *handle, cct_descriptor_t *desc, int g, charconv_error_t *error, uint_fast8_t flags)
{
	cct_handle_t *cct_handle, *extra_handle;
	charconv_t *ext_handle;
	uint_fast8_t idx = 0;

	flags |= desc->flags;

	if ((flags & CCT_FLAG_LARGE_SET) && g == 0)
		return CHARCONV_INTERNAL_ERROR;

	if (desc->name == NULL)
		ext_handle = _charconv_fill_utf(_charconv_open_iso8859_1_convertor(desc->name, 0, error), UTF32);
	else
		ext_handle = _charconv_fill_utf(_charconv_open_cct_convertor_internal(desc->name, 0, error, true), UTF32);

	if (ext_handle == NULL)
		return false;

	if ((cct_handle = malloc(sizeof(cct_handle_t))) == NULL) {
		charconv_close_convertor(ext_handle);
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		return false;
	}

	cct_handle->cct = ext_handle;
	cct_handle->bytes_per_char = desc->bytes_per_char;
	cct_handle->escape_seq[idx++] = 0x1b;
	if (desc->bytes_per_char > 1)
		cct_handle->escape_seq[idx++] = 0x24;
	cct_handle->escape_seq[idx++] = (desc->flags & CCT_FLAG_LARGE_SET ? 0x2C : 0x28) + g;
	cct_handle->escape_seq[idx++] = desc->final_byte;
	cct_handle->seq_len = idx;

	cct_handle->high_bit = desc->high_bit;
	cct_handle->flags = flags;
	cct_handle->prev = NULL;
	cct_handle->next = handle->g_sets[g];
	handle->g_sets[g] = cct_handle;

	if (desc->final_byte < 0x43 && desc->bytes_per_char > 1) {
		if ((extra_handle = malloc(sizeof(cct_handle_t))) == NULL) {
			charconv_close_convertor(ext_handle);
			free(cct_handle);
			if (error != NULL)
				*error = CHARCONV_OUT_OF_MEMORY;
			return false;
		}
		memcpy(extra_handle, cct_handle, sizeof(cct_handle_t));
		extra_handle->escape_seq[2] = desc->final_byte;
		extra_handle->seq_len = 3;
		if (flags & CCT_FLAGS_SHORT_SEQ)
			cct_handle->flags &= ~(CCT_FLAG_WRITE);
		else
			extra_handle->flags &= ~(CCT_FLAG_WRITE);
		extra_handle->next = handle->g_sets[g];
		handle->g_sets[g] = extra_handle;
	}

	return true;
}

#define LOAD_TABLE(handle, desc, g, error, _write) do { \
	if (!load_table((handle), (desc), (g), (error), (_write))) { \
		close_convertor(handle); \
		return NULL; \
	} \
} while (0)

void *_charconv_open_iso2022_convertor(const char *name, int flags, charconv_error_t *error) {
	static const name_to_iso2022type map[] = {
		{ "ISO-2022-JP", ISO2022_JP },
		{ "ISO-2022-JP-1", ISO2022_JP1 },
		{ "ISO-2022-JP-2", ISO2022_JP2 },
		{ "ISO-2022-JP-3", ISO2022_JP3 },
		{ "ISO-2022-JP-2004", ISO2022_JP2004 },
		{ "ISO-2022-KR", ISO2022_KR },
		{ "ISO-2022-CN", ISO2022_CN },
		{ "ISO-2022-CN-EXT", ISO2022_CNEXT }
#ifdef DEBUG
#warning using ISO-2022-TEST
		, { "ISO-2022-TEST", ISO2022_TEST }
#endif
	};

	convertor_state_t *retval;
	name_to_iso2022type *ptr;
	size_t array_size = ARRAY_SIZE(map);

	if ((ptr = lfind(name, map, &array_size, sizeof(map[0]), _charconv_element_strcmp)) == NULL) {
		if (error != NULL)
			*error = CHARCONV_INTERNAL_ERROR;
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == NULL) {
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		return NULL;
	}
	retval->g_sets[0] = NULL;
	retval->g_sets[1] = NULL;
	retval->g_sets[2] = NULL;
	retval->g_sets[3] = NULL;
	retval->g_initial[0] = NULL;
	retval->g_initial[1] = NULL;
	retval->g_initial[2] = NULL;
	retval->g_initial[3] = NULL;

	retval->iso2022_type = ptr->iso2022_type;

	switch (retval->iso2022_type) {
		/* Current understanding of the ISO-2022-JP-* situation:
		   JIS X 0213 has two planes: the first plane which is a superset of
		   JIS X 0208, and plane 2 which contains only new chars. However, in
		   making JIS X 0213, they found that they needed to amend the standard
		   for plane 1 in 2004. The result is 10 added codepoints that were not
		   present in the 2000 version.

		   ISO-2022-JP-2004 is the completely new and revised version, which
		   _should_ only contain ASCII and JIS X 0213 (2004). Note that plane 2
		   of JIS-X-0213 was never revised.

		   ISO-2022-JP-3 is the same as ISO-2022-JP-2004, but based on the
		   original JIS X 0213. For plane 1 of JIS X 0213 a different escape
		   sequence is used than in ISO-2022-JP-2004, so there are no nasty
		   problems there.

		   ISO-2022-JP-2 extends ISO-2022-JP-1, which in turn extends ISO-2022-JP
		   standard by adding more character sets.

		   The best approach in this case would be to make a distinction between
		   character sets which are understood for reading, and those which are
		   used for writing (according to the be conservative in what you send;
		   be liberal in what you accept philosophy.

		   Also note that, to make things slightly worse, in the attempts to
		   register the ISO-2022-JP-2004 character set with IANA, the following
		   aliases are named:

		   ISO-2022-JP-3-2003
		   ISO-2022-JP-2003

		   It is unclear what part JIS X 0201 has to play in this. It does encode
		   characters that do not appear to be in JIS X 0213...
		*/
		case ISO2022_JP2004:
			/* Load the JP and JP-3 sets, but only for reading. */
			LOAD_TABLE(retval, &jis_x_0201_1976_roman, 0, error, 0);
			LOAD_TABLE(retval, &jis_x_0208_1983, 0, error, 0);
			LOAD_TABLE(retval, &jis_x_0208_1978, 0, error, 0);
			LOAD_TABLE(retval, &jis_x_0213_2000_1, 0, error, 0);

			/* I'm not very sure about this one. Different sources seem to say different things */
			LOAD_TABLE(retval, &jis_x_0201_1976_kana, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &jis_x_0213_2000_2, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &jis_x_0213_2004_1, 0, error, CCT_FLAG_WRITE);
			retval->shift_types = 0;
			break;
		case ISO2022_JP3:
			/* Load the JP sets, but only for reading. */
			LOAD_TABLE(retval, &jis_x_0201_1976_roman, 0, error, 0);
			LOAD_TABLE(retval, &jis_x_0208_1983, 0, error, 0);
			LOAD_TABLE(retval, &jis_x_0208_1978, 0, error, 0);

			/* I'm not very sure about this one. Different sources seem to say different things */
			LOAD_TABLE(retval, &jis_x_0201_1976_kana, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &jis_x_0213_2000_1, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &jis_x_0213_2000_2, 0, error, CCT_FLAG_WRITE);
			retval->shift_types = 0;
			break;
		case ISO2022_JP2:
			LOAD_TABLE(retval, &iso8859_1, 2, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &iso8859_7, 2, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &ksc5601_1987, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &gb2312_1980, 0, error, CCT_FLAG_WRITE | CCT_FLAGS_SHORT_SEQ);
			/* FALLTHROUGH */
		case ISO2022_JP1:
			LOAD_TABLE(retval, &jis_x_0212_1990, 0, error, CCT_FLAG_WRITE);
			/* FALLTHROUGH */
		case ISO2022_JP:
			LOAD_TABLE(retval, &jis_x_0201_1976_roman, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &jis_x_0208_1978, 0, error, CCT_FLAG_WRITE | CCT_FLAGS_SHORT_SEQ);
			LOAD_TABLE(retval, &jis_x_0208_1983, 0, error, CCT_FLAG_WRITE | CCT_FLAGS_SHORT_SEQ);
			retval->shift_types = 0;
			break;
		case ISO2022_KR:
			LOAD_TABLE(retval, &ksc5601_1987, 1, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &ascii, 0, error, CCT_FLAG_WRITE);
			retval->shift_types = LS0 | LS1;
			break;
		case ISO2022_CNEXT:
			/* The RFC (1922) lists several more character sets, but only under the assumption
			   that a final character would be assigned to them. To the best of my knowledge,
			   this hasn't happened yet, so we don't include them. */
			LOAD_TABLE(retval, &iso_ir_165, 1, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_3, 3, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_4, 3, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_5, 3, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_6, 3, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_7, 3, error, CCT_FLAG_WRITE);
			/* FALLTHROUGH */
		case ISO2022_CN:
			LOAD_TABLE(retval, &gb2312_1980, 1, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_1, 1, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &cns_11643_1992_2, 2, error, CCT_FLAG_WRITE);
			retval->shift_types = LS0 | LS1 | SS2 | (retval->iso2022_type == ISO2022_CNEXT ? SS3 : 0);
			break;
		case ISO2022_TEST:
			LOAD_TABLE(retval, &jis_x_0201_1976_roman, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &jis_x_0201_1976_kana, 0, error, CCT_FLAG_WRITE);
			LOAD_TABLE(retval, &iso8859_1, 2, error, CCT_FLAG_WRITE);
			retval->shift_types = 0;
			break;
		default:
			close_convertor(retval);
			if (error != NULL)
				*error = CHARCONV_INTERNAL_ERROR;
			return NULL;
	}
	/* Load ASCII, which all convertors need. */
	LOAD_TABLE(retval, &ascii, 0, error, true);
	retval->ascii = retval->g_sets[0];
	retval->g_initial[0] = retval->ascii;

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = (flush_func_t) from_unicode_flush;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_convertor;
	retval->common.save = (save_func_t) save_iso2022_state;
	retval->common.load = (load_func_t) load_iso2022_state;

	to_unicode_reset(retval);
	from_unicode_reset(retval);
	return retval;
}

static void close_convertor(convertor_state_t *handle) {
	cct_handle_t *ptr;
	size_t i;

	for (i = 0; i < 4; i++) {
		for (ptr = handle->g_sets[i]; ptr != NULL; ptr = ptr->next) {
			charconv_close_convertor(ptr->cct);
			free(ptr);
		}
	}
	free(handle);
}
