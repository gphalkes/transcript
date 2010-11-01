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
	bool high_bit, write; /* Whether the cct has the high bit set for characters. */
	cct_handle_t *prev, *next; /* Doubly-linked list ptrs. */
};

typedef struct _charconv_iso2022_state_t state_t;

typedef struct {
	charconv_common_t common;
	cct_handle_t *g_initial[4];
	cct_handle_t *g_sets[4]; /* Linked lists of possible tables. */
	state_t state;
	int iso2022_type;
} convertor_state_t;

typedef struct {
	const char *name;
	uint_fast8_t bytes_per_char;
	char final_byte;
	bool high_bit;
	bool large_set; /* 96 byte character set. */
} cct_descriptor_t ;

/* We use the lower part of the ISO8859-1 convertor for ASCII. */
cct_descriptor_t ascii = { NULL, 1, '\x42', false, false };
cct_descriptor_t iso8859_1 = { NULL, 1, '\x41', true, true };//2
cct_descriptor_t jis_x_0201_1976_kana = { "ibm-897_P100-1995", 1, '\x49', true, false };
cct_descriptor_t jis_x_0201_1976_roman = { "ibm-897_P100-1995", 1, '\x4a', false, false };
cct_descriptor_t jis_x_0208_1978 = { "ibm-955_P110-1997", 2, '\x40', false, false };
/* This is the 1990 version, not the 1983 version, which includes two extra characters. */
/* FIXME: gconv simply uses the extra two characters. On the other hand, for JP-3, it
   does use the 2004 version for characters only in the new version... The proper version
   appears to be 13240, but that seems to be missing one character (based on the
   number of characters that IBM says is in there). */
cct_descriptor_t jis_x_0208_1983 = { "ibm-5048_P100-1995", 2, '\x42', true, false };
cct_descriptor_t jis_x_0212_1990 = { "ibm-5049_P100-1995", 2, '\x44', true, false };

//FIXME: use the correct codepage names and check the high_bit flag
cct_descriptor_t jis_x_0213_2000_1 = { "JIS-X-0213-2000-1", 2, '\x4f', true, false };
cct_descriptor_t jis_x_0213_2000_2 = { "JIS-X-0213-2000-2", 2, '\x50', true, false };
cct_descriptor_t jis_x_0213_2004_1 = { "JIS-X-0213-2004-1", 2, '\x51', true, false };
cct_descriptor_t iso8859_7 = { "ibm-813_P100-1995", 1, '\x4f', true, true }; //2
cct_descriptor_t ksc5601_1987 = { "KSC5601-1987", 2, '\x43', true, false };
cct_descriptor_t gb2312_1980 = { "GB2312-1980", 2, '\x41', true, false };

cct_descriptor_t cns_11643_1992_1 = { "CNS-11643-1992-1", 2, '\x47', true, false };//1
cct_descriptor_t cns_11643_1992_2 = { "CNS-11643-1992-2", 2, '\x48', true, false };//2
cct_descriptor_t cns_11643_1992_3 = { "CNS-11643-1992-3", 2, '\x49', true, false };//3
cct_descriptor_t cns_11643_1992_4 = { "CNS-11643-1992-4", 2, '\x4a', true, false };//3
cct_descriptor_t cns_11643_1992_5 = { "CNS-11643-1992-5", 2, '\x4b', true, false };//3
cct_descriptor_t cns_11643_1992_6 = { "CNS-11643-1992-6", 2, '\x4c', true, false };//3
cct_descriptor_t cns_11643_1992_7 = { "CNS-11643-1992-7", 2, '\x4d', true, false };//3
cct_descriptor_t iso_ir_165 = { "ISO-IR-165", 2, '\x45', true, false };//1

static void close_convertor(convertor_state_t *handle);

static int check_escapes(convertor_state_t *handle, uint8_t *_inbuf, size_t _inbytesleft) {
	cct_handle_t *ptr;
	size_t i;

	//FIXME: we should probably limit the number of bytes to check
	for (i = 1; i < _inbytesleft; i++) {
		if (_inbuf[i] >= 0x20 && _inbuf[i] <= 0x2f)
			continue;
		if (_inbuf[i] >= 0x40 && _inbuf[i] <= 0x7f)
			break;
		return CHARCONV_ILLEGAL;
	}
	if (i == _inbytesleft)
		return CHARCONV_INCOMPLETE;

	for (i = 0; i < 3; i++) {
		for (ptr = handle->g_sets[i]; ptr != NULL; ptr = ptr->next) {
			if (_inbytesleft < ptr->seq_len)
				continue;

			if (memcmp(_inbuf, ptr->escape_seq, ptr->seq_len) != 0)
				continue;

			handle->state.g_to[i] = ptr;
			return -ptr->seq_len;
		}
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
		//FIXME: should we accept shift sequences in non-locking shift states?
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

				switch (result = check_escapes(handle, _inbuf, _inbytesleft)) {
					case CHARCONV_INCOMPLETE:
						goto incomplete_char;
					case CHARCONV_ILLEGAL:
						return result;
					default:
						_inbuf = (uint8_t *) ((*inbuf) -= result);
						_inbytesleft = (*inbytesleft) += result;
						continue;
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
			} else if (*_inbuf == 0xd) {
				if (_inbytesleft > 1) {
					if (_inbuf[1] == 0xa) {
						//FIXME: reset state
					}
				} else if (!(flags & CHARCONV_END_OF_TEXT)) {
					return CHARCONV_INCOMPLETE;
				}
			}
			/* Other control. */
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

		if (handle->state.to > 3)
			handle->state.to &= 3;

		*inbuf = (char *) _inbuf;
		*inbytesleft = _inbytesleft;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}
	if (flags & CHARCONV_END_OF_TEXT) {
		//FIXME: reset
	}

	return CHARCONV_SUCCESS;

incomplete_char:
	if (flags & CHARCONV_END_OF_TEXT) {
		if (flags & CHARCONV_SUBST_ILLEGAL) {
			//FIXME: reset
			PUT_UNICODE(0xfffd);
			(*inbuf) += _inbytesleft;
			*inbytesleft = 0;
			return CHARCONV_SUCCESS;
		}
		return CHARCONV_ILLEGAL_END;
	}
	return CHARCONV_INCOMPLETE;
}

static int to_unicode_skip(charconv_common_t *handle, char **inbuf, size_t *inbytesleft) {
	(void) handle;

	if (*inbytesleft == 0)
		return CHARCONV_INCOMPLETE;
	(*inbuf)++;
	(*inbytesleft)--;
	return CHARCONV_SUCCESS;
}

static void to_unicode_reset(convertor_state_t *handle) {
	memcpy(handle->state.g_to, handle->g_initial, sizeof(handle->g_initial));
	handle->state.to = 0;
}

static bool load_table(convertor_state_t *handle, cct_descriptor_t *desc, int g, charconv_error_t *error, bool write)
{
	cct_handle_t *cct_handle, *extra_handle;
	charconv_t *ext_handle;
	uint_fast8_t idx = 0;

	if (desc->large_set && g == 0)
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
	cct_handle->escape_seq[idx++] = (desc->large_set ? 0x2C : 0x28) + g;
	cct_handle->escape_seq[idx++] = desc->final_byte;
	cct_handle->seq_len = idx;

	cct_handle->high_bit = desc->high_bit;
	cct_handle->write = write;
	cct_handle->prev = NULL;

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
		extra_handle->write = false;
		extra_handle->next = handle->g_sets[g];
		handle->g_sets[g] = extra_handle;
	}

	cct_handle->next = handle->g_sets[g];
	handle->g_sets[g] = cct_handle;
	return true;
}


static void save_iso2022_state(convertor_state_t *handle, state_t *save) {
	memcpy(save, &handle->state, sizeof(state_t));
}

static void load_iso2022_state(convertor_state_t *handle, state_t *save) {
	memcpy(&handle->state, save, sizeof(state_t));
}



#define CHECK_LOAD(x) do { if (!(x)) { close_convertor(retval); return NULL; }} while (0)

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
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_roman, 0, error, false));
			CHECK_LOAD(load_table(retval, &jis_x_0208_1983, 0, error, false));
			CHECK_LOAD(load_table(retval, &jis_x_0208_1978, 0, error, false));
			CHECK_LOAD(load_table(retval, &jis_x_0213_2000_1, 0, error, false));

			/* I'm not very sure about this one. Different sources seem to say different things */
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_kana, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0213_2000_2, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0213_2004_1, 0, error, true));
			/* Load ASCII last, as that is what should be the initial state. */
			CHECK_LOAD(load_table(retval, &ascii, 0, error, true));
			break;
		case ISO2022_JP3:
			/* Load the JP sets, but only for reading. */
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_roman, 0, error, false));
			CHECK_LOAD(load_table(retval, &jis_x_0208_1983, 0, error, false));
			CHECK_LOAD(load_table(retval, &jis_x_0208_1978, 0, error, false));

			/* I'm not very sure about this one. Different sources seem to say different things */
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_kana, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0213_2000_1, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0213_2000_2, 0, error, true));
			/* Load ASCII last, as that is what should be the initial state. */
			CHECK_LOAD(load_table(retval, &ascii, 0, error, true));
			break;
		case ISO2022_JP2:
			CHECK_LOAD(load_table(retval, &iso8859_1, 2, error, true));
			CHECK_LOAD(load_table(retval, &iso8859_7, 2, error, true));
			CHECK_LOAD(load_table(retval, &ksc5601_1987, 0, error, true));
			CHECK_LOAD(load_table(retval, &gb2312_1980, 0, error, true));
			/* FALLTHROUGH */
		case ISO2022_JP1:
			CHECK_LOAD(load_table(retval, &jis_x_0212_1990, 0, error, true));
			/* FALLTHROUGH */
		case ISO2022_JP:
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_roman, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0208_1983, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0208_1978, 0, error, true));
			/* Load ASCII last, as that is what should be the initial state. */
			CHECK_LOAD(load_table(retval, &ascii, 0, error, true));
			break;
		case ISO2022_KR:
			CHECK_LOAD(load_table(retval, &ksc5601_1987, 1, error, true));
			CHECK_LOAD(load_table(retval, &ascii, 0, error, true));
			break;
		case ISO2022_CNEXT:
			CHECK_LOAD(load_table(retval, &iso_ir_165, 1, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_3, 3, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_4, 3, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_5, 3, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_6, 3, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_7, 3, error, true));
			/* FALLTHROUGH */
		case ISO2022_CN:
			CHECK_LOAD(load_table(retval, &gb2312_1980, 1, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_1, 1, error, true));
			CHECK_LOAD(load_table(retval, &cns_11643_1992_2, 2, error, true));
			CHECK_LOAD(load_table(retval, &ascii, 0, error, true));
			break;
		case ISO2022_TEST:
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_roman, 0, error, true));
			CHECK_LOAD(load_table(retval, &jis_x_0201_1976_kana, 0, error, true));
			CHECK_LOAD(load_table(retval, &iso8859_1, 2, error, true));
			CHECK_LOAD(load_table(retval, &ascii, 0, error, true));
			retval->g_initial[0] = retval->g_sets[0];
			break;
		default:
			close_convertor(retval);
			if (error != NULL)
				*error = CHARCONV_INTERNAL_ERROR;
			return NULL;
	}

/*	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;*/
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_convertor;
	retval->common.save = (save_func_t) save_iso2022_state;
	retval->common.load = (load_func_t) load_iso2022_state;

	to_unicode_reset(retval);
/* 	from_unicode_reset(retval); */
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
