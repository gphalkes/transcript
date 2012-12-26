/* Copyright (C) 2011 G.P. Halkes
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

/* What do we need to know in the converter:
   - which sets correspond to GL and GR, and C0 and C1 (if these are actually switchable for any of the supported sets)
   - which sequence selects which set for G0 through G3
   per set:
   - #bytes per char
   - state table converter
*/
#include <string.h>
#include <search.h>

#include <transcript/static_assert.h>
#include <transcript/moduledefs.h>

/** Flags for describing state table based converters. */
enum {
	STC_FLAG_WRITE = (1<<0), /**< Set can be used for output. */
	STC_FLAGS_DUPSTC = (1<<5), /**< This STC descriptor is a duplicate for one with a pre-2022 sequence. */
	STC_FLAGS_SHORT_SEQ = (1<<6), /**< Set uses pre-2022 sequence. */
	STC_FLAG_LARGE_SET = (1<<7) /**< 96 characters instead of 94 in the set. */
};

/** Shift types used in the ISO-2022 converter. */
enum {
	LS0 = (1<<0),
	LS1 = (1<<1),
	LS2 = (1<<2),
	LS3 = (1<<3),
	SS2 = (1<<4),
	SS3 = (1<<5),
};

/** Constants for the different implemented ISO-2022 converters. */
enum {
	ISO2022_JP,
	ISO2022_JP1,
	ISO2022_JP2,
	ISO2022_JP2_STRICT,
	ISO2022_JP3,
	ISO2022_JP3_STRICT,
	ISO2022_JP2004,
	ISO2022_JP2004_STRICT,
	ISO2022_KR,
	ISO2022_CN,
	ISO2022_CNEXT
};

/** @struct name_to_iso2022type
    Struct holding the string to constant mapping for the different implemented ISO-2022 converters. */
typedef struct {
	const char *name;
	int iso2022_type;
} name_to_iso2022type;

static const name_to_iso2022type map[] = {
	{ "iso2022jp", ISO2022_JP },
	{ "iso2022jp1", ISO2022_JP1 },
	{ "iso2022jp2", ISO2022_JP2 },
	{ "iso2022jp2strict", ISO2022_JP2_STRICT },
	{ "iso2022jp3", ISO2022_JP3 },
	{ "iso2022jp3strict", ISO2022_JP3_STRICT },
	{ "iso2022jp2004", ISO2022_JP2004 },
	{ "iso2022jp2004strict", ISO2022_JP2004_STRICT },
	{ "iso2022kr", ISO2022_KR },
	{ "iso2022cn", ISO2022_CN },
	{ "iso2022cnext", ISO2022_CNEXT }
};


typedef struct _transcript_iso2022_stc_handle_t stc_handle_t;

/** Struct holding a state table converter and associated information. */
struct _transcript_iso2022_stc_handle_t {
	transcript_t *stc; /**< Handle for the table based converter. */
	uint_fast8_t bytes_per_char; /**< Bytes per character code. */
	uint_fast8_t seq_len; /**< Length of the escape sequence used to shift. */
	char escape_seq[7]; /**< The escape sequence itselft. */
	uint_fast8_t flags; /**< Flags indicating how to use the state table converter. */
	uint_fast8_t g; /**< Which graphics set should this be loaded into. */
	stc_handle_t *prev, *next; /**< Doubly-linked list ptrs. */
};

/** @struct state_t
    Structure holding the shift state of an ISO-2022 converter. */
typedef struct {
	stc_handle_t *g_to[4]; /**< Shifted-in sets. */
	stc_handle_t *g_from[4]; /**< Shifted-in sets. */
	uint_fast8_t to, /**< Current character set in use by the to-Unicode conversion. */
		from; /**< Current character set in use by the from-Unicode conversion. */
} state_t;

/** @struct save_state_t
    Structure holding the shift state of an ISO-2022 converter for save/load purposes. */
typedef struct {
	uint8_t g_to[4]; /**< Shifted-in sets. */
	uint8_t g_from[4]; /**< Shifted-in sets. */
	uint8_t to, /**< Current character set in use by the to-Unicode conversion. */
		from; /**< Current character set in use by the from-Unicode conversion. */
} save_state_t;


/* Make sure that the saved state will fit in an allocated block. */
static_assert(sizeof(save_state_t) <= TRANSCRIPT_SAVE_STATE_SIZE);

typedef struct converter_state_t converter_state_t;
typedef void (*reset_state_func_t)(converter_state_t *handle);

/** @struct converter_state_t
    Structure holding the data and the state of a state table converter. */
struct converter_state_t {
	transcript_t common;
	stc_handle_t *g_initial[4]; /**< Initial sets of the converter (for resetting purposes). */
	stc_handle_t *g_sets; /**< Linked lists of possible tables. */
	stc_handle_t *ascii; /**< The ASCII converter. */
	reset_state_func_t reset_state; /**< Function called after a NL character is encountered. */
	state_t state;
	int iso2022_type;
	int shift_types;
};

/** @struct stc_descriptor_t
    Structure holding the information needed to instantiate a state table converter. */
typedef struct {
	const char *name;
	uint_fast8_t bytes_per_char;
	char final_byte;
	uint_fast8_t flags;
} stc_descriptor_t;

static stc_descriptor_t ascii = { "iso-2022-ascii", 1, '\x42', 0 };
static stc_descriptor_t iso8859_1 = { "iso-2022-88591", 1, '\x41', STC_FLAG_LARGE_SET };
static stc_descriptor_t jis_x_0201_1976_kana = { "iso-2022-jisx0201kana", 1, '\x49', 0 };
static stc_descriptor_t jis_x_0201_1976_roman = { "iso-2022-jisx0201roman", 1, '\x4a', 0 };
static stc_descriptor_t jis_x_0208_1978 = { "iso-2022-jisx0208-1978", 2, '\x40', 0 };
static stc_descriptor_t jis_x_0208_1983 = { "iso-2022-jisx0208-1983", 2, '\x42', 0 };
/* Note that this set should be used for reading only, and then only in ISO-2022-JP-3/2004.
   This is because it uses the same escape sequence as the 1983 version, which is
   the only one mandated by any standard. However, to be able to read non-standard
   compliant output, we add this set for reading. Note that because JIS X 0213
   is an extension of the 1990 version, this poses no problem when writing. */
static stc_descriptor_t jis_x_0208_1990 = { "iso-2022-jisx0208-1990", 2, '\x42', 0 };
static stc_descriptor_t jis_x_0212_1990 = { "iso-2022-jisx0212-1990", 2, '\x44', 0 };

static stc_descriptor_t jis_x_0213_2000_1 = { "iso-2022-jisx0213-2000-1", 2, '\x4f', 0 };
static stc_descriptor_t jis_x_0213_2000_2 = { "iso-2022-jisx0213-2000-2", 2, '\x50', 0 };
static stc_descriptor_t jis_x_0213_2004_1 = { "iso-2022-jisx0213-2004-1", 2, '\x51', 0 };
static stc_descriptor_t iso8859_7 = { "iso-2022-88597", 1, '\x46', STC_FLAG_LARGE_SET };
static stc_descriptor_t ksc5601_1987 = { "iso-2022-ksc5601", 2, '\x43', 0 };

static stc_descriptor_t gb2312_1980 = { "iso-2022-gb2312", 2, '\x41', 0 };

static stc_descriptor_t cns_11643_1992_1 = { "CNS-11643-1992-1", 2, '\x47', 0 };
static stc_descriptor_t cns_11643_1992_2 = { "CNS-11643-1992-2", 2, '\x48', 0 };
static stc_descriptor_t cns_11643_1992_3 = { "CNS-11643-1992-3", 2, '\x49', 0 };
static stc_descriptor_t cns_11643_1992_4 = { "CNS-11643-1992-4", 2, '\x4a', 0 };
static stc_descriptor_t cns_11643_1992_5 = { "CNS-11643-1992-5", 2, '\x4b', 0 };
static stc_descriptor_t cns_11643_1992_6 = { "CNS-11643-1992-6", 2, '\x4c', 0 };
static stc_descriptor_t cns_11643_1992_7 = { "CNS-11643-1992-7", 2, '\x4d', 0 };
static stc_descriptor_t iso_ir_165 = { "ISO-IR-165", 2, '\x45', 0 };

static const char *ls[] = { "\x0f", "\x0e", "\x1b\x6e", "\x1b\x6f", "\x1b\x4e", "\x1b\x4f" };

static void to_unicode_reset(converter_state_t *handle);
static void from_unicode_reset(converter_state_t *handle);
static void close_converter(converter_state_t *handle);

/** Check an escape sequence for validity within this converter. */
static int check_escapes(converter_state_t *handle, const uint8_t **inbuf, const uint8_t *inbuflimit, bool_t skip) {
	stc_handle_t *ptr;
	const uint8_t *_inbuf = *inbuf + 1;

	/* Limit the number of bytes to check to 5. No sequence that large has been
	   assigned yet, so that won't be a problem. */
	if (inbuflimit > (*inbuf) + 5)
		inbuflimit = (*inbuf) + 5;

	for (; _inbuf < inbuflimit; _inbuf++) {
		if (*_inbuf >= 0x20 && *_inbuf <= 0x2f)
			continue;
		if (*_inbuf >= 0x40 && *_inbuf <= 0x7f) {
			_inbuf++;
			goto sequence_found;
		}
		if (skip)
			*inbuf = _inbuf - 1;
		return TRANSCRIPT_ILLEGAL;
	}

	if (_inbuf == inbuflimit && inbuflimit == (*inbuf) + 5) {
		if (skip)
			*inbuf += 5;
		return TRANSCRIPT_ILLEGAL;
	} else {
		return TRANSCRIPT_INCOMPLETE;
	}

sequence_found:
	if (!skip) {
		size_t len;

		len = _inbuf - (*inbuf);
		for (ptr = handle->g_sets; ptr != NULL; ptr = ptr->next) {
			if (len != ptr->seq_len)
				continue;

			if (memcmp(*inbuf, ptr->escape_seq, ptr->seq_len) != 0)
				continue;

			handle->state.g_to[ptr->g] = ptr;
			*inbuf = _inbuf;
			return TRANSCRIPT_SUCCESS;
		}
	} else {
		*inbuf = _inbuf;
	}
	return TRANSCRIPT_ILLEGAL;
}

/** Simplification macro for calling put_unicode which returns automatically on error. */
#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbuflimit)) != TRANSCRIPT_SUCCESS) \
		return result; \
} while (0)

/** convert_to implementation for ISO-2022 converters. */
static int to_unicode_conversion(converter_state_t *handle, const uint8_t **inbuf, const uint8_t const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast8_t state;
	int result;

	while (*inbuf < inbuflimit) {
		/* We accept shift sequences even in non-locking shift states. This
		   follows the 'be liberal in what you accept' policy. */
		if (**inbuf < 32) {
			/* Control characters. */
			if (**inbuf == 0x1b) {
				/* Escape sequence. */
				if ((*inbuf) + 1 == inbuflimit)
					goto incomplete_char;

				/* _inbytesleft at least 2 at this point. */
				switch ((*inbuf)[1]) {
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
							return TRANSCRIPT_ILLEGAL;
						handle->state.to = state;

						(*inbuf) += 2;
						continue;

					default:
						break;
				}

				switch (check_escapes(handle, inbuf, inbuflimit, FALSE)) {
					case TRANSCRIPT_INCOMPLETE:
						goto incomplete_char;
					case TRANSCRIPT_ILLEGAL:
						/* Handle C1 escapes. */
						if (handle->iso2022_type == ISO2022_JP2 && (*inbuf)[1] >= 0x40 && (*inbuf)[1] < 0x60) {
							PUT_UNICODE((*inbuf)[1] + 0x40);
							(*inbuf) += 2;
							break;
						}
						return TRANSCRIPT_ILLEGAL;
					case TRANSCRIPT_SUCCESS:
						continue;
					default:
						return TRANSCRIPT_INTERNAL_ERROR;
				}
			} else if (**inbuf == 0xe) {
				/* Shift out. */
				if (handle->state.g_to[1] == NULL)
					return TRANSCRIPT_ILLEGAL;
				handle->state.to = 1;
				(*inbuf)++;
				continue;
			} else if (**inbuf == 0xf) {
				/* Shift in. */
				handle->state.to = 0;
				(*inbuf)++;
				continue;
			} else {
				/* Other control.

				   We don't care if the current character set is a mulit byte character set, in
				   which case the standard says the control characters are not allowed. There
				   may be broken convertors which don't switch to ASCII/SBCS before the
				   control characters and for decoding correct input this will not happen.

				   Note that we don't issue a reset of the state after CRNL. Eventhough the state
				   should be re-initialised after CRNL, this doesn't mean we should ignore all
				   previous state. The input may not conform the the standard that well... */
				PUT_UNICODE(**inbuf);
				(*inbuf)++;
			}
		} else if (**inbuf & 0x80) {
			/* All ISO-2022 converters implemented here are 7 bit only. */
			return TRANSCRIPT_ILLEGAL;
		} else {
			int internal_flags = flags & ~(TRANSCRIPT_SUBST_ILLEGAL | TRANSCRIPT_SUBST_UNASSIGNED);

			state = handle->state.to;
			if (state > 3) {
				state >>= 2;
				internal_flags |= TRANSCRIPT_SINGLE_CONVERSION;
			}

			if ((result = handle->state.g_to[state]->stc->convert_to(handle->state.g_to[state]->stc, (const char **) inbuf,
					(const char *) inbuflimit, outbuf, outbuflimit, internal_flags)) != TRANSCRIPT_SUCCESS)
			{
				if (result == TRANSCRIPT_ILLEGAL && **inbuf < 32) {
					continue;
				} else if (result == TRANSCRIPT_ILLEGAL_END || result == TRANSCRIPT_INCOMPLETE) {
					goto incomplete_char;
				} if (result == TRANSCRIPT_UNASSIGNED && (flags & TRANSCRIPT_SUBST_UNASSIGNED)) {
					PUT_UNICODE(0xfffd);
					(*inbuf) += handle->state.g_to[state]->bytes_per_char;
				} else {
					return result;
				}
			}
		}

		handle->state.to &= 3;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}
	return TRANSCRIPT_SUCCESS;

incomplete_char:
	if (flags & TRANSCRIPT_END_OF_TEXT) {
		if (flags & TRANSCRIPT_SUBST_ILLEGAL) {
			PUT_UNICODE(0xfffd);
			(*inbuf) = inbuflimit;
			return TRANSCRIPT_SUCCESS;
		}
		return TRANSCRIPT_ILLEGAL_END;
	}
	return TRANSCRIPT_INCOMPLETE;
}

/** skip_to implementation for ISO-2022 converters. */
static transcript_error_t to_unicode_skip(converter_state_t *handle, const uint8_t **inbuf, const uint8_t const *inbuflimit) {
	uint_fast8_t state;

	if (*inbuf == inbuflimit)
		return TRANSCRIPT_INCOMPLETE;

	if (**inbuf == 0x1b)
		return check_escapes(handle, inbuf, inbuflimit, TRUE) == TRANSCRIPT_INCOMPLETE ?
			TRANSCRIPT_INCOMPLETE : TRANSCRIPT_SUCCESS;

	if (**inbuf < 32) {
		(*inbuf)++;
		return TRANSCRIPT_SUCCESS;
	}

	state = handle->state.to;
	if (state > 3)
		state >>= 2;


	if ((*inbuf) + handle->state.g_to[state]->bytes_per_char > inbuflimit)
		return TRANSCRIPT_INCOMPLETE;

	handle->state.to &= 3;

	*inbuf += handle->state.g_to[state]->bytes_per_char;
	return TRANSCRIPT_SUCCESS;
}

/** reset_to implementation for ISO-2022 converters. */
static void to_unicode_reset(converter_state_t *handle) {
	memcpy(handle->state.g_to, handle->g_initial, sizeof(handle->g_initial));
	handle->state.to = 0;
}

/** Simplification macro for writing a set of output bytes, which returns if not enough space is available. */
#define PUT_BYTES(count, buffer) do { size_t _i, _count = count; \
	if ((*outbuf) + _count > outbuflimit) \
		return TRANSCRIPT_NO_SPACE; \
	for (_i = 0; _i < _count; _i++) \
		(*outbuf)[_i] = buffer[_i] & 0x7f; \
	*outbuf += _count; \
} while (0)

/** Switch to named output set.
    @param handle The current ISO-2022 converter.
    @param stc The output set to switch to.
    @param g The index of the set to switch.
    @param outbuf &nbsp;
    @param outbuflimit &nbsp;

    This function both updates the @a handle and write the associated sequence
    to the output.
*/
static transcript_error_t switch_to_set(converter_state_t *handle, stc_handle_t *stc, char **outbuf, const char const *outbuflimit) {
	if (handle->state.g_from[stc->g] != stc) {
		PUT_BYTES(stc->seq_len, stc->escape_seq);
		handle->state.g_from[stc->g] = stc;
	}
	if (handle->state.from != stc->g) {
		/* First check for a locking shift. If not available, check for a non-locking shift. */
		if (handle->shift_types & (1 << stc->g)) {
			PUT_BYTES(1 + (stc->g >> 1), ls[stc->g]);
			handle->state.from = stc->g;
		} else if (stc->g > 1 && (handle->shift_types & (1 << (stc->g + 2)))) {
			PUT_BYTES(2, ls[stc->g + 2]);
			handle->state.from = (handle->state.from & 3) | (stc->g << 2);
		}
	}
	return TRANSCRIPT_SUCCESS;
}

/** Simplification macro calling switch_to_set, which returns if not enough space is available. */
#define SWITCH_TO_SET(stc) do { \
	if (switch_to_set(handle, stc, outbuf, outbuflimit) != TRANSCRIPT_SUCCESS) \
		return TRANSCRIPT_NO_SPACE; \
} while (0)

/** convert_from implementation for ISO-2022 converters. */
static transcript_error_t from_unicode_conversion(converter_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	stc_handle_t *fallback_stc = NULL;
	stc_handle_t *ptr;
	char buffer[32], *buffer_ptr;
	uint_fast8_t state;
	transcript_error_t result;
	int internal_flags;

	if (flags & TRANSCRIPT_FILE_START) {
		/* RFC1557 specifies a text should start by loading KSC5601 as G1. */
		if (handle->iso2022_type == ISO2022_KR) {
			PUT_BYTES(4, "\x1b\x24\x29\x43");
			handle->state.g_from[1] = handle->g_sets->next;
		}
	}

	while ((const char *) _inbuf < inbuflimit) {
		fallback_stc = NULL;
		/* Assume that most codepoints will come from the same character set, so just try to
		   convert using that. If it succeeds, we're done. Otherwise, we need to search for
		   the first set that does encode the character. */
		internal_flags = flags & ~(TRANSCRIPT_ALLOW_FALLBACK | TRANSCRIPT_SUBST_ILLEGAL | TRANSCRIPT_SUBST_UNASSIGNED);
		state = handle->state.from;
		if (state > 3) {
			state >>= 2;
			internal_flags |= TRANSCRIPT_SINGLE_CONVERSION;
		}
		ptr = handle->state.g_from[state];
		switch ((result = ptr->stc->convert_from(ptr->stc, (const char **) &_inbuf, inbuflimit, outbuf, outbuflimit, internal_flags))) {
			case TRANSCRIPT_SUCCESS:
				break;
			case TRANSCRIPT_FALLBACK:
				fallback_stc = ptr;
				break;
			case TRANSCRIPT_UNASSIGNED: {
				/* We may have encountered a control character, in which case we
				   should switch to ASCII and continue. */

				uint32_t codepoint;
				codepoint = handle->common.get_unicode((const char **) &_inbuf, inbuflimit, FALSE);
				if (codepoint < 32) {
					/* ESC, SHIFT-IN and SHIFT-OUT can not be encoded in the output, as they
					   are used as character-set control characters. */
					if (codepoint == 0x1b || codepoint == 0x0e || codepoint == 0x0f) {
						if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
							return TRANSCRIPT_ILLEGAL;
						SWITCH_TO_SET(handle->ascii);
						buffer[0] = 0x1a;
						PUT_BYTES(1, buffer);
					} else {
						SWITCH_TO_SET(handle->ascii);
						if (codepoint == 0x0a || codepoint == 0x0d) {
							/* Take the simple approach: go to ASCII mode on _any_ possible line ending.
							   This may be a bit too much, it is not wrong, and some converters may
							   actually be expecting this. */
							handle->reset_state(handle);
						}
						buffer[0] = codepoint;
						PUT_BYTES(1, buffer);
					}
					/* Make sure we skip looking for a matching converter. */
					result = TRANSCRIPT_SUCCESS;
				} else if (codepoint < 0xa0 && codepoint >= 0x80) {
					if (handle->iso2022_type != ISO2022_JP2) {
						if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
							return TRANSCRIPT_UNASSIGNED;
						SWITCH_TO_SET(handle->ascii);
						buffer[0] = 0x1a;
						PUT_BYTES(1, buffer);
					} else if (codepoint == 0x8e || codepoint == 0x8f) {
						/* SS2 and SS3 can not be encoded in the output, as they are
						   used as character-set control characters. */
						if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
							return TRANSCRIPT_ILLEGAL;
						SWITCH_TO_SET(handle->ascii);
						buffer[0] = 0x1a;
						PUT_BYTES(1, buffer);
					} else {
						buffer[0] = 0x1b;
						buffer[1] = codepoint - 0x40;
						PUT_BYTES(2, buffer);
					}
					/* Make sure we skip looking for a matching converter. */
					result = TRANSCRIPT_SUCCESS;
				}
				break;
			}
			case TRANSCRIPT_ILLEGAL:
			case TRANSCRIPT_ILLEGAL_END:
				if (flags & TRANSCRIPT_SUBST_ILLEGAL) {
					SWITCH_TO_SET(handle->ascii);
					buffer[0] = 0x1a;
					PUT_BYTES(1, buffer);
					result = TRANSCRIPT_SUCCESS;
					break;
				}
				/* FALLTHROUGH */
			default:
				return result;
		}

		if (result != TRANSCRIPT_SUCCESS) {
			const char *tmp_inbuf;
			/* Search for a suitable character set. Note that if the conversion succeeded
			   with the previously used character set, we never reach this point. */
			internal_flags = (flags & ~(TRANSCRIPT_ALLOW_FALLBACK | TRANSCRIPT_SUBST_ILLEGAL | TRANSCRIPT_SUBST_UNASSIGNED)) |
				TRANSCRIPT_SINGLE_CONVERSION;
			for (ptr = handle->g_sets; ptr != NULL; ptr = ptr->next) {
				if (!(ptr->flags & STC_FLAG_WRITE))
					continue;

				tmp_inbuf = *inbuf;
				buffer_ptr = buffer;

				switch (ptr->stc->convert_from(ptr->stc, &tmp_inbuf, inbuflimit,
						&buffer_ptr, buffer + 32, internal_flags))
				{
					case TRANSCRIPT_SUCCESS:
						SWITCH_TO_SET(ptr);
						PUT_BYTES(buffer_ptr - buffer, buffer);
						_inbuf = (const uint8_t *) tmp_inbuf;
						goto converter_found;
					case TRANSCRIPT_UNASSIGNED:
						break;
					case TRANSCRIPT_FALLBACK:
						if (fallback_stc == NULL)
							fallback_stc = ptr;
						break;
					case TRANSCRIPT_INCOMPLETE:
						return TRANSCRIPT_INCOMPLETE;
					default:
						return TRANSCRIPT_INTERNAL_ERROR;
				}
			}

			if (fallback_stc == NULL) {
				if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
					return TRANSCRIPT_UNASSIGNED;
				SWITCH_TO_SET(handle->ascii);
				buffer[0] = 0x1a;
				PUT_BYTES(1, buffer);
			} else {
				/* Fallback */
				if (!(flags & TRANSCRIPT_ALLOW_FALLBACK))
					return TRANSCRIPT_FALLBACK;
				SWITCH_TO_SET(fallback_stc);
				switch (fallback_stc->stc->convert_from(fallback_stc->stc, (const char **) &_inbuf, inbuflimit, outbuf, outbuflimit,
					flags | TRANSCRIPT_ALLOW_FALLBACK | TRANSCRIPT_SINGLE_CONVERSION))
				{
					case TRANSCRIPT_NO_SPACE:
						return TRANSCRIPT_NO_SPACE;
					case TRANSCRIPT_SUCCESS:
						break;
					default:
						return TRANSCRIPT_INTERNAL_ERROR;
				}
			}
		}
converter_found:
		*inbuf = (const char *) _inbuf;
		handle->state.from &= 3;

		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}

	if (flags & TRANSCRIPT_END_OF_TEXT)
		SWITCH_TO_SET(handle->ascii);
	return TRANSCRIPT_SUCCESS;
}

/** flush_from implementation for ISO-2022 converters. */
static transcript_error_t from_unicode_flush(converter_state_t *handle, char **outbuf, const char const *outbuflimit) {
	SWITCH_TO_SET(handle->ascii);
	return TRANSCRIPT_SUCCESS;
}

/** reset_from implementation for ISO-2022 converters. */
static void from_unicode_reset(converter_state_t *handle) {
	memcpy(handle->state.g_from, handle->g_initial, sizeof(handle->g_initial));
	handle->state.from = 0;
}

/** save implementation for ISO-2022 converters. */
static void save_iso2022_state(converter_state_t *handle, save_state_t *save) {
	stc_handle_t *ptr;
	int i;

	save->to = handle->state.to;
	save->from = handle->state.from;
	for (i = 0; i < 4; i++) {
		save->g_from[i] = 0;
		ptr = handle->g_sets;
		while (ptr != NULL && ptr != handle->state.g_from[i]) {
			ptr = ptr->next;
			save->g_from[i]++;
		}

		save->g_to[i] = 0;
		ptr = handle->g_sets;
		while (ptr != NULL && ptr != handle->state.g_to[i]) {
			ptr = ptr->next;
			save->g_to[i]++;
		}
	}
}

/** load implementation for ISO-2022 converters. */
static void load_iso2022_state(converter_state_t *handle, save_state_t *save) {
	int i, j;
	handle->state.to = save->to;
	handle->state.from = save->from;
	for (i = 0; i < 4; i++) {
		handle->state.g_from[i] = handle->g_sets;
		for (j = save->g_from[i]; j != 0 && handle->state.g_from[i] != NULL; j--)
			handle->state.g_from[i] = handle->state.g_from[i]->next;

		handle->state.g_to[i] = handle->g_sets;
		for (j = save->g_to[i]; j != 0 && handle->state.g_to[i] != NULL; j--)
			handle->state.g_to[i] = handle->state.g_to[i]->next;
	}
}

/** Do-nothing function for reset_state in ::converter_state_t. */
static void reset_state_nop(converter_state_t *handle) { (void) handle; };

/** Function which resets the states to the initial state for reset_state in ::converter_state_t. */
static void reset_state_cn(converter_state_t *handle) {
	memcpy(handle->state.g_from, handle->g_initial, sizeof(handle->g_initial));
};

/** Function which resets the G2 state to the initial state for reset_state in ::converter_state_t. */
static void reset_state_jp2(converter_state_t *handle) {
	handle->state.g_from[2] = NULL;
}

/** Load a converter (as oposed to probing for it).

    Used internally to load the different converters used by ISO-2022.
*/
static bool_t real_load(converter_state_t *handle, stc_descriptor_t *desc, int g, transcript_error_t *error,
		transcript_utf_t utf_type, uint_fast8_t flags)
{
	stc_handle_t *stc_handle, *extra_handle;
	transcript_t *ext_handle;
	uint_fast8_t idx = 0;

	flags |= desc->flags;

	if ((flags & STC_FLAG_LARGE_SET) && g == 0) {
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_ERROR;
		return FALSE;
	}

	ext_handle = transcript_open_converter_nolock(desc->name, utf_type, TRANSCRIPT_INTERNAL, error);

	if (ext_handle == NULL)
		return FALSE;

	if ((stc_handle = malloc(sizeof(stc_handle_t))) == NULL) {
		transcript_close_converter(ext_handle);
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
		return FALSE;
	}

	stc_handle->stc = ext_handle;
	stc_handle->bytes_per_char = desc->bytes_per_char;
	stc_handle->escape_seq[idx++] = 0x1b;
	if (desc->bytes_per_char > 1)
		stc_handle->escape_seq[idx++] = 0x24;
	stc_handle->escape_seq[idx++] = (desc->flags & STC_FLAG_LARGE_SET ? 0x2C : 0x28) + g;
	stc_handle->escape_seq[idx++] = desc->final_byte;
	stc_handle->seq_len = idx;

	stc_handle->flags = flags;
	stc_handle->prev = NULL;
	stc_handle->g = g;
	stc_handle->next = handle->g_sets;
	handle->g_sets = stc_handle;

	/* Some converters have a short non-compliant sequence as well a strictly
	   compliant escape sequence. Depending on the STC_FLAGS_SHORT_SEQ, either
	   the short sequence or the long sequence is used for from-Unicode conversions. */
	if (desc->final_byte < 0x43 && desc->bytes_per_char > 1) {
		if ((extra_handle = malloc(sizeof(stc_handle_t))) == NULL) {
			transcript_close_converter(ext_handle);
			free(stc_handle);
			if (error != NULL)
				*error = TRANSCRIPT_OUT_OF_MEMORY;
			return FALSE;
		}
		memcpy(extra_handle, stc_handle, sizeof(stc_handle_t));
		extra_handle->escape_seq[2] = desc->final_byte;
		extra_handle->seq_len = 3;
		if (flags & STC_FLAGS_SHORT_SEQ)
			stc_handle->flags &= ~(STC_FLAG_WRITE);
		else
			extra_handle->flags &= ~(STC_FLAG_WRITE);
		extra_handle->flags |= STC_FLAGS_DUPSTC;
		extra_handle->next = handle->g_sets;
		handle->g_sets = extra_handle;
	}

	return TRUE;
}

/** Probe the availability of a converter. */
static bool_t probe(converter_state_t *handle, stc_descriptor_t *desc, int g, transcript_error_t *error,
		transcript_utf_t utf_type, uint_fast8_t flags)
{
	(void) handle;
	(void) g;
	(void) error;
	(void) utf_type;
	(void) flags;

	return transcript_probe_converter_nolock(desc->name);
}

/** Convenience macro which tries to load a converter and exits the function if it is not available. */
#define DO_LOAD(handle, desc, g, _write) do { \
	if (!load((handle), (desc), (g), error, utf_type, (_write))) \
		return FALSE; \
} while (0)

typedef bool_t (*load_table_func)(converter_state_t *handle, stc_descriptor_t *desc, int g, transcript_error_t *error,
	transcript_utf_t utf_type, uint_fast8_t flags);

/** Load the converters required for a specific ISO-2022 converter. */
static bool_t do_load(load_table_func load, converter_state_t *handle, int type, transcript_utf_t utf_type, transcript_error_t *error) {
		switch (type) {
		/* Current understanding of the ISO-2022-JP-* situation:
		   JIS X 0213 has two planes: the first plane which is a superset of
		   JIS X 0208, and plane 2 which contains only new chars. However, in
		   making JIS X 0213, they found that they needed to amend the standard
		   for plane 1 in 2004. The result is 10 added codepoints that were not
		   present in the 2000 version.

		   ISO-2022-JP-2004 is the completely new and revised version, which
		   contains ASCII and JIS X 0213 (2004). Note that plane 2 of JIS X 0213
		   was never revised. For compatibility, JIS X 0208-1983 and
		   JIS X 0213-2000 can be used as well.

		   ISO-2022-JP-3 is the same as ISO-2022-JP-2004, but based on the
		   original JIS X 0213. For plane 1 of JIS X 0213 a different escape
		   sequence is used than in ISO-2022-JP-2004, so there are no nasty
		   problems there.

		   ISO-2022-JP-2 extends ISO-2022-JP-1, which in turn extends ISO-2022-JP
		   standard by adding more character sets.

		   The problem is that not everyone has the same idea of what the
		   ISO-2022-JP-* are. For example, according to the JIS X 0213 standard
		   (Annex 2, Section 4) the only supported sets for ISO-2022-JP-3 are
		   ASCII, JIS X 0213-2000 plane 1 and 2, and JIS X 0208 1983. However,
		   several implementations simply add the JIS X 0213 planes to the
		   ISO-2022-JP-2 sets. To some extent this makes sense, because the
		   JIS X 0213 sets don't cover all characters in the ISO-2022-JP-2
		   repertoire. Also, some converters use JIS X 0208 1990, instead of the
		   1983 version as mandated by the standard(s).

		   Also note that, to make things slightly worse, in the attempts to
		   register the ISO-2022-JP-2004 character set with IANA, the following
		   aliases are named:

		   ISO-2022-JP-3-2003
		   ISO-2022-JP-2003

		   It is unclear what part JIS X 0201 has to play in this. It does encode
		   characters that are not in JIS X 0213. It would seem that some
		   implementors of ISO-2022-JP-* simply add them to have access to the
		   otherwise unavailable characters.
		*/
		case ISO2022_JP2004:
			DO_LOAD(handle, &jis_x_0213_2004_1, 0, STC_FLAG_WRITE);
			/* FALLTHROUGH */
		case ISO2022_JP3:
			if (type != ISO2022_JP3_STRICT && type != ISO2022_JP2004_STRICT) {
				/* These are not officially in ISO-2022-JP3, but glibc iconv includes them. */
				DO_LOAD(handle, &jis_x_0201_1976_roman, 0, STC_FLAG_WRITE);
				DO_LOAD(handle, &jis_x_0201_1976_kana, 0, STC_FLAG_WRITE);
			}
			DO_LOAD(handle, &jis_x_0213_2000_2, 0, STC_FLAG_WRITE);
			DO_LOAD(handle, &jis_x_0213_2000_1, 0, STC_FLAG_WRITE);
			DO_LOAD(handle, &jis_x_0208_1983, 0, STC_FLAG_WRITE | STC_FLAGS_SHORT_SEQ);
			/* Load the JIS X 0208 1990 version for reading only, because some
			   non-compliant converters (e.g. glibc iconv) may generate it. We
			   can actually convert them back to something useful in this case
			   because JIS X 0213 includes them as well. */
			DO_LOAD(handle, &jis_x_0208_1990, 0, STC_FLAGS_SHORT_SEQ);
			if (handle != NULL)
				handle->shift_types = 0;
			break;
		case ISO2022_JP2:
			if (type != ISO2022_JP2_STRICT) {
				DO_LOAD(handle, &jis_x_0201_1976_roman, 0, STC_FLAG_WRITE);
				DO_LOAD(handle, &jis_x_0201_1976_kana, 0, STC_FLAG_WRITE);
			}
			DO_LOAD(handle, &ksc5601_1987, 0, STC_FLAG_WRITE);
			DO_LOAD(handle, &gb2312_1980, 0, STC_FLAG_WRITE | STC_FLAGS_SHORT_SEQ);
			DO_LOAD(handle, &iso8859_7, 2, STC_FLAG_WRITE);
			DO_LOAD(handle, &iso8859_1, 2, STC_FLAG_WRITE);
			if (handle != NULL) {
				handle->reset_state = reset_state_jp2;
				handle->shift_types = SS2;
			}
			/* FALLTHROUGH */
		case ISO2022_JP1:
			DO_LOAD(handle, &jis_x_0212_1990, 0, STC_FLAG_WRITE);
			/* FALLTHROUGH */
		case ISO2022_JP:
			DO_LOAD(handle, &jis_x_0201_1976_roman, 0, STC_FLAG_WRITE);
			DO_LOAD(handle, &jis_x_0208_1978, 0, STC_FLAG_WRITE | STC_FLAGS_SHORT_SEQ);
			DO_LOAD(handle, &jis_x_0208_1983, 0, STC_FLAG_WRITE | STC_FLAGS_SHORT_SEQ);
			if (handle != NULL && type != ISO2022_JP2)
				handle->shift_types = 0;
			break;
		case ISO2022_KR:
			DO_LOAD(handle, &ksc5601_1987, 1, STC_FLAG_WRITE);
			if (handle != NULL)
				handle->shift_types = LS0 | LS1;
			break;
		case ISO2022_CNEXT:
			/* The RFC (1922) lists several more character sets, but only under the assumption
			   that a final character would be assigned to them. To the best of my knowledge,
			   this hasn't happened yet, so we don't include them. */
			DO_LOAD(handle, &iso_ir_165, 1, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_3, 3, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_4, 3, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_5, 3, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_6, 3, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_7, 3, STC_FLAG_WRITE);
			/* FALLTHROUGH */
		case ISO2022_CN:
			DO_LOAD(handle, &gb2312_1980, 1, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_1, 1, STC_FLAG_WRITE);
			DO_LOAD(handle, &cns_11643_1992_2, 2, STC_FLAG_WRITE);
			if (handle != NULL) {
				handle->shift_types = LS0 | LS1 | SS2 | (handle->iso2022_type == ISO2022_CNEXT ? SS3 : 0);
				handle->reset_state = reset_state_cn;
			}
			break;
		default:
			if (error != NULL)
				*error = TRANSCRIPT_INTERNAL_ERROR;
			return FALSE;
	}
	return TRUE;
}

/** Compare function for lfind. */
static int compare(const name_to_iso2022type *a, const name_to_iso2022type *b) {
	return strcmp(a->name, b->name);
}

/** @internal
    @brief Open an ISO-2022 converter.
*/
static void *open_iso2022(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error) {
	converter_state_t *retval;
	name_to_iso2022type *ptr;
	name_to_iso2022type key = { name, 0 };
	size_t array_size = TRANSCRIPT_ARRAY_SIZE(map);

	if ((ptr = lfind(&key, map, &array_size, sizeof(map[0]),
			(int (*)(const void *, const void *)) compare)) == NULL)
	{
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_ERROR;
		return NULL;
	}

	if ((retval = malloc(sizeof(converter_state_t))) == NULL) {
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
		return NULL;
	}
	retval->g_sets = NULL;
	retval->g_initial[0] = NULL;
	retval->g_initial[1] = NULL;
	retval->g_initial[2] = NULL;
	retval->g_initial[3] = NULL;

	retval->iso2022_type = ptr->iso2022_type;
	retval->reset_state = reset_state_nop;

	if (!do_load(real_load, retval, ptr->iso2022_type, utf_type, error)) {
		close_converter(retval);
		return NULL;
	}
	/* Load ASCII, which all converters need. */
	if (!real_load(retval, &ascii, 0, error, utf_type, TRUE)) {
		close_converter(retval);
		return NULL;
	}
	retval->ascii = retval->g_sets;
	retval->g_initial[0] = retval->ascii;

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = (flush_func_t) from_unicode_flush;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_converter;
	retval->common.save = (save_load_func_t) save_iso2022_state;
	retval->common.load = (save_load_func_t) load_iso2022_state;

	to_unicode_reset(retval);
	from_unicode_reset(retval);
	return retval;
}

static bool_t probe_iso2022(const char *name) {
	name_to_iso2022type *ptr;
	name_to_iso2022type key = { name, 0 };
	size_t array_size = TRANSCRIPT_ARRAY_SIZE(map);
	transcript_error_t error;

	if ((ptr = lfind(&key, map, &array_size, sizeof(map[0]),
			(int (*)(const void *, const void *)) compare)) == NULL)
		return FALSE;

	return do_load(probe, NULL, ptr->iso2022_type, 0, &error);
}

/** close implementation for ISO-2022 converters. */
static void close_converter(converter_state_t *handle) {
	stc_handle_t *ptr, *next;

	for (ptr = handle->g_sets; ptr != NULL; ptr = next) {
		if (!(ptr->flags & STC_FLAGS_DUPSTC))
			transcript_close_converter(ptr->stc);
		next = ptr->next;
		free(ptr);
	}
}

TRANSCRIPT_EXPORT const char * const *transcript_namelist_iso2022(void) {
	static const char * const namelist[] = {
		"iso-2022-jp", "iso-2022-jp-1", "iso-2022-jp-2", "iso-2022-jp-3",
		"iso-2022-jp-2004", "iso-2022-kr", "iso-2022-cn", "iso-2022-cn-ext",
		NULL
	};
	return namelist;
}

#define DEFINE_INTERFACE(name) \
TRANSCRIPT_ALIAS_OPEN(open_iso2022, name) \
TRANSCRIPT_ALIAS_PROBE(probe_iso2022, name) \
TRANSCRIPT_EXPORT int transcript_get_iface_##name(void) { return TRANSCRIPT_FULL_MODULE_V1; }

DEFINE_INTERFACE(iso2022jp)
DEFINE_INTERFACE(iso2022jp1)
DEFINE_INTERFACE(iso2022jp2)
DEFINE_INTERFACE(iso2022jp3)
DEFINE_INTERFACE(iso2022jp2004)
DEFINE_INTERFACE(iso2022kr)
DEFINE_INTERFACE(iso2022cn)
DEFINE_INTERFACE(iso2022cnext)
