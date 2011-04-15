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
#include <string.h>
#include "transcript_internal.h"
#include "utf.h"
#include "static_assert.h"

enum {
	FROM_UNICODE_FLAGS_TABLE_INCLUDED = (1<<0),
	TO_UNICODE_FLAGS_TABLE_INCLUDED = (1<<1),
	MULTI_MAPPINGS_AVAILABLE = (1<<2),
	SUBCHAR1_VALID = (1<<3),
	MULTIBYTE_START_STATE_1 = (1<<4),
	INTERNAL_TABLE = (1<<5),
	VARIANTS_AVAILABLE = (1<<6)
};

enum action_t {
	ACTION_FINAL,
	ACTION_FINAL_NOFLAGS,
	ACTION_FINAL_LEN1_NOFLAGS,
	ACTION_FINAL_LEN2_NOFLAGS,
	ACTION_FINAL_LEN3_NOFLAGS,
	ACTION_FINAL_LEN4_NOFLAGS,
	/* Define lengths 5 through 8 such that we don't have to renumber later.
	   Not used right now. */
	ACTION_FINAL_LEN5_NOFLAGS,
	ACTION_FINAL_LEN6_NOFLAGS,
	ACTION_FINAL_LEN7_NOFLAGS,
	ACTION_FINAL_LEN8_NOFLAGS,
	ACTION_VALID,
	ACTION_UNASSIGNED,
	ACTION_SHIFT,
	ACTION_ILLEGAL,

	ACTION_FLAG_PAIR = (1<<7),
	ACTION_FINAL_PAIR = ACTION_FINAL | ACTION_FLAG_PAIR,
	ACTION_FINAL_PAIR_NOFLAGS = ACTION_FINAL_NOFLAGS | ACTION_FLAG_PAIR,
};

enum {
	FROM_UNICODE_LENGTH_MASK = (3<<0),
	FROM_UNICODE_NOT_AVAIL = (1<<2),
	FROM_UNICODE_FALLBACK = (1<<3),
	FROM_UNICODE_SUBCHAR1 = (1<<4),
	FROM_UNICODE_MULTI_START = (1<<5),
	FROM_UNICODE_VARIANT = (1<<6)
};

enum {
	TO_UNICODE_FALLBACK = (1<<0),
	TO_UNICODE_MULTI_START = (1<<1),
	TO_UNICODE_PRIVATE_USE = (1<<2),
	TO_UNICODE_VARIANT = (1<<3)
};

/** @struct save_state_t
    Structure holding the shift state of a state table convertor. */
typedef struct _transcript_state_table_state_t {
	uint8_t to, from;
} save_state_t;

/* Make sure that the saved state will fit in an allocated block. */
static_assert(sizeof(save_state_t) <= TRANSCRIPT_SAVE_STATE_SIZE);

typedef struct {
	uint8_t (*get_flags)(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx);
	const uint8_t *bits2flags;
} flag_handler_t;

/** @struct convertor_state_t
    Structure holding the pointers to the data and the state of a state table convertor. */
typedef struct {
	transcript_t common;
	convertor_tables_v1_t tables;
	flag_handler_t codepage_flags;
	flag_handler_t unicode_flags;
	save_state_t state;
} convertor_state_t;

static transcript_error_t to_unicode_skip(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit);
static bool init_flag_handler(flag_handler_t *flags, uint8_t flag_info);

/** Simplification macro for calling put_unicode which returns automatically on error. */
#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbuflimit)) != TRANSCRIPT_SUCCESS) \
		return result; \
} while (0)

/** Get the minimum of two @c size_t values. */
static _TRANSCRIPT_INLINE size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

/** Find variant conversion for to-Unicode conversion.

    The state table based convertors can store multiple similar convertors in a single
    table. For the different convertors, or variants, look-up tables are provided
    to find the actual conversion. This function perform the look-up.
*/
static void find_to_unicode_variant(const variant_v1_t *variant, const uint8_t *bytes, size_t length,
		uint8_t *conv_flags, uint_fast32_t *codepoint)
{
	const variant_mapping_v1_t *mapping;
	char value[4] = { 0, 0, 0, 0};
	uint_fast16_t low, high, mid;

	memcpy(&value, bytes, length);
	/* The length field as encoded in the from_unicode_flags field is the length - 1,
	   and we need to compare with that. So we decrease length here, so we don't have to
	   add 1 in the comparisons below. */
	length--;

	low = 0;
	high = variant->nr_mappings;
	while (low < high) {
		mid = low + ((high - low) / 2);
		mapping = variant->simple_mappings + variant->simple_mappings[mid].sort_idx;
		if (memcmp(mapping->codepage_bytes, value, 4) < 0 || (memcmp(mapping->codepage_bytes, value, 4) == 0 &&
				(mapping->from_unicode_flags & FROM_UNICODE_LENGTH_MASK) < length))
			low = mid + 1;
		else
			high = mid;
	}
	/* Check whether we actually found a mapping. */
	if (low == variant->nr_mappings)
		return;
	mapping = variant->simple_mappings + variant->simple_mappings[low].sort_idx;
	if (memcmp(mapping->codepage_bytes, value, 4) != 0 ||
			(mapping->from_unicode_flags & FROM_UNICODE_LENGTH_MASK) != length ||
			(mapping->from_unicode_flags & FROM_UNICODE_FALLBACK))
		return;
	/* Note that the items are sorted such that the first in the list has
	   precision 0, the second has precision 3 and the last has precision 1
	   (in as far as they exist of course). We already checked that we don't
	   have a precision 1 mapping, so this mapping is the one we want. */
	*conv_flags = mapping->to_unicode_flags;
	*codepoint = mapping->codepoint;
}

/** convert_to implementation for state table convertors. */
static transcript_error_t to_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	uint_fast8_t state = handle->state.to;
	uint_fast32_t idx = handle->tables.convertor->codepage_states[handle->state.to].base;
	uint_fast32_t codepoint;
	const entry_v1_t *entry;
	uint_fast8_t conv_flags;

	while (_inbuf < (const uint8_t *) inbuflimit) {
		entry = &handle->tables.convertor->codepage_states[state].entries[handle->tables.convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;

		if (entry->action == ACTION_FINAL_NOFLAGS) {
			PUT_UNICODE(handle->tables.convertor->codepage_mappings[idx]);
		} else if (entry->action == ACTION_VALID) {
			/* Sequence not complete yet... */
			state = entry->next_state;
			continue;
		} else if (entry->action == ACTION_FINAL_PAIR_NOFLAGS) {
			codepoint = handle->tables.convertor->codepage_mappings[idx];
			if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
				codepoint -= UINT32_C(0xd800);
				codepoint <<= 10;
				codepoint += handle->tables.convertor->codepage_mappings[idx + 1] - UINT32_C(0xdc00);
				codepoint += 0x10000;
			}
			PUT_UNICODE(codepoint);
		} else if (entry->action == ACTION_FINAL) {
			/* NOTE: we don't check for FINAL_PAIR, because that was converted when loading. */
			conv_flags = handle->codepage_flags.get_flags(&handle->tables.convertor->codepage_flags,
				handle->codepage_flags.bits2flags, idx);
			if ((conv_flags & TO_UNICODE_MULTI_START) &&
					(flags & (TRANSCRIPT_NO_MN_CONVERSION | TRANSCRIPT_NO_1N_CONVERSION)) < TRANSCRIPT_NO_1N_CONVERSION)
			{
				size_t check_len;
				uint_fast32_t i, j;
				char *outbuf_tmp;
				int result;

				/* Note: we sorted the multi_mappings table according to bytes_length, so we will first
				   check the longer mappings. This way we always find the longest match. */
				for (i = 0; i < handle->tables.nr_multi_mappings; i++) {
					check_len = min(handle->tables.codepage_sorted_multi_mappings[i]->bytes_length, inbuflimit - *inbuf);

					/* Check if the multi-mapping is a prefix of the current input, or the
					   current input is a prefix of the multi-mapping. */
					if (memcmp(handle->tables.codepage_sorted_multi_mappings[i]->bytes, *inbuf, check_len) != 0)
						continue;

					/* Handle the case where the input is a prefix of the multi-mapping. */
					if (check_len != handle->tables.codepage_sorted_multi_mappings[i]->bytes_length) {
						if (flags & (TRANSCRIPT_END_OF_TEXT | TRANSCRIPT_NO_MN_CONVERSION))
							continue;
						return TRANSCRIPT_INCOMPLETE;
					}

					/* We found the longest matching multi-mapping. Write the associated
					   Unicode codepoints to the output buffer. */
					outbuf_tmp = *outbuf;
					for (j = 0; j < handle->tables.codepage_sorted_multi_mappings[i]->codepoints_length; j++) {
						codepoint = handle->tables.codepage_sorted_multi_mappings[i]->codepoints[j];
						if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
							j++;
							codepoint -= UINT32_C(0xd800);
							codepoint <<= 10;
							codepoint += handle->tables.codepage_sorted_multi_mappings[i]->codepoints[j] - UINT32_C(0xdc00);
							codepoint += 0x10000;
						}
						if ((result = handle->common.put_unicode(codepoint, &outbuf_tmp, outbuflimit)) != TRANSCRIPT_SUCCESS)
							return result;
					}
					*outbuf = outbuf_tmp;

					/* Update the state and the *inbuf pointer. Note that to get
					   to the correct next input state we need to "parse" the
					   input, so we use to_unicode_skip to update *inbuf. */
					_inbuf = (const uint8_t *) ((*inbuf) + check_len);
					handle->state.to = state = entry->next_state;
					while ((const uint8_t *) *inbuf < _inbuf)
						if (to_unicode_skip(handle, inbuf, inbuflimit) != 0)
							return TRANSCRIPT_INTERNAL_ERROR;
					idx = handle->tables.convertor->codepage_states[handle->state.to].base;
					if (flags & TRANSCRIPT_SINGLE_CONVERSION)
						return TRANSCRIPT_SUCCESS;
					break; /* Break from multi-mapping search. */
				}
				if (i != handle->tables.nr_multi_mappings)
					continue;
			}

			codepoint = handle->tables.convertor->codepage_mappings[idx];
			if (conv_flags & TO_UNICODE_VARIANT) {
				find_to_unicode_variant(handle->tables.variant, (const uint8_t *) *inbuf, (const char *) _inbuf - *inbuf,
					&conv_flags, &codepoint);
			}

			if ((conv_flags & TO_UNICODE_PRIVATE_USE) && !(flags & TRANSCRIPT_ALLOW_PRIVATE_USE)) {
				if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
					return TRANSCRIPT_PRIVATE_USE;
				PUT_UNICODE(UINT32_C(0xfffd));
			} else if ((conv_flags & TO_UNICODE_FALLBACK) && !(flags & TRANSCRIPT_ALLOW_FALLBACK)) {
				return TRANSCRIPT_FALLBACK;
			} else if (codepoint == UINT32_C(0xffff)) {
				if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
					return TRANSCRIPT_UNASSIGNED;
				PUT_UNICODE(UINT32_C(0xfffd));
			} else {
				if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
					codepoint -= UINT32_C(0xd800);
					codepoint <<= 10;
					codepoint += handle->tables.convertor->codepage_mappings[idx + 1] - UINT32_C(0xdc00);
					codepoint += 0x10000;
				}
				PUT_UNICODE(codepoint);
			}
		} else if (entry->action == ACTION_ILLEGAL) {
			if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
				return TRANSCRIPT_ILLEGAL;
			PUT_UNICODE(UINT32_C(0xfffd));
		} else if (entry->action == ACTION_UNASSIGNED) {
			if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
				return TRANSCRIPT_UNASSIGNED;
			PUT_UNICODE(UINT32_C(0xfffd));
		} else if (entry->action != ACTION_SHIFT) {
			return TRANSCRIPT_INTERNAL_ERROR;
		}
		/* Update state. */
		*inbuf = (const char *) _inbuf;
		handle->state.to = state = entry->next_state;
		idx = handle->tables.convertor->codepage_states[handle->state.to].base;

		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}

	/* Check for incomplete characters at the end of the buffer. */
	if (*inbuf != inbuflimit) {
		if (flags & TRANSCRIPT_END_OF_TEXT) {
			if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
				return TRANSCRIPT_ILLEGAL_END;
			PUT_UNICODE(UINT32_C(0xFFFD));
			*inbuf = inbuflimit;
		} else {
			return TRANSCRIPT_INCOMPLETE;
		}
	}
	return TRANSCRIPT_SUCCESS;
}

/** skip_to implementation for state table convertors. */
static transcript_error_t to_unicode_skip(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit) {
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	uint_fast8_t state = handle->state.to;
	uint_fast32_t idx = handle->tables.convertor->codepage_states[handle->state.to].base;
	const entry_v1_t *entry;

	while (_inbuf < (const uint8_t *) inbuflimit) {
		entry = &handle->tables.convertor->codepage_states[state].entries[handle->tables.convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;

		switch (entry->action) {
			case ACTION_SHIFT:
			case ACTION_VALID:
				state = entry->next_state;
				break;
			case ACTION_FINAL:
			case ACTION_FINAL_PAIR:
			case ACTION_ILLEGAL:
			case ACTION_UNASSIGNED:
				*inbuf = (const char *) _inbuf;
				handle->state.to = state = entry->next_state;
				return TRANSCRIPT_SUCCESS;
			default:
				return TRANSCRIPT_INTERNAL_ERROR;
		}
	}

	return TRANSCRIPT_INCOMPLETE;
}

/** reset_to implementation for state table convertors. */
static void to_unicode_reset(convertor_state_t *handle) {
	handle->state.to = 0;
}

/** Simplification macro for the get_unicode function in the convertor handle. */
#define GET_UNICODE() do { \
	codepoint = handle->common.get_unicode((const char **) &_inbuf, inbuflimit, false); \
} while (0)

/** Simplification macro for the put_bytes call, which automatically returns on TRANSCRIPT_NO_SPACE. */
#define PUT_BYTES(count, buffer) do { \
	if (put_bytes(handle, outbuf, outbuflimit, count, buffer) == TRANSCRIPT_NO_SPACE) \
		return TRANSCRIPT_NO_SPACE; \
} while (0)

/** Write a byte sequence to the output, prepending a shift sequence if necessary. */
static _TRANSCRIPT_INLINE transcript_error_t put_bytes(convertor_state_t *handle, char **outbuf,
		const char const *outbuflimit, size_t count, const uint8_t *bytes)
{
	uint_fast8_t required_state;
	uint_fast8_t i;

	/* Shift sequences are only necessary for specificly marked convertors. */
	if (handle->tables.convertor->flags & MULTIBYTE_START_STATE_1) {
		required_state = count > 1 ? 1 : 0;
		if (handle->state.from != required_state) {
			/* Find the correct shift sequence. This can handle more than simply
			   going from state 0 to 1 and vice versa. */
			for (i = 0; i < handle->tables.convertor->nr_shift_states; i++) {
				if (handle->tables.convertor->shift_states[i].from_state == handle->state.from &&
						handle->tables.convertor->shift_states[i].to_state == required_state)
				{
					if ((*outbuf) + count + handle->tables.convertor->shift_states[i].len > outbuflimit)
						return TRANSCRIPT_NO_SPACE;
					memcpy(*outbuf, handle->tables.convertor->shift_states[i].bytes, handle->tables.convertor->shift_states[i].len);
					*outbuf += handle->tables.convertor->shift_states[i].len;
					handle->state.from = required_state;
					/* The space check has already been done, so simply skip to
					   the copying of the output bytes. */
					goto write_bytes;
				}
			}
		}
	}
	if ((*outbuf) + count > outbuflimit)
		return TRANSCRIPT_NO_SPACE;

write_bytes:
	/* Using the switch here is faster than memcpy, which has to be completely general. */
	/* Use 8 here, just so we don't create a bug when we decide to up mb_cur_max. */
	switch (count) {
		case 8: *(*outbuf)++ = *bytes++;
		case 7: *(*outbuf)++ = *bytes++;
		case 6: *(*outbuf)++ = *bytes++;
		case 5: *(*outbuf)++ = *bytes++;
		case 4: *(*outbuf)++ = *bytes++;
		case 3: *(*outbuf)++ = *bytes++;
		case 2: *(*outbuf)++ = *bytes++;
		case 1: *(*outbuf)++ = *bytes++;
		default: ;
	}
	return TRANSCRIPT_SUCCESS;
}

/** Check if the current input is a multi-mapping for a from-Unicode conversion. */
static transcript_error_t from_unicode_check_multi_mappings(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;
	uint_fast32_t i;

	/* Buffer is over-dimensioned by 1 to prevent need for checking the end of buffer. */
	uint16_t codepoints[20];
	char *ptr = (char *) codepoints;

	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	size_t check_len;
	size_t mapping_check_len;
	bool can_read_more = flags & TRANSCRIPT_NO_MN_CONVERSION ? false : true;

	/* Note: we specifically use the codepoint_sorted_multi_mappings to ensure that we always use
	   the longest possible match. */

	GET_UNICODE();
	if (_transcript_put_utf16_no_check(codepoint, &ptr) != 0)
		return TRANSCRIPT_INTERNAL_ERROR;

	for (i = 0; i < handle->tables.nr_multi_mappings; i++) {
		/* Skip if the first codepoint is smaller. */
		if (codepoints[0] < handle->tables.codepage_sorted_multi_mappings[i]->codepoints[0])
			continue;
		/* Skip other tests if the first codepoint is larger (sorted input). */
		else if (codepoints[0] > handle->tables.codepage_sorted_multi_mappings[i]->codepoints[0])
			break;

		mapping_check_len = handle->tables.codepoint_sorted_multi_mappings[i]->codepoints_length * 2;
		check_len = min(ptr - (char *) codepoints, mapping_check_len);

		/* Get more Unicode codepoints if the mapping we are checking is longer than
		   what we have in our buffer. However, only if there is more input available. */
		while (can_read_more && check_len < mapping_check_len) {
			GET_UNICODE();

			if (codepoint == TRANSCRIPT_UTF_INCOMPLETE) {
				if (flags & TRANSCRIPT_END_OF_TEXT) {
					can_read_more = false;
					goto check_next_mapping;
				}
				return TRANSCRIPT_INCOMPLETE;
			}

			if (codepoint == TRANSCRIPT_UTF_ILLEGAL) {
				can_read_more = false;
				goto check_next_mapping;
			}

			switch (_transcript_put_utf16_no_check(codepoint, &ptr)) {
				case TRANSCRIPT_INCOMPLETE:
					if (flags & TRANSCRIPT_END_OF_TEXT) {
						can_read_more = false;
						goto check_next_mapping;
					}
					return TRANSCRIPT_INCOMPLETE;
				case TRANSCRIPT_SUCCESS:
					break;
				case TRANSCRIPT_NO_SPACE:
					can_read_more = false;
					goto check_next_mapping;
				default:
					return TRANSCRIPT_INTERNAL_ERROR;
			}
			check_len = ptr - (char *) codepoints;
		}

		if (check_len >= mapping_check_len && memcmp(codepoints, handle->tables.codepoint_sorted_multi_mappings[i]->codepoints,
				mapping_check_len) == 0)
		{
			/* Multi-mapping found. */
			PUT_BYTES(handle->tables.codepoint_sorted_multi_mappings[i]->bytes_length,
				handle->tables.codepoint_sorted_multi_mappings[i]->bytes);

			if ((size_t) (ptr - (char *) codepoints) != mapping_check_len) {
				/* Re-read codepoints up to the number in the mapping. */
				_inbuf = (const uint8_t *) *inbuf;
				for (check_len = 0; mapping_check_len > check_len; check_len += codepoint > 0xffff ? 4 : 2)
					GET_UNICODE();
			}
			*inbuf = (const char *) _inbuf;
			return TRANSCRIPT_SUCCESS;
		}
check_next_mapping: ;
	}
	return -1;
}

/** Find variant conversion for from-Unicode conversion.

    The state table based convertors can store multiple similar convertors in a single
    table. For the different convertors, or variants, look-up tables are provided
    to find the actual conversion. This function perform the look-up.
*/
static void find_from_unicode_variant(const variant_v1_t *variant, uint32_t codepoint,
		uint8_t *conv_flags, const uint8_t **bytes)
{
	const variant_mapping_v1_t *mapping;
	uint_fast16_t low, high, mid;

	low = 0;
	high = variant->nr_mappings;
	while (low < high) {
		mid = low + ((high - low) / 2);
		mapping = variant->simple_mappings + mid;
		if (mapping->codepoint < codepoint)
			low = mid + 1;
		else
			high = mid;
	}
	mapping = variant->simple_mappings + low;
	/* Check whether we actually found a mapping. */
	if (low == variant->nr_mappings || mapping->codepoint != codepoint || (mapping->to_unicode_flags & TO_UNICODE_FALLBACK))
		return;
	/* Note that the items are sorted such that the first in the list has
	   precision 0, the second has precision 1 and the last has precision 3
	   (in as far as they exist of course). We already checked that we don't
	   have a precision 3 mapping, so this mapping is the one we want. */
	*conv_flags = mapping->from_unicode_flags;
	*bytes = (uint8_t *) &mapping->codepage_bytes;
}

/** convert_from implementation for state table convertors. */
static transcript_error_t from_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	const uint8_t *_inbuf;
	uint_fast8_t state, state_16_bit;
	uint_fast32_t idx;
	uint_fast32_t codepoint;
	const entry_v1_t *entry;
	uint_fast8_t byte;
	uint_fast8_t conv_flags;
	const uint8_t *bytes;

	_inbuf = (const uint8_t *) *inbuf;


	entry = &handle->tables.convertor->unicode_states[0].entries[handle->tables.convertor->unicode_states[0].map[0]];
	state_16_bit = entry->next_state;

	while (*inbuf < inbuflimit) {
		GET_UNICODE();
		if (codepoint == TRANSCRIPT_UTF_INCOMPLETE)
			break;

		if (codepoint == TRANSCRIPT_UTF_ILLEGAL) {
			if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
				return TRANSCRIPT_ILLEGAL;
			PUT_BYTES(handle->tables.convertor->subchar_len, handle->tables.convertor->subchar);
			*inbuf = (const char *) _inbuf;
			continue;
		}

		/* Calculate index in conversion table. Contrary to the to-Unicode case,
		   we know which bytes make up the input, so we don't have to do this in a
		   byte-by-byte loop. */

		/* Optimize common case by not doing an actual lookup when the first byte is 0. */
		if (codepoint > 0x10000L) {
			byte = (codepoint >> 16) & 0xff;
			entry = &handle->tables.convertor->unicode_states[0].entries[handle->tables.convertor->unicode_states[0].map[byte]];
			idx = entry->base + (byte - entry->low) * entry->mul;
			state = entry->next_state;
		} else {
			idx = 0;
			state = state_16_bit;
		}

		byte = (codepoint >> 8) & 0xff;
		entry = &handle->tables.convertor->unicode_states[state].entries[handle->tables.convertor->unicode_states[state].map[byte]];
		idx += entry->base + (byte - entry->low) * entry->mul;
		state = entry->next_state;

		byte = codepoint & 0xff;
		entry = &handle->tables.convertor->unicode_states[state].entries[handle->tables.convertor->unicode_states[state].map[byte]];
		idx += entry->base + (byte - entry->low) * entry->mul;

		/* First check for the most common case: a simple conversion without any special flags. */
		if (entry->action >= ACTION_FINAL_LEN1_NOFLAGS && entry->action <= ACTION_FINAL_LEN4_NOFLAGS) {
			bytes = &handle->tables.convertor->unicode_mappings[idx * handle->tables.convertor->single_size];
			PUT_BYTES(entry->action - ACTION_FINAL_LEN1_NOFLAGS + 1, bytes);
		} else if (entry->action == ACTION_FINAL) {
			conv_flags = handle->unicode_flags.get_flags(&handle->tables.convertor->unicode_flags,
				handle->unicode_flags.bits2flags, idx);
			if ((conv_flags & FROM_UNICODE_MULTI_START) &&
					(flags & (TRANSCRIPT_NO_MN_CONVERSION | TRANSCRIPT_NO_1N_CONVERSION)) < TRANSCRIPT_NO_1N_CONVERSION)
			{
				/* Check multi-mappings. */
				switch (from_unicode_check_multi_mappings(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags)) {
					case TRANSCRIPT_SUCCESS:
						_inbuf = (const uint8_t *) *inbuf;
						if (flags & TRANSCRIPT_SINGLE_CONVERSION)
							return TRANSCRIPT_SUCCESS;
						continue;
					case TRANSCRIPT_INCOMPLETE:
						return TRANSCRIPT_INCOMPLETE;
					case TRANSCRIPT_INTERNAL_ERROR:
					default:
						return TRANSCRIPT_INTERNAL_ERROR;
					case TRANSCRIPT_NO_SPACE:
						return TRANSCRIPT_NO_SPACE;
					case -1:
						break;
				}
			}

			bytes = &handle->tables.convertor->unicode_mappings[idx * handle->tables.convertor->single_size];
			if (conv_flags & FROM_UNICODE_VARIANT)
				find_from_unicode_variant(handle->tables.variant, codepoint, &conv_flags, &bytes);

			if ((conv_flags & FROM_UNICODE_FALLBACK) && !(flags & TRANSCRIPT_ALLOW_FALLBACK))
				return TRANSCRIPT_FALLBACK;

			if (conv_flags & FROM_UNICODE_NOT_AVAIL) {
				/* The HANDLE_UNASSIGNED macro first checks for generic call-backs, and
				   uses the code in parentheses when even that doesn't result in a mapping. */
				HANDLE_UNASSIGNED(
					if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
						return TRANSCRIPT_UNASSIGNED;
					if (conv_flags & FROM_UNICODE_SUBCHAR1)
						PUT_BYTES(1, &handle->tables.convertor->subchar1);
					else
						PUT_BYTES(handle->tables.convertor->subchar_len, handle->tables.convertor->subchar);
				)
			} else {
				PUT_BYTES((conv_flags & FROM_UNICODE_LENGTH_MASK) + 1, bytes);
			}
		} else if (entry->action == ACTION_ILLEGAL) {
			if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
				return TRANSCRIPT_ILLEGAL;
			PUT_BYTES(handle->tables.convertor->subchar_len, handle->tables.convertor->subchar);
		} else if (entry->action == ACTION_UNASSIGNED) {
			/* The HANDLE_UNASSIGNED macro first checks for generic call-backs, and
			   uses the code in parentheses when even that doesn't result in a mapping. */
			HANDLE_UNASSIGNED(
				if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
					return TRANSCRIPT_UNASSIGNED;
				PUT_BYTES(handle->tables.convertor->subchar_len, handle->tables.convertor->subchar);
			)
		} else {
			return TRANSCRIPT_INTERNAL_ERROR;
		}
		*inbuf = (const char *) _inbuf;
		if (flags & TRANSCRIPT_SINGLE_CONVERSION)
			return TRANSCRIPT_SUCCESS;
	}

	/* Check for incomplete characters at the end of the buffer. */
	if (*inbuf < inbuflimit) {
		if (flags & TRANSCRIPT_END_OF_TEXT) {
			if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
				return TRANSCRIPT_ILLEGAL_END;
			PUT_BYTES(handle->tables.convertor->subchar_len, handle->tables.convertor->subchar);
			*inbuf = inbuflimit;
		} else {
			return TRANSCRIPT_INCOMPLETE;
		}
	}
	return TRANSCRIPT_SUCCESS;
}

/** flush_from implementation for state table convertors. */
static transcript_error_t from_unicode_flush(convertor_state_t *handle, char **outbuf, const char const *outbuflimit) {
	if (handle->state.from != 0)
		PUT_BYTES(0, NULL);
	return TRANSCRIPT_SUCCESS;
}

/** reset_from implementation for state table convertors. */
static void from_unicode_reset(convertor_state_t *handle) {
	handle->state.from = 0;
}

/** save implementation for state table convertors. */
static void save_state_table_state(convertor_state_t *handle, save_state_t *save) {
	memcpy(save, &handle->state, sizeof(save_state_t));
}

/** load implementation for state table convertors. */
static void load_state_table_state(convertor_state_t *handle, save_state_t *save) {
	memcpy(&handle->state, save, sizeof(save_state_t));
}

/** @internal
    @brief Load a state table table and create a convertor handle from it.
    @param name The name of the convertor, which must correspond to a file name.
    @param flags Flags for the convertor.
    @param error The location to store an error.
*/
void *_transcript_open_state_table_convertor(const convertor_tables_v1_t *tables, int flags, transcript_error_t *error) {
	convertor_state_t *retval;

	if (!(flags & TRANSCRIPT_INTERNAL) &&
			((tables->variant == NULL ? tables->convertor->flags : tables->variant->flags) & (INTERNAL_TABLE | VARIANTS_AVAILABLE)))
	{
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_TABLE;
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == NULL) {
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
		return NULL;
	}

	retval->tables = *tables;
	retval->state.from = 0;
	retval->state.to = 0;

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = (flush_func_t) from_unicode_flush;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = NULL;
	retval->common.save = (save_func_t) save_state_table_state;
	retval->common.load = (load_func_t) load_state_table_state;

	init_flag_handler(&retval->codepage_flags, tables->convertor->codepage_flags.flags_type);
	init_flag_handler(&retval->unicode_flags, tables->convertor->unicode_flags.flags_type);
	return retval;
}

static uint8_t bits2flags4[][16];
static uint8_t bits2flags2[][4];
static uint8_t bits2flags1[][2];

static _TRANSCRIPT_INLINE uint8_t get_default_flags(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	(void) idx;
	(void) bits2flags;
	return flags->default_flags;
}
static _TRANSCRIPT_INLINE uint8_t get_flags_1(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return flags->default_flags | bits2flags[(flags->flags[idx >> 3] >> (idx & 7)) & 0x1];
}
static _TRANSCRIPT_INLINE uint8_t get_flags_2(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return flags->default_flags | bits2flags[(flags->flags[idx >> 2] >> (2 * (idx & 3))) & 0x3];
}
static _TRANSCRIPT_INLINE uint8_t get_flags_4(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return flags->default_flags | bits2flags[(flags->flags[idx >> 1] >> (4 * (idx & 1))) & 0xf];
}
static _TRANSCRIPT_INLINE uint8_t get_flags_8(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	(void) bits2flags;
	return flags->default_flags | flags->flags[idx];
}

static uint8_t get_flags_1_trie(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return get_flags_1(flags, bits2flags, (idx & 127) + (flags->indices[idx >> 7] << 7));
}
static uint8_t get_flags_2_trie(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return get_flags_2(flags, bits2flags, (idx & 63) + (flags->indices[idx >> 6] << 6));
}
static uint8_t get_flags_4_trie(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return get_flags_4(flags, bits2flags, (idx & 31) + (flags->indices[idx >> 5] << 5));
}
static uint8_t get_flags_8_trie(const flags_v1_t *flags, const uint8_t *bits2flags, uint_fast32_t idx) {
	return get_flags_8(flags, bits2flags, (idx & 15) + (flags->indices[idx >> 4] << 4));
}

static bool init_flag_handler(flag_handler_t *flags, uint8_t flag_info) {
	bool trie;

	trie = (flag_info & 0x80) != 0;
	flag_info &= 0x7f;
	if (flag_info > 106) {
		return false;
	} else if (flag_info > 98) {
		flags->bits2flags = bits2flags1[flag_info - 99];
		flags->get_flags = trie ? get_flags_1_trie : get_flags_1;
	} else if (flag_info > 70) {
		flags->bits2flags = bits2flags2[flag_info - 71];
		flags->get_flags = trie ? get_flags_2_trie : get_flags_2;
	} else if (flag_info > 0) {
		flags->bits2flags = bits2flags4[flag_info - 1];
		flags->get_flags = trie ? get_flags_4_trie : get_flags_4;
	} else {
		flags->get_flags = trie ? get_flags_8_trie : get_flags_8;
	}
	return true;
}


static uint8_t bits2flags4[][16] = {
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x10, 0x11, 0x14, 0x15, 0x18, 0x19, 0x1c, 0x1d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x20, 0x21, 0x24, 0x25, 0x28, 0x29, 0x2c, 0x2d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e },
{ 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33 },
{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x20, 0x21, 0x24, 0x25, 0x30, 0x31, 0x34, 0x35 },
{ 0x00, 0x02, 0x04, 0x06, 0x10, 0x12, 0x14, 0x16, 0x20, 0x22, 0x24, 0x26, 0x30, 0x32, 0x34, 0x36 },
{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x20, 0x21, 0x28, 0x29, 0x30, 0x31, 0x38, 0x39 },
{ 0x00, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x20, 0x22, 0x28, 0x2a, 0x30, 0x32, 0x38, 0x3a },
{ 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x40, 0x41, 0x42, 0x43, 0x48, 0x49, 0x4a, 0x4b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4c, 0x4d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e },
{ 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x40, 0x41, 0x42, 0x43, 0x50, 0x51, 0x52, 0x53 },
{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x40, 0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 },
{ 0x00, 0x02, 0x04, 0x06, 0x10, 0x12, 0x14, 0x16, 0x40, 0x42, 0x44, 0x46, 0x50, 0x52, 0x54, 0x56 },
{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x40, 0x41, 0x48, 0x49, 0x50, 0x51, 0x58, 0x59 },
{ 0x00, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x40, 0x42, 0x48, 0x4a, 0x50, 0x52, 0x58, 0x5a },
{ 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c },
{ 0x00, 0x01, 0x02, 0x03, 0x20, 0x21, 0x22, 0x23, 0x40, 0x41, 0x42, 0x43, 0x60, 0x61, 0x62, 0x63 },
{ 0x00, 0x01, 0x04, 0x05, 0x20, 0x21, 0x24, 0x25, 0x40, 0x41, 0x44, 0x45, 0x60, 0x61, 0x64, 0x65 },
{ 0x00, 0x02, 0x04, 0x06, 0x20, 0x22, 0x24, 0x26, 0x40, 0x42, 0x44, 0x46, 0x60, 0x62, 0x64, 0x66 },
{ 0x00, 0x01, 0x08, 0x09, 0x20, 0x21, 0x28, 0x29, 0x40, 0x41, 0x48, 0x49, 0x60, 0x61, 0x68, 0x69 },
{ 0x00, 0x02, 0x08, 0x0a, 0x20, 0x22, 0x28, 0x2a, 0x40, 0x42, 0x48, 0x4a, 0x60, 0x62, 0x68, 0x6a },
{ 0x00, 0x04, 0x08, 0x0c, 0x20, 0x24, 0x28, 0x2c, 0x40, 0x44, 0x48, 0x4c, 0x60, 0x64, 0x68, 0x6c },
{ 0x00, 0x01, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41, 0x50, 0x51, 0x60, 0x61, 0x70, 0x71 },
{ 0x00, 0x02, 0x10, 0x12, 0x20, 0x22, 0x30, 0x32, 0x40, 0x42, 0x50, 0x52, 0x60, 0x62, 0x70, 0x72 },
{ 0x00, 0x04, 0x10, 0x14, 0x20, 0x24, 0x30, 0x34, 0x40, 0x44, 0x50, 0x54, 0x60, 0x64, 0x70, 0x74 },
{ 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78 },
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 },
{ 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x80, 0x81, 0x82, 0x83, 0x88, 0x89, 0x8a, 0x8b },
{ 0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x80, 0x81, 0x84, 0x85, 0x88, 0x89, 0x8c, 0x8d },
{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e },
{ 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x80, 0x81, 0x82, 0x83, 0x90, 0x91, 0x92, 0x93 },
{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x80, 0x81, 0x84, 0x85, 0x90, 0x91, 0x94, 0x95 },
{ 0x00, 0x02, 0x04, 0x06, 0x10, 0x12, 0x14, 0x16, 0x80, 0x82, 0x84, 0x86, 0x90, 0x92, 0x94, 0x96 },
{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x80, 0x81, 0x88, 0x89, 0x90, 0x91, 0x98, 0x99 },
{ 0x00, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x80, 0x82, 0x88, 0x8a, 0x90, 0x92, 0x98, 0x9a },
{ 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x80, 0x84, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c },
{ 0x00, 0x01, 0x02, 0x03, 0x20, 0x21, 0x22, 0x23, 0x80, 0x81, 0x82, 0x83, 0xa0, 0xa1, 0xa2, 0xa3 },
{ 0x00, 0x01, 0x04, 0x05, 0x20, 0x21, 0x24, 0x25, 0x80, 0x81, 0x84, 0x85, 0xa0, 0xa1, 0xa4, 0xa5 },
{ 0x00, 0x02, 0x04, 0x06, 0x20, 0x22, 0x24, 0x26, 0x80, 0x82, 0x84, 0x86, 0xa0, 0xa2, 0xa4, 0xa6 },
{ 0x00, 0x01, 0x08, 0x09, 0x20, 0x21, 0x28, 0x29, 0x80, 0x81, 0x88, 0x89, 0xa0, 0xa1, 0xa8, 0xa9 },
{ 0x00, 0x02, 0x08, 0x0a, 0x20, 0x22, 0x28, 0x2a, 0x80, 0x82, 0x88, 0x8a, 0xa0, 0xa2, 0xa8, 0xaa },
{ 0x00, 0x04, 0x08, 0x0c, 0x20, 0x24, 0x28, 0x2c, 0x80, 0x84, 0x88, 0x8c, 0xa0, 0xa4, 0xa8, 0xac },
{ 0x00, 0x01, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x80, 0x81, 0x90, 0x91, 0xa0, 0xa1, 0xb0, 0xb1 },
{ 0x00, 0x02, 0x10, 0x12, 0x20, 0x22, 0x30, 0x32, 0x80, 0x82, 0x90, 0x92, 0xa0, 0xa2, 0xb0, 0xb2 },
{ 0x00, 0x04, 0x10, 0x14, 0x20, 0x24, 0x30, 0x34, 0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4, 0xb0, 0xb4 },
{ 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8 },
{ 0x00, 0x01, 0x02, 0x03, 0x40, 0x41, 0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0xc0, 0xc1, 0xc2, 0xc3 },
{ 0x00, 0x01, 0x04, 0x05, 0x40, 0x41, 0x44, 0x45, 0x80, 0x81, 0x84, 0x85, 0xc0, 0xc1, 0xc4, 0xc5 },
{ 0x00, 0x02, 0x04, 0x06, 0x40, 0x42, 0x44, 0x46, 0x80, 0x82, 0x84, 0x86, 0xc0, 0xc2, 0xc4, 0xc6 },
{ 0x00, 0x01, 0x08, 0x09, 0x40, 0x41, 0x48, 0x49, 0x80, 0x81, 0x88, 0x89, 0xc0, 0xc1, 0xc8, 0xc9 },
{ 0x00, 0x02, 0x08, 0x0a, 0x40, 0x42, 0x48, 0x4a, 0x80, 0x82, 0x88, 0x8a, 0xc0, 0xc2, 0xc8, 0xca },
{ 0x00, 0x04, 0x08, 0x0c, 0x40, 0x44, 0x48, 0x4c, 0x80, 0x84, 0x88, 0x8c, 0xc0, 0xc4, 0xc8, 0xcc },
{ 0x00, 0x01, 0x10, 0x11, 0x40, 0x41, 0x50, 0x51, 0x80, 0x81, 0x90, 0x91, 0xc0, 0xc1, 0xd0, 0xd1 },
{ 0x00, 0x02, 0x10, 0x12, 0x40, 0x42, 0x50, 0x52, 0x80, 0x82, 0x90, 0x92, 0xc0, 0xc2, 0xd0, 0xd2 },
{ 0x00, 0x04, 0x10, 0x14, 0x40, 0x44, 0x50, 0x54, 0x80, 0x84, 0x90, 0x94, 0xc0, 0xc4, 0xd0, 0xd4 },
{ 0x00, 0x08, 0x10, 0x18, 0x40, 0x48, 0x50, 0x58, 0x80, 0x88, 0x90, 0x98, 0xc0, 0xc8, 0xd0, 0xd8 },
{ 0x00, 0x01, 0x20, 0x21, 0x40, 0x41, 0x60, 0x61, 0x80, 0x81, 0xa0, 0xa1, 0xc0, 0xc1, 0xe0, 0xe1 },
{ 0x00, 0x02, 0x20, 0x22, 0x40, 0x42, 0x60, 0x62, 0x80, 0x82, 0xa0, 0xa2, 0xc0, 0xc2, 0xe0, 0xe2 },
{ 0x00, 0x04, 0x20, 0x24, 0x40, 0x44, 0x60, 0x64, 0x80, 0x84, 0xa0, 0xa4, 0xc0, 0xc4, 0xe0, 0xe4 },
{ 0x00, 0x08, 0x20, 0x28, 0x40, 0x48, 0x60, 0x68, 0x80, 0x88, 0xa0, 0xa8, 0xc0, 0xc8, 0xe0, 0xe8 },
{ 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 }};

static uint8_t bits2flags2[][4] = {
{ 0x00, 0x01, 0x02, 0x03 },
{ 0x00, 0x01, 0x04, 0x05 },
{ 0x00, 0x02, 0x04, 0x06 },
{ 0x00, 0x01, 0x08, 0x09 },
{ 0x00, 0x02, 0x08, 0x0a },
{ 0x00, 0x04, 0x08, 0x0c },
{ 0x00, 0x01, 0x10, 0x11 },
{ 0x00, 0x02, 0x10, 0x12 },
{ 0x00, 0x04, 0x10, 0x14 },
{ 0x00, 0x08, 0x10, 0x18 },
{ 0x00, 0x01, 0x20, 0x21 },
{ 0x00, 0x02, 0x20, 0x22 },
{ 0x00, 0x04, 0x20, 0x24 },
{ 0x00, 0x08, 0x20, 0x28 },
{ 0x00, 0x10, 0x20, 0x30 },
{ 0x00, 0x01, 0x40, 0x41 },
{ 0x00, 0x02, 0x40, 0x42 },
{ 0x00, 0x04, 0x40, 0x44 },
{ 0x00, 0x08, 0x40, 0x48 },
{ 0x00, 0x10, 0x40, 0x50 },
{ 0x00, 0x20, 0x40, 0x60 },
{ 0x00, 0x01, 0x80, 0x81 },
{ 0x00, 0x02, 0x80, 0x82 },
{ 0x00, 0x04, 0x80, 0x84 },
{ 0x00, 0x08, 0x80, 0x88 },
{ 0x00, 0x10, 0x80, 0x90 },
{ 0x00, 0x20, 0x80, 0xa0 },
{ 0x00, 0x40, 0x80, 0xc0 }};

static uint8_t bits2flags1[][2] = {
{ 0x00, 0x01 },
{ 0x00, 0x02 },
{ 0x00, 0x04 },
{ 0x00, 0x08 },
{ 0x00, 0x10 },
{ 0x00, 0x20 },
{ 0x00, 0x40 },
{ 0x00, 0x80 }};
