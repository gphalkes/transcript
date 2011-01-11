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
#include <pthread.h>

#include "charconv_internal.h"
#include "cct_convertor.h"
#include "utf.h"

typedef struct _charconv_cct_state_t save_state_t;

typedef struct {
	charconv_common_t common;
	convertor_t *convertor;
	variant_t *variant;
	multi_mapping_t **codepage_sorted_multi_mappings;
	multi_mapping_t **codepoint_sorted_multi_mappings;
	uint32_t nr_multi_mappings;
	save_state_t state;
} convertor_state_t;

static charconv_error_t to_unicode_skip(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit);
static void close_convertor(convertor_state_t *handle);

static pthread_mutex_t cct_list_mutex = PTHREAD_MUTEX_INITIALIZER;

#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbuflimit)) != 0) \
		return result; \
} while (0)

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

static void find_to_unicode_variant(const variant_t *variant, const uint8_t *bytes, size_t length,
		uint8_t *conv_flags, uint_fast32_t *codepoint)
{
	variant_mapping_t *mapping;
	uint32_t value = 0;
	uint_fast16_t low, high, mid;

	memcpy(&value, bytes, length);
	/* The length field as encoded in the from_unicode_flags field is the length - 1,
	   and we need to compare with that. So we decrease length here, so we don't have to
	   add 1 in the comparisons below. */
	length--;

	low = 0;
	high = variant->nr_simple_mappings;
	while (low < high) {
		mid = low + ((high - low) / 2);
		mapping = variant->simple_mappings + variant->simple_mappings[mid].sort_idx;
		if (mapping->codepage_bytes < value || (mapping->codepage_bytes == value &&
				(mapping->from_unicode_flags & FROM_UNICODE_LENGTH_MASK) < length))
			low = mid + 1;
		else
			high = mid;
	}
	/* Check whether we actually found a mapping. */
	if (low == variant->nr_simple_mappings)
		return;
	mapping = variant->simple_mappings + variant->simple_mappings[low].sort_idx;
	if (mapping->codepage_bytes != value ||
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

static charconv_error_t to_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	uint_fast8_t state = handle->state.to;
	uint_fast32_t idx = handle->convertor->codepage_states[handle->state.to].base;
	uint_fast32_t codepoint;
	entry_t *entry;
	uint_fast8_t conv_flags;

	while (_inbuf < (const uint8_t *) inbuflimit) {
		entry = &handle->convertor->codepage_states[state].entries[handle->convertor->codepage_states[state].map[*_inbuf]];

		idx += entry->base + (uint_fast32_t)(*_inbuf - entry->low) * entry->mul;
		_inbuf++;

		if (entry->action == ACTION_FINAL_NOFLAGS) {
			PUT_UNICODE(handle->convertor->codepage_mappings[idx]);
		} else if (entry->action == ACTION_VALID) {
			state = entry->next_state;
			continue;
		} else if (entry->action == ACTION_FINAL_PAIR_NOFLAGS) {
			codepoint = handle->convertor->codepage_mappings[idx];
			if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
				codepoint -= UINT32_C(0xd800);
				codepoint <<= 10;
				codepoint += handle->convertor->codepage_mappings[idx + 1] - UINT32_C(0xdc00);
				codepoint += 0x10000;
			}
			PUT_UNICODE(codepoint);
		} else if (entry->action == ACTION_FINAL) {
			conv_flags = handle->convertor->codepage_flags.get_flags(&handle->convertor->codepage_flags, idx);
			if ((conv_flags & TO_UNICODE_MULTI_START) &&
					(flags & (CHARCONV_NO_MN_CONVERSION | CHARCONV_NO_1N_CONVERSION)) < CHARCONV_NO_1N_CONVERSION)
			{
				size_t check_len;
				uint_fast32_t i, j;
				char *outbuf_tmp;
				int result;

				/* Note: we sorted the multi_mappings table according to bytes_length, so we will first
				   check the longer mappings. This way we always find the longest match. */

				for (i = 0; i < handle->nr_multi_mappings; i++) {
					check_len = min(handle->codepage_sorted_multi_mappings[i]->bytes_length, inbuflimit - *inbuf);

					if (memcmp(handle->codepage_sorted_multi_mappings[i]->bytes, *inbuf, check_len) != 0)
						continue;

					if (check_len != handle->codepage_sorted_multi_mappings[i]->bytes_length) {
						if (flags & (CHARCONV_END_OF_TEXT | CHARCONV_NO_MN_CONVERSION))
							continue;
						return CHARCONV_INCOMPLETE;
					}

					outbuf_tmp = *outbuf;
					for (j = 0; j < handle->codepage_sorted_multi_mappings[i]->codepoints_length; j++) {
						codepoint = handle->codepage_sorted_multi_mappings[i]->codepoints[j];
						if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
							j++;
							codepoint -= UINT32_C(0xd800);
							codepoint <<= 10;
							codepoint += handle->codepage_sorted_multi_mappings[i]->codepoints[j] - UINT32_C(0xdc00);
							codepoint += 0x10000;
						}
						if ((result = handle->common.put_unicode(codepoint, &outbuf_tmp, outbuflimit)) != 0)
							return result;
					}
					*outbuf = outbuf_tmp;

					_inbuf = (const uint8_t *) ((*inbuf) + check_len);
					handle->state.to = state = entry->next_state;
					/* We need to go to the correct state, so we use the skip function to move *inbuf. */
					while ((const uint8_t *) *inbuf < _inbuf)
						if (to_unicode_skip(handle, inbuf, inbuflimit) != 0)
							return CHARCONV_INTERNAL_ERROR;
					idx = handle->convertor->codepage_states[handle->state.to].base;
					if (flags & CHARCONV_SINGLE_CONVERSION)
						return CHARCONV_SUCCESS;
					break; /* Break from multi-mapping search. */
				}
				if (i != handle->nr_multi_mappings)
					continue;
			}

			codepoint = handle->convertor->codepage_mappings[idx];
			if (conv_flags & TO_UNICODE_VARIANT) {
				find_to_unicode_variant(handle->variant, (const uint8_t *) *inbuf, (const char *) _inbuf - *inbuf,
					&conv_flags, &codepoint);
			}

			if ((conv_flags & TO_UNICODE_PRIVATE_USE) && !(flags & CHARCONV_ALLOW_PRIVATE_USE)) {
				if (!(flags & CHARCONV_SUBST_UNASSIGNED))
					return CHARCONV_PRIVATE_USE;
				PUT_UNICODE(UINT32_C(0xfffd));
			} else if ((conv_flags & TO_UNICODE_FALLBACK) && !(flags & CHARCONV_ALLOW_FALLBACK)) {
				return CHARCONV_FALLBACK;
			} else if (codepoint == UINT32_C(0xffff)) {
				if (!(flags & CHARCONV_SUBST_UNASSIGNED))
					return CHARCONV_UNASSIGNED;
				PUT_UNICODE(UINT32_C(0xfffd));
			} else {
				if ((codepoint & UINT32_C(0xfc00)) == UINT32_C(0xd800)) {
					codepoint -= UINT32_C(0xd800);
					codepoint <<= 10;
					codepoint += handle->convertor->codepage_mappings[idx + 1] - UINT32_C(0xdc00);
					codepoint += 0x10000;
				}
				PUT_UNICODE(codepoint);
			}
		} else if (entry->action == ACTION_ILLEGAL) {
			if (!(flags & CHARCONV_SUBST_ILLEGAL))
				return CHARCONV_ILLEGAL;
			PUT_UNICODE(UINT32_C(0xfffd));
		} else if (entry->action == ACTION_UNASSIGNED) {
			if (!(flags & CHARCONV_SUBST_UNASSIGNED))
				return CHARCONV_UNASSIGNED;
			PUT_UNICODE(UINT32_C(0xfffd));
		} else if (entry->action != ACTION_SHIFT) {
			return CHARCONV_INTERNAL_ERROR;
		}
		*inbuf = (const char *) _inbuf;
		handle->state.to = state = entry->next_state;
		idx = handle->convertor->codepage_states[handle->state.to].base;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}

	if (*inbuf != inbuflimit) {
		if (flags & CHARCONV_END_OF_TEXT) {
			if (!(flags & CHARCONV_SUBST_ILLEGAL))
				return CHARCONV_ILLEGAL_END;
			PUT_UNICODE(UINT32_C(0xFFFD));
			*inbuf = inbuflimit;
		} else {
			return CHARCONV_INCOMPLETE;
		}
	}
	return CHARCONV_SUCCESS;
}

static charconv_error_t to_unicode_skip(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit) {
	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	uint_fast8_t state = handle->state.to;
	uint_fast32_t idx = handle->convertor->codepage_states[handle->state.to].base;
	entry_t *entry;

	while (_inbuf < (const uint8_t *) inbuflimit) {
		entry = &handle->convertor->codepage_states[state].entries[handle->convertor->codepage_states[state].map[*_inbuf]];

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
				return CHARCONV_SUCCESS;
			default:
				return CHARCONV_INTERNAL_ERROR;
		}
	}

	return CHARCONV_INCOMPLETE;
}

static void to_unicode_reset(convertor_state_t *handle) {
	handle->state.to = 0;
}


#define GET_UNICODE() do { \
	codepoint = handle->common.get_unicode((const char **) &_inbuf, inbuflimit, false); \
} while (0)

#define PUT_BYTES(count, buffer) do { \
	if (put_bytes(handle, outbuf, outbuflimit, count, buffer) == CHARCONV_NO_SPACE) \
		return CHARCONV_NO_SPACE; \
} while (0)

static inline charconv_error_t put_bytes(convertor_state_t *handle, char **outbuf, const char const *outbuflimit, size_t count, const uint8_t *bytes) {
	uint_fast8_t required_state;
	uint_fast8_t i;

	if (handle->convertor->flags & MULTIBYTE_START_STATE_1) {
		required_state = count > 1 ? 1 : 0;
		if (handle->state.from != required_state) {
			for (i = 0; i < handle->convertor->nr_shift_states; i++) {
				if (handle->convertor->shift_states[i].from_state == handle->state.from &&
						handle->convertor->shift_states[i].to_state == required_state)
				{
					if ((*outbuf) + count + handle->convertor->shift_states[i].len > outbuflimit)
						return CHARCONV_NO_SPACE;
					memcpy(*outbuf, handle->convertor->shift_states[i].bytes, handle->convertor->shift_states[i].len);
					*outbuf += handle->convertor->shift_states[i].len;
					handle->state.from = required_state;
					goto write_bytes;
				}
			}
		}
	}
	if ((*outbuf) + count > outbuflimit)
		return CHARCONV_NO_SPACE;
write_bytes:
	/* Use 8 here, just so we don't create a bug when we decide to up mb_cur_max. */
	/* Using the switch here is faster than memcpy, which has to be completely general. */
	switch (count) {
		case 8: *(*outbuf)++ = *bytes++;
		case 7: *(*outbuf)++ = *bytes++;
		case 6: *(*outbuf)++ = *bytes++;
		case 5: *(*outbuf)++ = *bytes++;
		case 4: *(*outbuf)++ = *bytes++;
		case 3: *(*outbuf)++ = *bytes++;
		case 2: *(*outbuf)++ = *bytes++;
		case 1: *(*outbuf)++ = *bytes++;
	}
	return CHARCONV_SUCCESS;
}

static charconv_error_t from_unicode_check_multi_mappings(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	uint_fast32_t codepoint;
	uint_fast32_t i;

	/* Buffer is over-dimensioned by 1 to prevent need for checking the end of buffer. */
	#define CODEPOINT_BUFLEN 20
	uint16_t codepoints[CODEPOINT_BUFLEN];
	char *ptr = (char *) codepoints;

	const uint8_t *_inbuf = (const uint8_t *) *inbuf;
	size_t check_len;
	size_t mapping_check_len;
	bool can_read_more = flags & CHARCONV_NO_MN_CONVERSION ? false : true;

	/* Note: we specifically use the codepoint_sorted_multi_mappings to ensure that we always use
	   the longest possible match. */

	GET_UNICODE();
	if (_charconv_put_utf16_no_check(codepoint, &ptr) != 0)
		return CHARCONV_INTERNAL_ERROR;

	for (i = 0; i < handle->nr_multi_mappings; i++) {
		/* Skip if the first codepoint is smaller. */
		if (codepoints[0] < handle->codepage_sorted_multi_mappings[i]->codepoints[0])
			continue;
		/* Skip other tests if the first codepoint is larger (sorted input). */
		else if (codepoints[0] > handle->codepage_sorted_multi_mappings[i]->codepoints[0])
			break;

		mapping_check_len = handle->codepoint_sorted_multi_mappings[i]->codepoints_length * 2;
		check_len = min(ptr - (char *) codepoints, mapping_check_len);

		while (can_read_more && check_len < mapping_check_len) {
			GET_UNICODE();

			if (codepoint == CHARCONV_UTF_INCOMPLETE) {
				if (flags & CHARCONV_END_OF_TEXT) {
					can_read_more = false;
					goto check_next_mapping;
				}
				return CHARCONV_INCOMPLETE;
			}

			if (codepoint == CHARCONV_UTF_ILLEGAL) {
				can_read_more = false;
				goto check_next_mapping;
			}

			switch (_charconv_put_utf16_no_check(codepoint, &ptr)) {
				case CHARCONV_INCOMPLETE:
					if (flags & CHARCONV_END_OF_TEXT) {
						can_read_more = false;
						goto check_next_mapping;
					}
					return CHARCONV_INCOMPLETE;
				case CHARCONV_SUCCESS:
					break;
				case CHARCONV_NO_SPACE:
					can_read_more = false;
					goto check_next_mapping;
				default:
					return CHARCONV_INTERNAL_ERROR;
			}
			check_len = ptr - (char *) codepoints;
		}

		if (check_len >= mapping_check_len && memcmp(codepoints, handle->codepoint_sorted_multi_mappings[i]->codepoints, mapping_check_len) == 0) {
			PUT_BYTES(handle->codepoint_sorted_multi_mappings[i]->bytes_length,
				handle->codepoint_sorted_multi_mappings[i]->bytes);

			if ((size_t) (ptr - (char *) codepoints) != mapping_check_len) {
				/* Re-read codepoints up to the number in the mapping. */
				_inbuf = (const uint8_t *) *inbuf;
				for (check_len = 0; mapping_check_len > check_len; check_len += codepoint > 0xffff ? 4 : 2)
					GET_UNICODE();
			}
			*inbuf = (const char *) _inbuf;
			return CHARCONV_SUCCESS;
		}
check_next_mapping: ;
	}
	return -1;
}


static void find_from_unicode_variant(const variant_t *variant, uint32_t codepoint,
		uint8_t *conv_flags, uint8_t **bytes)
{
	variant_mapping_t *mapping;
	uint_fast16_t low, high, mid;

	low = 0;
	high = variant->nr_simple_mappings;
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
	if (low == variant->nr_simple_mappings || mapping->codepoint != codepoint || (mapping->to_unicode_flags & TO_UNICODE_FALLBACK))
		return;
	/* Note that the items are sorted such that the first in the list has
	   precision 0, the second has precision 1 and the last has precision 3
	   (in as far as they exist of course). We already checked that we don't
	   have a precision 3 mapping, so this mapping is the one we want. */
	*conv_flags = mapping->from_unicode_flags;
	*bytes = (uint8_t *) &mapping->codepage_bytes;
}

static charconv_error_t from_unicode_conversion(convertor_state_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	const uint8_t *_inbuf;
	uint_fast8_t state, state_16_bit;
	uint_fast32_t idx;
	uint_fast32_t codepoint;
	entry_t *entry;
	uint_fast8_t byte;
	uint_fast8_t conv_flags;
	uint8_t *bytes;

	_inbuf = (const uint8_t *) *inbuf;


	entry = &handle->convertor->unicode_states[0].entries[handle->convertor->unicode_states[0].map[0]];
	state_16_bit = entry->next_state;

	while (*inbuf < inbuflimit) {
		GET_UNICODE();
		if (codepoint == CHARCONV_UTF_INCOMPLETE)
			break;

		if (codepoint == CHARCONV_UTF_ILLEGAL) {
			if (!(flags & CHARCONV_SUBST_ILLEGAL))
				return CHARCONV_ILLEGAL;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
			*inbuf = (const char *) _inbuf;
			continue;
		}

		/* Optimize common case by not doing an actual lookup when the first byte is 0. */
		if (codepoint > 0x10000L) {
			byte = (codepoint >> 16) & 0xff;
			entry = &handle->convertor->unicode_states[0].entries[handle->convertor->unicode_states[0].map[byte]];
			idx = entry->base + (byte - entry->low) * entry->mul;
			state = entry->next_state;
		} else {
			idx = 0;
			state = state_16_bit;
		}

		byte = (codepoint >> 8) & 0xff;
		entry = &handle->convertor->unicode_states[state].entries[handle->convertor->unicode_states[state].map[byte]];
		idx += entry->base + (byte - entry->low) * entry->mul;
		state = entry->next_state;

		byte = codepoint & 0xff;
		entry = &handle->convertor->unicode_states[state].entries[handle->convertor->unicode_states[state].map[byte]];
		idx += entry->base + (byte - entry->low) * entry->mul;


		if (entry->action == ACTION_FINAL) {
			conv_flags = handle->convertor->unicode_flags.get_flags(&handle->convertor->unicode_flags, idx);
			if ((conv_flags & FROM_UNICODE_MULTI_START) &&
					(flags & (CHARCONV_NO_MN_CONVERSION | CHARCONV_NO_1N_CONVERSION)) < CHARCONV_NO_1N_CONVERSION)
			{
				switch (from_unicode_check_multi_mappings(handle, inbuf, inbuflimit, outbuf, outbuflimit, flags)) {
					case CHARCONV_SUCCESS:
						_inbuf = (const uint8_t *) *inbuf;
						if (flags & CHARCONV_SINGLE_CONVERSION)
							return CHARCONV_SUCCESS;
						continue;
					case CHARCONV_INCOMPLETE:
						return CHARCONV_INCOMPLETE;
					case CHARCONV_INTERNAL_ERROR:
					default:
						return CHARCONV_INTERNAL_ERROR;
					case CHARCONV_NO_SPACE:
						return CHARCONV_NO_SPACE;
					case -1:
						break;
				}
			}

			bytes = &handle->convertor->unicode_mappings[idx * handle->convertor->single_size];
			if (conv_flags & FROM_UNICODE_VARIANT)
				find_from_unicode_variant(handle->variant, codepoint, &conv_flags, &bytes);

			if ((conv_flags & FROM_UNICODE_FALLBACK) && !(flags & CHARCONV_ALLOW_FALLBACK))
				return CHARCONV_FALLBACK;

			if (conv_flags & FROM_UNICODE_NOT_AVAIL) {
				if (!(flags & CHARCONV_SUBST_UNASSIGNED))
					return CHARCONV_UNASSIGNED;
				if (conv_flags & FROM_UNICODE_SUBCHAR1)
					PUT_BYTES(1, &handle->convertor->subchar1);
				else
					PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
			} else {
				PUT_BYTES((conv_flags & FROM_UNICODE_LENGTH_MASK) + 1, bytes);
			}
		} else if (entry->action == ACTION_ILLEGAL) {
			if (!(flags & CHARCONV_SUBST_ILLEGAL))
				return CHARCONV_ILLEGAL;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
		} else if (entry->action == ACTION_UNASSIGNED) {
			if (!(flags & CHARCONV_SUBST_UNASSIGNED))
				return CHARCONV_UNASSIGNED;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
		} else {
			return CHARCONV_INTERNAL_ERROR;
		}
		*inbuf = (const char *) _inbuf;
		if (flags & CHARCONV_SINGLE_CONVERSION)
			return CHARCONV_SUCCESS;
	}

	if (*inbuf < inbuflimit) {
		if (flags & CHARCONV_END_OF_TEXT) {
			if (!(flags & CHARCONV_SUBST_ILLEGAL))
				return CHARCONV_ILLEGAL_END;
			PUT_BYTES(handle->convertor->subchar_len, handle->convertor->subchar);
			*inbuf = inbuflimit;
		} else {
			return CHARCONV_INCOMPLETE;
		}
	}
	return CHARCONV_SUCCESS;
}

static charconv_error_t from_unicode_flush(convertor_state_t *handle, char **outbuf, const char const *outbuflimit) {
	if (handle->state.from != 0)
		PUT_BYTES(0, NULL);
	return CHARCONV_SUCCESS;
}


static void from_unicode_reset(convertor_state_t *handle) {
	handle->state.from = 0;
}

static void save_cct_state(convertor_state_t *handle, save_state_t *save) {
	memcpy(save, &handle->state, sizeof(save_state_t));
}

static void load_cct_state(convertor_state_t *handle, save_state_t *save) {
	memcpy(&handle->state, save, sizeof(save_state_t));
}

void *_charconv_open_cct_convertor_internal(const char *name, int flags, charconv_error_t *error, bool internal_use) {
	convertor_state_t *retval;
	variant_t *variant;
	convertor_t *ptr;

	pthread_mutex_lock(&cct_list_mutex);

	if ((ptr = _charconv_load_cct_convertor(name, error, &variant)) == NULL) {
		pthread_mutex_unlock(&cct_list_mutex);
		return NULL;
	}

	if (!internal_use && ((variant == NULL ? ptr->flags : variant->flags) & (INTERNAL_TABLE | VARIANTS_AVAILABLE))) {
		_charconv_unload_cct_convertor(ptr);
		if (error != NULL)
			*error = CHARCONV_INTERNAL_TABLE;
		pthread_mutex_unlock(&cct_list_mutex);
		return NULL;
	}

	if ((retval = malloc(sizeof(convertor_state_t))) == NULL) {
		_charconv_unload_cct_convertor(ptr);
		if (error != NULL)
			*error = CHARCONV_OUT_OF_MEMORY;
		pthread_mutex_unlock(&cct_list_mutex);
		return NULL;
	}
	pthread_mutex_unlock(&cct_list_mutex);

	retval->convertor = ptr;
	retval->state.from = 0;
	retval->state.to = 0;

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = (flush_func_t) from_unicode_flush;
	retval->common.reset_from = (reset_func_t) from_unicode_reset;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = (reset_func_t) to_unicode_reset;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_convertor;
	retval->common.save = (save_func_t) save_cct_state;
	retval->common.load = (load_func_t) load_cct_state;
	retval->variant = NULL;
	retval->codepage_sorted_multi_mappings = ptr->codepage_sorted_multi_mappings;
	retval->codepoint_sorted_multi_mappings = ptr->codepoint_sorted_multi_mappings;
	retval->nr_multi_mappings = ptr->nr_multi_mappings;
	if (variant != NULL) {
		retval->variant = variant;
		if (variant->nr_multi_mappings != 0) {
			retval->codepage_sorted_multi_mappings = variant->codepage_sorted_multi_mappings;
			retval->codepoint_sorted_multi_mappings = variant->codepoint_sorted_multi_mappings;
			retval->nr_multi_mappings += variant->nr_multi_mappings;
		}
	}
	return retval;
}

void *_charconv_open_cct_convertor(const char *name, int flags, charconv_error_t *error) {
	return _charconv_open_cct_convertor_internal(name, flags, error, false);
}


static void close_convertor(convertor_state_t *handle) {
	pthread_mutex_lock(&cct_list_mutex);
	if (handle->convertor->refcount == 1)
		_charconv_unload_cct_convertor(handle->convertor);
	else
		handle->convertor->refcount--;
	pthread_mutex_unlock(&cct_list_mutex);
	free(handle);
}
