/* Copyright (C) 2012 G.P. Halkes
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
#include <search.h>

#include <transcript/static_assert.h>
#include <transcript/moduledefs.h>

#define NR_OF_PLANES 16

static const char *plane_names_2004[NR_OF_PLANES] = {
	"ASCII",
	"CNS-11643-2004-1",
	"CNS-11643-2004-2",
	"CNS-11643-2004-3",
	"CNS-11643-2004-4",
	"CNS-11643-2004-5",
	"CNS-11643-2004-6",
	"CNS-11643-2004-7",

	/* Planes 8, 9 and A have no codepoints, and thus do not exist as tables.
	   We define them as NULL here, and skip them in the initialization below. */
	NULL,
	NULL,
	NULL,

	"CNS-11643-2004-B",
	"CNS-11643-2004-C",
	"CNS-11643-2004-D",
	"CNS-11643-2004-E",
	"CNS-11643-2004-F"
};

static const char *plane_names_1992[NR_OF_PLANES] = {
	"ASCII",
	"CNS-11643-1992-1",
	"CNS-11643-1992-2",
	"CNS-11643-1992-3",
	"CNS-11643-1992-4",
	"CNS-11643-1992-5",
	"CNS-11643-1992-6",
	"CNS-11643-1992-7",

	/* Planes 8 through 14 have no codepoints, and thus do not exist as tables.
	   We define them as NULL here, and skip them in the initialization below. */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,

	"CNS-11643-1992-F"
};

typedef struct {
	transcript_t common;
	transcript_t *planes[NR_OF_PLANES];
} converter_handle_t;

static void close_converter(converter_handle_t *handle);

/** Simplification macro for calling put_unicode which returns automatically on error. */
#define PUT_UNICODE(codepoint) do { int result; \
	if ((result = handle->common.put_unicode(codepoint, outbuf, outbuflimit)) != TRANSCRIPT_SUCCESS) \
		return result; \
} while (0)

/** convert_to implementation for EUC-TW converter. */
static int to_unicode_conversion(converter_handle_t *handle, const uint8_t **inbuf, const uint8_t const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	while (*inbuf < inbuflimit) {
		if (**inbuf < 0x80) {
			PUT_UNICODE(**inbuf);
			(*inbuf)++;
		} else if (**inbuf == 0x8e || (**inbuf >= 0xa1 && **inbuf <= 0xfe)) {
			uint8_t conversion_bytes[2];
			const uint8_t *conversion_bytes_ptr;
			int plane, lead_bytes, result;

			if (**inbuf == 0x8e) {
				if ((*inbuf) + 3 >= inbuflimit)
					goto incomplete_char;
				if ((*inbuf)[1] < 0xa1 || (*inbuf)[1] > 0xaf || (*inbuf)[2] < 0xa1 ||
						(*inbuf)[2] == 0xff || (*inbuf)[3] < 0xa1 || (*inbuf)[3] == 0xff)
				{
					if (flags & TRANSCRIPT_SUBST_ILLEGAL) {
						PUT_UNICODE(UINT32_C(0xfffd));
						(*inbuf)++;
						continue;
					} else {
						return TRANSCRIPT_ILLEGAL;
					}
				}
				plane = (*inbuf)[1] - 0xa0;
				lead_bytes = 2;
			} else {
				if ((*inbuf) + 1 == inbuflimit)
					goto incomplete_char;
				if ((*inbuf)[1] < 0xa1 || (*inbuf)[1] == 0xff)
					return TRANSCRIPT_ILLEGAL;
				plane = 1;
				lead_bytes = 0;
			}

			if (handle->planes[plane] == NULL) {
				if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
					return TRANSCRIPT_UNASSIGNED;
				PUT_UNICODE(UINT32_C(0xfffd));
			} else {
				conversion_bytes[0] = (*inbuf)[lead_bytes] & 0x7f;
				conversion_bytes[1] = (*inbuf)[lead_bytes + 1] & 0x7f;
				conversion_bytes_ptr = conversion_bytes;
				switch ((result = handle->planes[plane]->convert_to(handle->planes[plane], (const char **) &conversion_bytes_ptr,
						(const char *) conversion_bytes + 2, outbuf, outbuflimit, flags)))
				{
					case TRANSCRIPT_SUCCESS:
						break;
					case TRANSCRIPT_UNASSIGNED:
						if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
							return TRANSCRIPT_UNASSIGNED;
						PUT_UNICODE(UINT32_C(0xfffd));
						break;
					default:
						return result;
				}
				(*inbuf) += lead_bytes + 2;
			}
		} else {
			if (flags & TRANSCRIPT_SUBST_ILLEGAL) {
				PUT_UNICODE(UINT32_C(0xfffd));
				(*inbuf)++;
			} else {
				return TRANSCRIPT_ILLEGAL;
			}
		}
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

/** skip_to implementation for EUC-TW converter. */
static transcript_error_t to_unicode_skip(converter_handle_t *handle, const uint8_t **inbuf, const uint8_t const *inbuflimit) {
	(void) handle;

	if (*inbuf == inbuflimit)
		return TRANSCRIPT_INCOMPLETE;

	if (**inbuf < 0x80) {
		(*inbuf)++;
	} else if (**inbuf >= 0xa1 && **inbuf <= 0xfe) {
		if ((*inbuf) + 1 == inbuflimit)
			return TRANSCRIPT_INCOMPLETE;
		if ((*inbuf)[1] < 0x80)
			(*inbuf)++;
		else
			(*inbuf) += 2;
	} else if (**inbuf == 0x8e) {
		int i;

		if ((*inbuf) + 4 >= inbuflimit)
			return TRANSCRIPT_INCOMPLETE;
		for (i = 0; i < 4 && **inbuf > 0x7f; i++, (*inbuf)++) {}
	} else {
		(*inbuf)++;
	}
	return TRANSCRIPT_SUCCESS;
}

/** convert_from implementation for EUC-TW converter. */
static transcript_error_t from_unicode_conversion(converter_handle_t *handle, const char **inbuf, const char const *inbuflimit,
		char **outbuf, const char const *outbuflimit, int flags)
{
	transcript_error_t result;
	transcript_t *plane_handle;
	char *saved_outbuf;
	char *data_start;
	char *data_write;
	int internal_flags;
	int fallback_converter;
	int i;

	while (*inbuf < inbuflimit) {
		fallback_converter = -1;
		for (i = 0; i < NR_OF_PLANES; i++) {
			if (handle->planes[i] == NULL)
				continue;

			internal_flags = flags & ~(TRANSCRIPT_SUBST_ILLEGAL | TRANSCRIPT_SUBST_UNASSIGNED | TRANSCRIPT_ALLOW_FALLBACK);
			plane_handle = handle->planes[i];
			saved_outbuf = *outbuf;
			result = plane_handle->convert_from(plane_handle, inbuf, inbuflimit, outbuf,
				*outbuf + ((outbuflimit - *outbuf) >> (i > 1)), internal_flags);

			if (i > 1) {
				data_start = *outbuf;
				data_write = *outbuf + (data_start - saved_outbuf);
				*outbuf = data_write;
				while (data_start > saved_outbuf) {
					*--data_write = *--data_start | 0x80;
					*--data_write = *--data_start | 0x80;
					*--data_write = 0xa0 + i;
					*--data_write = 0x8e;
				}
			} else if (i == 1) {
				while (saved_outbuf < *outbuf)
					*saved_outbuf++ |= 0x80;
			}

			switch (result) {
				case TRANSCRIPT_ILLEGAL:
				case TRANSCRIPT_ILLEGAL_END:
					if (!(flags & TRANSCRIPT_SUBST_ILLEGAL))
						return result;
					handle->common.get_unicode(inbuf, inbuflimit, TRUE);
					if (*outbuf == outbuflimit)
						return TRANSCRIPT_NO_SPACE;
					*(*outbuf)++ = 0x1a;
					break;
				case TRANSCRIPT_UNASSIGNED:
					break;
				case TRANSCRIPT_FALLBACK:
					if ((flags & TRANSCRIPT_ALLOW_FALLBACK) && fallback_converter < 0)
						fallback_converter = i;
					break;
				default:
					return result;
			}
			if (saved_outbuf != *outbuf)
				break;
		}

		if (i == NR_OF_PLANES) {
			if (fallback_converter >= 0) {
				result = plane_handle->convert_from(plane_handle, inbuf, inbuflimit, outbuf,
					*outbuf + ((outbuflimit - *outbuf) >> (i > 1)), flags | TRANSCRIPT_SINGLE_CONVERSION);
				if (result != TRANSCRIPT_SUCCESS)
					return result;
			}

			if (!(flags & TRANSCRIPT_SUBST_UNASSIGNED))
				return TRANSCRIPT_UNASSIGNED;
			if (*outbuf == outbuflimit)
				return TRANSCRIPT_NO_SPACE;
			*(*outbuf)++ = 0x1a;
			handle->common.get_unicode(inbuf, inbuflimit, TRUE);
		}
	}
	return TRANSCRIPT_SUCCESS;
}

/** @internal
    @brief Open the EUC-TW converter.
*/
static void *open_euctw(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error) {
	converter_handle_t *retval;
	const char **plane_names;
	int i;

	if (strcmp(name, "euctw2004") == 0) {
		plane_names = plane_names_2004;
	} else if (strcmp(name, "euctw") == 0 || strcmp(name, "euctw1992") == 0) {
		plane_names = plane_names_1992;
	} else {
		if (error != NULL)
			*error = TRANSCRIPT_INTERNAL_ERROR;
		return NULL;
	}

	if ((retval = malloc(sizeof(converter_handle_t))) == NULL) {
		if (error != NULL)
			*error = TRANSCRIPT_OUT_OF_MEMORY;
		return NULL;
	}


	for (i = 0; i < NR_OF_PLANES; i++) {
		if (plane_names[i] == NULL) {
			retval->planes[i] = NULL;
			continue;
		}
		if ((retval->planes[i] = transcript_open_converter_nolock(plane_names[i], utf_type, TRANSCRIPT_INTERNAL, error)) == NULL) {
			for (i--; i >= 0; i--)
				transcript_close_converter_nolock(retval->planes[i]);
			free(retval);
			return NULL;
		}
	}

	retval->common.convert_from = (conversion_func_t) from_unicode_conversion;
	retval->common.flush_from = NULL;
	retval->common.reset_from = NULL;
	retval->common.convert_to = (conversion_func_t) to_unicode_conversion;
	retval->common.skip_to = (skip_func_t) to_unicode_skip;
	retval->common.reset_to = NULL;
	retval->common.flags = flags;
	retval->common.close = (close_func_t) close_converter;
	retval->common.save = NULL;
	retval->common.load = NULL;

	return retval;
}

static bool_t probe_euctw(const char *name) {
	const char **plane_names;
	int i;

	if (strcmp(name, "euctw2004") == 0)
		plane_names = plane_names_2004;
	else if (strcmp(name, "euctw") == 0 || strcmp(name, "euctw1992") == 0)
		plane_names = plane_names_1992;
	else
		return FALSE;

	for (i = 0; i < NR_OF_PLANES; i++) {
		if (plane_names[i] == NULL)
			continue;
		if (!transcript_probe_converter_nolock(plane_names[i]))
			return FALSE;
	}
	return TRUE;
}

/** close implementation for ISO-2022 converters. */
static void close_converter(converter_handle_t *handle) {
	int i;
	for (i = 0; i < NR_OF_PLANES; i++)
		transcript_close_converter(handle->planes[i]);
	free(handle);
}

TRANSCRIPT_EXPORT const char * const *transcript_namelist_euctw(void) {
	static const char * const namelist[] = {
		"euc-tw", "euc-tw-1992", "euc-tw-2004", NULL
	};
	return namelist;
}

#define DEFINE_INTERFACE(name) \
TRANSCRIPT_ALIAS_OPEN(open_euctw, name) \
TRANSCRIPT_ALIAS_PROBE(probe_euctw, name) \
TRANSCRIPT_EXPORT int transcript_get_iface_##name(void) { return TRANSCRIPT_FULL_MODULE_V1; }

DEFINE_INTERFACE(euctw)
DEFINE_INTERFACE(euctw1992)
DEFINE_INTERFACE(euctw2004)
