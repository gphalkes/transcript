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
#include <errno.h>
#include <string.h>
#include <ltdl.h>

#include "transcript_internal.h"
#include "utf.h"

#define ERROR(value) do { if (error != NULL) *error = value; goto end_error; } while (0)

/** Load a suffixed symbol from a plugin. */
static void *get_sym(lt_dlhandle handle, const char *sym, const char *convertor_name) {
	char buffer[NORMALIZE_NAME_MAX + 32];
	strcpy(buffer, sym);
	strcat(buffer, convertor_name);
	return lt_dlsym(handle, buffer);
}

/** Try to open (i.e. get a file handle) a convertor.

    If the option probe=load has been set in the convertor options, then instead
    of trying to open with fopen, it will actually be dlopened and the function
    transcript_probe_<name> will be called.
*/
static bool probe_convertor(const char *name, const char *normalized_name, bool probe_load) {
	char base_name[NORMALIZE_NAME_MAX];

	/* Strip any options. */
	transcript_get_option(name, base_name, NORMALIZE_NAME_MAX, NULL);

	if (probe_load) {
		bool (*probe)(const char *);
		lt_dlhandle handle;
		int result = 0;

		if ((handle = _transcript_db_open(base_name, "tct", (open_func_t) lt_dlopen, NULL)) == NULL)
			return 0;

		transcript_get_option(normalized_name, base_name, NORMALIZE_NAME_MAX, NULL);
		if ((probe = get_sym(handle, "transcript_probe_", base_name)) != NULL)
			result = probe(normalized_name);

		lt_dlclose(handle);
		return result;
	} else {
		FILE *handle = NULL;
		/* For most convertors it is sufficient to know that the file is readable. */
		if ((handle = _transcript_db_open(base_name, "tct", (open_func_t) fopen, NULL)) != NULL)
			fclose(handle);
		return handle != NULL;
	}
}

/** @internal
    @brief Perform the action described at ::transcript_probe_convertor.

    This function does not call ::_transcript_init, which ::transcript_probe_convertor
    does. However, ::_transcript_init only needs to be called once, so if we
    know it has already been called, we don't need to check again. Therefore,
    in the library itself we use this stripped down version.
*/
int transcript_probe_convertor_nolock(const char *name) {
	transcript_name_desc_t *convertor;
	char normalized_name[NORMALIZE_NAME_MAX];

	_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	if ((convertor = _transcript_get_name_desc(normalized_name, 0)) != NULL) {
		if (convertor->flags & NAME_DESC_FLAG_DISABLED)
			return false;
		return probe_convertor(convertor->real_name, convertor->name, !!(convertor->flags & NAME_DESC_FLAG_PROBE_LOAD));
	}
	return probe_convertor(name, normalized_name, false);
}

/** Fill the @c get_unicode and @c put_unicode members of a ::transcript_t struct. */
static transcript_t *fill_utf(transcript_t *handle, transcript_utf_t utf_type) {
	if (handle == NULL)
		return NULL;
	handle->get_unicode = _transcript_get_get_unicode(utf_type);
	handle->put_unicode = _transcript_get_put_unicode(utf_type);
	return handle;
}

/** Open a convertor plugin. */
static transcript_t *open_convertor(const char *normalized_name, const char *real_name, int flags, transcript_error_t *error) {
	lt_dlhandle handle = NULL;
	int (*get_iface)(void);
	transcript_t *result = NULL;
	char base_name[NORMALIZE_NAME_MAX];

	transcript_get_option(real_name, base_name, NORMALIZE_NAME_MAX, NULL);

	if ((handle = _transcript_db_open(base_name, "tct", (open_func_t) lt_dlopen, error)) == NULL) {
		FILE *test_handle;
		transcript_error_t local_error;
		if ((test_handle = _transcript_db_open(base_name, "tct", (open_func_t) fopen, &local_error)) == NULL)
			ERROR(local_error);
		fclose(test_handle);
		ERROR(TRANSCRIPT_DLOPEN_FAILURE);
	}

	transcript_get_option(normalized_name, base_name, NORMALIZE_NAME_MAX, NULL);

	if ((get_iface = get_sym(handle, "transcript_get_iface_", base_name)) == NULL)
		ERROR(TRANSCRIPT_INVALID_FORMAT);

	switch (get_iface()) {
		case TRANSCRIPT_STATE_TABLE_V1: {
			const convertor_tables_v1_t *(*get_table)(void);
			if ((get_table = get_sym(handle, "transcript_get_table_", base_name)) == NULL)
				ERROR(TRANSCRIPT_INVALID_FORMAT);
			if ((result = _transcript_open_cct_convertor(get_table(), flags, error)) != NULL) {
				result->library_handle = handle;
				return result;
			}
			break;
		}
		case TRANSCRIPT_FULL_MODULE_V1: {
			transcript_t *(*open_convertor)(const char *, int flags, transcript_error_t *);
			if ((open_convertor = get_sym(handle, "transcript_open_", base_name)) == NULL)
				ERROR(TRANSCRIPT_INVALID_FORMAT);
			if ((result = open_convertor(normalized_name, flags, error)) != NULL) {
				result->library_handle = handle;
				return result;
			}
			break;
		}
		default:
			ERROR(TRANSCRIPT_INVALID_FORMAT);
	}

end_error:
	if (handle != NULL)
		lt_dlclose(handle);
	return result;
}

/** @internal
    @brief Open a convertor.

    This function is called by ::transcript_open_convertor, after locking the
    internal mutex. This function is provided such that convertors can open
    other convertors without causing a deadlock.
*/
transcript_t *transcript_open_convertor_nolock(const char *name, transcript_utf_t utf_type, int flags, transcript_error_t *error) {
	transcript_name_desc_t *convertor;
	char normalized_name[NORMALIZE_NAME_MAX];

	if (utf_type > TRANSCRIPT_UTF32LE || utf_type <= 0) {
		if (error != NULL)
			*error = TRANSCRIPT_BAD_ARG;
		return NULL;
	}

	_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	if ((convertor = _transcript_get_name_desc(normalized_name, 0)) != NULL) {
		if (convertor->flags & NAME_DESC_FLAG_DISABLED) {
			if (error != NULL)
				*error = TRANSCRIPT_CONVERTOR_DISABLED;
			return NULL;
		}
		return fill_utf(open_convertor(convertor->name, convertor->real_name, flags, error), utf_type);
	}
	return fill_utf(open_convertor(normalized_name, name, flags, error), utf_type);
}

/** Try to open a file from a database directory.
    @param name The base name of the file to open.
    @param ext The extension of the file to open.
    @param dir The directory to look in.
    @param error The location to store a possible error.
    @return A @c FILE pointer on success, or @c NULL on failure.
*/
static FILE *db_open(const char *name, const char *ext, const char *dir, open_func_t open_func, transcript_error_t *error) {
	char *file_name = NULL;
	void *result = NULL;
	size_t len;

	len = strlen(dir) + strlen(name) + 2 + strlen(ext) + 1;
	if ((file_name = malloc(len)) == NULL)
		ERROR(TRANSCRIPT_OUT_OF_MEMORY);

	strcpy(file_name, dir);
	strcat(file_name, "/"); /* Even on Windows, / is recognised as directory separator internally. */
	strcat(file_name, name);
	strcat(file_name, ".");
	strcat(file_name, ext);

	if ((result = open_func(file_name, "r")) == NULL)
		ERROR(TRANSCRIPT_ERRNO);

end_error:
	free(file_name);
	return result;
}

/** @internal
    @brief Open a file from the database directory.
    @param name The base name of the file to open.
    @param ext The extension of the file to open.
    @param error The location to store a possible error.
    @return A @c FILE pointer on success, or @c NULL on failure.

    This function first looks in the diretory named in the TRANSCRIPT_PATH
    environment variable (if set), and then in the compiled in database
    directory.
*/
void *_transcript_db_open(const char *name, const char *ext, open_func_t open_func, transcript_error_t *error) {
	const char **next_dir;
	FILE *result;

	for (next_dir = _transcript_search_path; *next_dir != NULL; next_dir++) {
		if ((result = db_open(name, ext, *next_dir, open_func, error)) != NULL)
			return result;
	}
	return NULL;
}
