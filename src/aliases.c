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

/** @file */

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

/* Make sure that for us the struct members are not constant, so we can modify
   them. */
#define _TRANSCRIPT_CONST
#include "transcript_internal.h"

#define LOOP_LIST(type, iter, head) { type *iter; for (iter = head; iter != NULL; iter = iter->next) {
#define END_LOOP_LIST }}

/** @addtogroup transcript */
/** @{ */

static transcript_name_desc_t *converters, /**< The SL-list of known converters. */
	*converters_tail; /**< Tail of the known converters SL-list. */
static transcript_name_t *display_names; /**< The array of names that may be used for display purposes. */
static int display_names_allocated, /**< The number of elements allocated in the ::display_names array. */
	display_names_used; /**< The number of elements in the ::display_names array that is currently in use. */

/** Add a name to the ::display_names array, resizing the array if necessary. */
static void add_display_name(const char *name, int available) {
	if (display_names_allocated == 0) {
		if ((display_names = malloc(64 * sizeof(transcript_name_t))) == NULL)
			return;
		display_names_allocated = 64;
	} else if (display_names_used >= display_names_allocated) {
		transcript_name_t *tmp;

		if ((tmp = realloc(display_names, display_names_allocated * 2 * sizeof(transcript_name_t))) == NULL)
			return;
		display_names = tmp;
		display_names_allocated *= 2;
	}

	if ((display_names[display_names_used].name = _transcript_strdup(name)) == NULL)
		return;
	display_names[display_names_used].available = available;
	display_names_used++;
}

/** Process the next non-alias name found in the aliases.txt file. */
static bool add_converter_name(const char *name) {
	transcript_name_desc_t *converter = NULL;
	char normalized_name[NORMALIZE_NAME_MAX];
	bool is_display_name = *name == '*';

	if (is_display_name)
		name++;

	_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	if (normalized_name[0] == 0) {
		_transcript_log("error: converter name '%s' is invalid\n", name);
		goto return_error;
	}

	/* Check if the name is already in use as a converter or an alias. */
	LOOP_LIST(transcript_name_desc_t, ptr, converters)
		if (strcmp(normalized_name, ptr->name) == 0) {
			_transcript_log("error: converter name '%s' is already known\n", name);
			goto return_error;
		}
		LOOP_LIST(transcript_alias_name_t, alias, ptr->aliases)
			if (strcmp(normalized_name, alias->name) == 0)
				_transcript_log("warning: converter name '%s' is shadowed by an alias for '%s'\n", name, ptr->real_name);
		END_LOOP_LIST
	END_LOOP_LIST

	if ((converter = malloc(sizeof(transcript_name_desc_t))) == NULL ||
			(converter->real_name = _transcript_strdup(name)) == NULL ||
			(converter->name = _transcript_strdup(normalized_name)) == NULL)
	{
		_transcript_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	converter->aliases = NULL;
	converter->next = NULL;

	if ((converter->name = _transcript_strdup(normalized_name)) == NULL) {
		_transcript_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	converter->flags = 0;

	if (is_display_name) {
		add_display_name(name, 0);
		converter->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}

	/* Link into list. */
	if (converters_tail != NULL)
		converters_tail->next = converter;
	else
		converters = converter;
	converters_tail = converter;
	return true;

return_error:
	if (converter) {
		free(converter->real_name);
		free(converter->name);
		free(converter);
	}
	return false;
}

/** Handle any touch-ups of the last converter data structure. */
static void converter_done(void) {
	/* Check that the previous converter has at least one display name. If not
	   make the converter name itself a display name. */
	if (converters_tail != NULL && !(converters_tail->flags & NAME_DESC_FLAG_HAS_DISPNAME)) {
		add_display_name(converters_tail->real_name, 0);
		converters_tail->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}
}

/** Process an alias found in the aliases.txt file. */
static bool add_converter_alias(const char *name) {
	transcript_alias_name_t *alias = NULL;
	char normalized_name[NORMALIZE_NAME_MAX];
	bool is_display_name = *name == '*';

	if (is_display_name)
		name++;

	_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);

	if (*normalized_name == 0) {
		_transcript_log("error: alias name '%s' is invalid\n", name);
		goto return_error;
	}

	/* Check if the name is already in use as a converter or an alias. */
	LOOP_LIST(transcript_name_desc_t, ptr, converters)
		if (strcmp(normalized_name, ptr->name) == 0)
			_transcript_log("error: alias name '%s' is shadowd by a converter\n", name);

		LOOP_LIST(transcript_alias_name_t, alias, ptr->aliases)
			if (strcmp(normalized_name, alias->name) == 0)
				_transcript_log("warning: alias name '%s' is shadowed by an alias for '%s'\n", name, ptr->real_name);
		END_LOOP_LIST
	END_LOOP_LIST

	if ((alias = malloc(sizeof(transcript_name_desc_t))) == NULL) {
		_transcript_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	if ((alias->name = _transcript_strdup(normalized_name)) == NULL) {
		_transcript_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	if (is_display_name) {
		add_display_name(name, 0);
		converters_tail->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}

	alias->next = converters_tail->aliases;
	converters_tail->aliases = alias;
	return true;

return_error:
	if (alias != NULL) {
		free(alias->name);
		free(alias);
	}
	return false;
}

/** @internal
    @brief Get the descriptor for a converter by name. */
transcript_name_desc_t *_transcript_get_name_desc(const char *name, int need_normalization) {
	char normalized_name[NORMALIZE_NAME_MAX];

	if (need_normalization) {
		_transcript_normalize_name(name, normalized_name, NORMALIZE_NAME_MAX);
		name = normalized_name;
	}

	LOOP_LIST(transcript_name_desc_t, ptr, converters)
		if (strcmp(name, ptr->name) == 0)
			return ptr;

		LOOP_LIST(transcript_alias_name_t, alias, ptr->aliases)
			if (strcmp(name, alias->name) == 0)
				return ptr;
		END_LOOP_LIST
	END_LOOP_LIST
	return NULL;
}

/** @internal
    @brief Initialize the list of available converter names.

    This function tries to find all converters which are available. Unlike
    ::_transcript_init_aliases_from_file, it actually checks the file system to
    see which tables are available. Furthermore, it checks which converters from
    the list built by ::init_availability is available.
*/
static void init_availability(void) {
	static bool availability_initialized = false;

	DIR *dir;
	struct dirent *entry;
	size_t i;

	if (availability_initialized)
		return;

	/* The initial check is to ensure that in the most common case, we skip the
	   locking of the mutex. This is possible because we only set the value to
	   true, never to false. Now we do the properly mutex protected check. */
	ACQUIRE_LOCK();
	if (availability_initialized) {
		RELEASE_LOCK();
		return;
	}

	/* Probe all the converters listed as aliases from the file. */
	for (i = 0; i < (size_t) display_names_used; i++)
		display_names[i].available = transcript_probe_converter_nolock(display_names[i].name);

	/* FIXME: perhaps we should add the default links for the full-type converters here. */

	/* Add all the file names we can find in the DB dir, if they are not already present. */
	if ((dir = opendir(DB_DIRECTORY)) != NULL) {
		while ((entry = readdir(dir)) != NULL) {
			size_t entry_name_len = strlen(entry->d_name);
			if (entry_name_len < 5)
				continue;
			if (entry->d_name[0] == '_')
				continue;
			if (strcmp(entry->d_name + entry_name_len - 4, ".ltc") != 0)
				continue;
			entry->d_name[entry_name_len - 4] = 0;
			if (_transcript_get_name_desc(entry->d_name, 1) == NULL)
				add_display_name(entry->d_name, transcript_probe_converter_nolock(entry->d_name));
		}
		closedir(dir);
	}

	availability_initialized = true;
	RELEASE_LOCK();
}

/** Retrieve the list of display names known to this instantiation of the library.
    @param count A location to store the number of names returned.
    @return An array of ::transcript_name_t structures listing the known converters.
*/
const transcript_name_t *transcript_get_names(int *count) {
	_transcript_init();
	init_availability();
	if (count != NULL)
		*count = display_names_used;
	return display_names;
}

/** @internal
    @brief The maximum size of a name in the aliases file.

    Names longer than this are truncated.
*/
#define MAX_ID (2 * NORMALIZE_NAME_MAX)

/** @internal
    @brief Read the list of converters and their aliases from the aliases.txt file.
*/
static void *read_alias_file(const char *name) {
	FILE *aliases;
	int converter_found = 0;
	size_t idx = 0;
	char id[MAX_ID + 1];
	int c, line_number = 1;
	bool comma_seen = false;

	enum {
		LINE_START,
		LINE_CONTINUED,
		ID_FIRST,
		ID_ALIAS,
		AFTER_ID,
		COMMENT,
		SKIP_REST
	} state = LINE_START;


	if ((aliases = fopen(name, "r")) == NULL) {
		_transcript_log("Error opening '%s': %s\n", name, strerror(errno));
		return NULL;
	}
	_transcript_log("Processing alias file %s\n", name);

	while ((c = fgetc(aliases)) != EOF) {
		if (c == '\n')
			line_number++;

		switch (state) {
			case LINE_START:
			case LINE_CONTINUED:
				if (_transcript_isspace(c)) {
					state = LINE_CONTINUED;
					break;
				}

				if (c == '#') {
					state = COMMENT;
					break;
				}

				if (!_transcript_isidchr(c) && c != '*') {
					_transcript_log("aliases.txt:%d: invalid character\n", line_number);
					state = SKIP_REST;
					break;
				}

				if (state == LINE_START) {
					state = ID_FIRST;
				} else {
					if (converter_found)
						state = ID_ALIAS;
					else
						state = SKIP_REST;
				}

				id[0] = c;
				idx = 1;
				break;
			case ID_FIRST:
				/* FALLTHROUGH */
			case ID_ALIAS:
				if (_transcript_isidchr(c)) {
					if (idx < MAX_ID)
						id[idx++] = c;
					break;
				}

				if (_transcript_isspace(c) || c == '#') {
					id[idx] = 0;
					if (state == ID_FIRST) {
						/* Finish handling the previous converter. */
						converter_done();
						/* Start with the new converter. */
						converter_found = add_converter_name(id);
					} else {
						if (strcmp(id, ":disable") == 0)
							converters_tail->flags |= NAME_DESC_FLAG_DISABLED;
						else if (strcmp(id, ":probe_load") == 0)
							converters_tail->flags |= NAME_DESC_FLAG_PROBE_LOAD;
						else
							add_converter_alias(id);
					}
					state = c == '#' ? COMMENT : AFTER_ID;
				} else {
					_transcript_log("aliases.txt:%d: invalid character\n", line_number);
					state = SKIP_REST;
				}
				comma_seen = false;
				break;
			case AFTER_ID:
				if (_transcript_isspace(c))
					break;
				if (_transcript_isidchr(c) || c == '*') {
					id[0] = c;
					idx = 1;
					state = ID_ALIAS;
					break;
				}
				if (c == '#') {
					state = COMMENT;
					break;
				}
				_transcript_log("aliases.txt:%d: invalid character\n", line_number);
				state = SKIP_REST;
				break;
			case SKIP_REST:
			case COMMENT:
				break;
			default:
				_transcript_log("Program logic error while reading aliases.txt\n");
				fclose(aliases);
				return NULL;
		}
		if (c == '\n')
			state = LINE_START;
	}
	/* Finish handling the last converter. */
	converter_done();
	fclose(aliases);
	return NULL;
}

/** @internal
    @brief Read the list of converters and their aliases from the aliases.txt file.
*/
void _transcript_init_aliases_from_file(void) {
	_transcript_db_open("aliases", "txt", read_alias_file, NULL);
}
