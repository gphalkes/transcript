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
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>

#define _CHARCONV_CONST
#include "charconv_internal.h"

#define LOOP_LIST(type, iter, head) { type *iter; for (iter = head; iter != NULL; iter = iter->next) {
#define END_LOOP_LIST }}

static charconv_name_desc_t *convertors, *convertors_tail;
static charconv_name_t *display_names;
static int display_names_allocated, display_names_used;

static void add_display_name(const char *name, int available) {
	if (display_names_allocated == 0) {
		if ((display_names = malloc(64 * sizeof(charconv_name_t))) == NULL)
			return;
		display_names_allocated = 64;
	} else if (display_names_used >= display_names_allocated) {
		charconv_name_t *tmp;

		if ((tmp = realloc(display_names, display_names_allocated * 2 * sizeof(charconv_name_t))) == NULL)
			return;
		display_names = tmp;
		display_names_allocated *= 2;
	}

	if ((display_names[display_names_used].name = _charconv_strdup(name)) == NULL)
		return;
	display_names[display_names_used].available = available;
	display_names_used++;
}

void _charconv_log(const char *fmt, ...) {
	if (getenv("CHARCONV_LOG") != NULL) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

bool _charconv_add_convertor_name(const char *name) {
	charconv_name_desc_t *convertor = NULL;
	char squashed_name[SQUASH_NAME_MAX];
	bool is_display_name = *name == '*';

	if (convertors_tail != NULL && !(convertors_tail->flags & NAME_DESC_FLAG_HAS_DISPNAME)) {
		add_display_name(convertors_tail->real_name, 0);
		convertors_tail->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}

	if (is_display_name)
		name++;

	charconv_squash_name(name, squashed_name, SQUASH_NAME_MAX);

	if (*squashed_name == 0) {
		_charconv_log("error: convertor name '%s' is invalid\n", name);
		goto return_error;
	}

	LOOP_LIST(charconv_name_desc_t, ptr, convertors)
		if (strcmp(squashed_name, ptr->name) == 0) {
			_charconv_log("error: convertor name '%s' is already known\n", name);
			goto return_error;
		}
		LOOP_LIST(charconv_alias_name_t, alias, ptr->aliases)
			if (strcmp(squashed_name, alias->name) == 0)
				_charconv_log("warning: convertor name '%s' is shadowed by an alias for '%s'\n", name, ptr->real_name);
		END_LOOP_LIST
	END_LOOP_LIST

	if ((convertor = malloc(sizeof(charconv_name_desc_t))) == NULL ||
			(convertor->real_name = _charconv_strdup(name)) == NULL ||
			(convertor->name = _charconv_strdup(squashed_name)) == NULL)
	{
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	convertor->aliases = NULL;
	convertor->next = NULL;

	if ((convertor->name = _charconv_strdup(squashed_name)) == NULL) {
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	convertor->flags = 0;

	if (is_display_name) {
		add_display_name(name, 0);
		convertor->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}

	/* Link into list. */
	if (convertors_tail != NULL)
		convertors_tail->next = convertor;
	else
		convertors = convertor;
	convertors_tail = convertor;
	return true;

return_error:
	if (convertor) {
		free(convertor->real_name);
		free(convertor->name);
		free(convertor);
	}
	return false;
}

bool _charconv_add_convertor_alias(const char *name) {
	charconv_alias_name_t *alias = NULL;
	char squashed_name[SQUASH_NAME_MAX];
	bool is_display_name = *name == '*';

	if (is_display_name)
		name++;

	charconv_squash_name(name, squashed_name, SQUASH_NAME_MAX);

	if (*squashed_name == 0) {
		_charconv_log("error: alias name '%s' is invalid\n", name);
		goto return_error;
	}

	LOOP_LIST(charconv_name_desc_t, ptr, convertors)
		if (strcmp(squashed_name, ptr->name) == 0)
			_charconv_log("error: alias name '%s' is shadowd by a convertor\n", name);

		LOOP_LIST(charconv_alias_name_t, alias, ptr->aliases)
			if (strcmp(squashed_name, alias->name) == 0)
				_charconv_log("warning: alias name '%s' is shadowed by an alias for '%s'\n", name, ptr->real_name);
		END_LOOP_LIST
	END_LOOP_LIST

	if ((alias = malloc(sizeof(charconv_name_desc_t))) == NULL) {
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	if ((alias->name = _charconv_strdup(squashed_name)) == NULL) {
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	if (is_display_name) {
		add_display_name(name, 0);
		convertors_tail->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}

	alias->next = convertors_tail->aliases;
	convertors_tail->aliases = alias;
	return true;

return_error:
	if (alias != NULL) {
		free(alias->name);
		free(alias);
	}
	return false;
}

charconv_name_desc_t *_charconv_get_name_desc(const char *name) {
	char squashed_name[SQUASH_NAME_MAX];
	charconv_squash_name(name, squashed_name, SQUASH_NAME_MAX);

	LOOP_LIST(charconv_name_desc_t, ptr, convertors)
		if (strcmp(squashed_name, ptr->name) == 0)
			return ptr;

		LOOP_LIST(charconv_alias_name_t, alias, ptr->aliases)
			if (strcmp(squashed_name, alias->name) == 0)
				return ptr;
		END_LOOP_LIST
	END_LOOP_LIST
	return NULL;
}

static const char *builtin_names[] = {
	"UTF-8",
	"UTF-16",
	"UTF-16LE",
	"UTF-16BE",
	"UTF-32",
	"UTF-32LE",
	"UTF-32BE",
	"UTF-8,BOM",
	"CESU-8",
	"GB-18030",
	"UTF-7",
	"SCSU",
	"ISO-8859-1",
	"ISO-2022-JP",
	"ISO-2022-JP1",
	"ISO-2022-JP2",
	"ISO-2022-JP3",
	"ISO-2022-JP-2004",
	"ISO-2022-KR",
	"ISO-2022-CN",
	"ISO-2022-CN-EXT"
};

static void _charconv_init_aliases(void) {
	static bool availability_initialized = false;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	DIR *dir;
	struct dirent *entry;
	size_t i;

	if (availability_initialized)
		return;

	pthread_mutex_lock(&lock);
	if (availability_initialized) {
		pthread_mutex_unlock(&lock);
		return;
	}

	/* FIXME: this is a hack. We should do this properly in _charconv_init_aliases_from_file.
	   That is annoying as well, because it requires exposing several internal variables.
	*/
	if (convertors_tail != NULL && !(convertors_tail->flags & NAME_DESC_FLAG_HAS_DISPNAME)) {
		add_display_name(convertors_tail->real_name, (convertors_tail->flags & NAME_DESC_FLAG_AVAILABLE) != 0);
		convertors_tail->flags |= NAME_DESC_FLAG_HAS_DISPNAME;
	}

	/* Probe all the convertors listed as aliases from the file. */
	for (i = 0; i < (size_t) display_names_used; i++)
		display_names[i].available = _charconv_probe_convertor(display_names[i].name);


	/* Add the built-in convertors, in as far as they are not already defined through the aliases file. */
	for (i = 0; i < sizeof(builtin_names) / sizeof(builtin_names[0]); i++) {
		if (_charconv_get_name_desc(builtin_names[i]) == NULL)
			add_display_name(builtin_names[i], _charconv_probe_convertor(builtin_names[i]));
	}

	/* Add all the file names we can find in the DB dir, if they are not already present. */
	if ((dir = opendir(DB_DIRECTORY)) != NULL) {
		while ((entry = readdir(dir)) != NULL) {
			size_t entry_name_len = strlen(entry->d_name);
			if (entry_name_len < 5)
				continue;
			if (entry->d_name[0] == '_')
				continue;
			if (strcmp(entry->d_name + entry_name_len - 4, ".cct") != 0)
				continue;
			entry->d_name[entry_name_len - 4] = 0;
			if (_charconv_get_name_desc(entry->d_name) == NULL)
				add_display_name(entry->d_name, _charconv_probe_convertor(entry->d_name));
		}
		closedir(dir);
	}

	availability_initialized = true;
	pthread_mutex_unlock(&lock);
}

const charconv_name_t *charconv_get_names(int *count) {
	_charconv_init();
	_charconv_init_aliases();
	if (count != NULL)
		*count = display_names_used;
	return display_names;
}
