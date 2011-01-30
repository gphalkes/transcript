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

	if ((display_names[display_names_used].name = strdup(name)) == NULL)
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

	if (convertors_tail != NULL && !(convertors_tail->flags & NAME_DESC_FLAG_HAS_DISPNAME))
		add_display_name(convertors_tail->real_name, (convertors_tail->flags & NAME_DESC_FLAG_AVAILABLE) != 0);

	if (is_display_name)
		name++;

	_charconv_squash_name(name, squashed_name);

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
			(convertor->real_name = strdup(name)) == NULL ||
			(convertor->name = strdup(squashed_name)) == NULL)
	{
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	convertor->aliases = NULL;
	convertor->next = NULL;

	if ((convertor->name = strdup(squashed_name)) == NULL) {
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	convertor->flags = _charconv_probe_convertor(name) ? NAME_DESC_FLAG_AVAILABLE : 0;

	if (is_display_name) {
		add_display_name(name, (convertor->flags & NAME_DESC_FLAG_AVAILABLE) != 0);
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

	_charconv_squash_name(name, squashed_name);

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

	if ((alias->name = strdup(squashed_name)) == NULL) {
		_charconv_log("error: out of memory while loading aliases\n");
		/* FIXME: should really jump out of the whole parsing here. */
		goto return_error;
	}

	if (is_display_name) {
		add_display_name(name, (convertors_tail->flags & NAME_DESC_FLAG_AVAILABLE) != 0);
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
	_charconv_squash_name(name, squashed_name);

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

const charconv_name_t *charconv_get_names(int *count) {
	_charconv_init();
	if (count != NULL)
		*count = display_names_used;
	return display_names;
}

static const char *builtin_names[] = {
	"UTF-8",
	"UTF-16",
	"UTF-16LE",
	"UTF-16BE",
	"UTF-32",
	"UTF-32LE",
	"UTF-32BE",
	"UTF-8,bom",
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

void _charconv_init_aliases(void) {
	char squashed_name[SQUASH_NAME_MAX];
	size_t i;

	_charconv_init_aliases_from_file();

	for (i = 0; i < sizeof(builtin_names) / sizeof(builtin_names[0]); i++) {
		_charconv_squash_name(builtin_names[i], squashed_name);
		LOOP_LIST(charconv_name_desc_t, ptr, convertors)
			if (strcmp(squashed_name, ptr->name) == 0)
				goto next_builtin_name;

			LOOP_LIST(charconv_alias_name_t, alias, ptr->aliases)
				if (strcmp(squashed_name, alias->name) == 0)
					goto next_builtin_name;
			END_LOOP_LIST
		END_LOOP_LIST
		add_display_name(builtin_names[i], _charconv_probe_convertor(builtin_names[i]));
next_builtin_name:;
	}
}

