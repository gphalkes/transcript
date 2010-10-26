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
#include "charconv.h"

void *open_cct_convertor(const char *name, int utf_type, int flags, int *error);

void *charconv_open_convertor(const char *name, int utf_type, int flags, int *error) {
	//FIXME: for now we only have cct based convertors, but we have to handle the others as well!
	return open_cct_convertor(name, utf_type, flags, error);
}

void charconv_close_convertor(void *handle) {
	((charconv_common_t *) handle)->close(handle);
}

int charconv_to_unicode(void *handle, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft, int flags) {
	return ((charconv_common_t *) handle)->convert_to(handle, inbuf, inbytesleft, outbuf, outbytesleft, flags);
}
