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

%{
#include "charconv_internal.h"

static enum { START, ALIAS, SKIP_REST } parse_state = START;
static int line_number;
#define PARSE_ERROR 1
%}

%option noyywrap
%option prefix="_charconv_"

%%
\\\n                        line_number++;
\n                          line_number++; parse_state = START;
[[:space:]]                 /* Ignore space */
#.*                         /* Ignore comments */
\*?[-a-zA-Z0-9:.+_]+        {
                            	switch (parse_state) {
                            		case START:
                            			parse_state = _charconv_add_convertor_name(yytext) ? ALIAS : SKIP_REST;
                            			break;
                            		case ALIAS:
                            			_charconv_add_convertor_alias(yytext);
                            			break;
                            		case SKIP_REST:
                            			break;
                            	}
                            }
\*?[-a-zA-Z0-9:.+_]+,([a-zA-Z0-9_]+(=[a-zA-Z0-9_]+)?)?    {
                            	if (parse_state == START)
                            		parse_state = _charconv_add_convertor_name(yytext) ? ALIAS : SKIP_REST;
                            }
.                           return PARSE_ERROR;

%%

#include <errno.h>
#include <string.h>

void _charconv_init_aliases_from_file(void) {
	if ((yyin = _charconv_db_open("aliases", ".txt", NULL)) == NULL) {
		_charconv_log("Error opening aliases.txt: %s\n", strerror(errno));
		return;
	}
	if (yylex() == 1)
		_charconv_log("Parse error at aliases.txt:%d\n", line_number);
	yy_delete_buffer(YY_CURRENT_BUFFER);
	yy_init = 1;
}

