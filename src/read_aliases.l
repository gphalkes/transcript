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

static enum { START, PRE_OPTIONS, ALIAS } parse_state = START;
static int line_number;
#define PARSE_ERROR 1
%}

%x OPTIONS
%option noyywrap

%%
\\\n                        line_number++;
\n                          line_number++; parse_state = START;
[[:space:]]                 if (parse_state == PRE_OPTIONS) parse_state = ALIAS;
#.*                         if (parse_state == PRE_OPTIONS) parse_state = ALIAS;
\*[-a-zA-Z0-9:.+_]+         {
								switch (parse_state) {
									case START:
										_charconv_add_convertor_name(yytext);
										parse_state = PRE_OPTIONS;
										break;
									case PRE_OPTIONS:
										/* ERROR! */
										break;
									case ALIAS:
										_charconv_add_convertor_alias(yytext);
										break;
								}
							}
,                           BEGIN(OPTIONS);
.                           return PARSE_ERROR;

<OPTIONS>{
[a-zA-Z0-9_]+               _charconv_set_option(yytext, NULL);
[a-zA-Z0-9_]+=[a-zA-Z0-9_]+ { char *equals = strchr(yytext, '='); *equals = 0; _charconv_set_option(yytext, equals + 1); }
#.*                         BEGIN(INITIAL); parse_state = ALIAS;
\\\n                        line_number++;
\n                          line_number++; BEGIN(INITIAL); parse_state = START;
[[:space:]]                 BEGIN(INITIAL); parse_state = ALIAS;
.                           return PARSE_ERROR;
}

%%

void _charconv_init_aliases(void) {
	/* FIXME: open correct aliases file (use cct_open which should be moved to charconv.c */
	if ((yyin = fopen("aliases.txt", "r")) == NULL)
		return;
	yylex();
	yy_delete_buffer(YY_CURRENT_BUFFER);
	yy_init = 1;
}

