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
#include <stdlib.h>
#include "ucmparser.h"

int line_number = 1;
char *file_name;
void fatal(const char *fmt, ...);

%}

%x STATE
%option noyywrap

%%
[ \t]                       /* ignore space */
#.*                         /* ignore */
\n                          line_number++; return '\n';
\<icu:state>                BEGIN(STATE); return _STATE;
--                          return MACHINE_SEPARATOR;
\<[^>]+>                    return TAG;
(\\[xX][0-9a-fA-F]+\+?)+    return CHARSEQ;
[0-9]+                      return NUMBER;
CHARMAP                     return CHARMAP;
END                         return END;
\"[^\"\n]+\"                { size_t len = strlen(yytext); memmove(yytext, yytext + 1, len - 2); yytext[len - 2] = 0; return STRING; }
\".                         fatal("%s:%d: Incomplete string\n", file_name, line_number);
\|[0-3]                     return PRECISION;
.                           fatal("%s:%d: Unexpected character '%c'\n", file_name, line_number, yytext[0]);


<STATE>{
[ \t]                       /* ignore space */
\n                          line_number++; BEGIN(INITIAL); return '\n';
initial                     return _INITIAL;
surrogates                  return SURROGATES;
[0-9a-fA-F]+                return HEXNUM;
[-.:,]                      return yytext[0];
[uspi]                      return ACTION;
.                           fatal("%s:%d: Unexpected character '%c'\n", file_name, line_number, yytext[0]);
}

%%
