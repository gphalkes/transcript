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

//FIXME: the first CHARMAP may also contain complex mappings

%options "generate-symbol-table lowercase-symbols generate-lexer-wrapper reentrant";
%label CHARMAP, "CHARMAP";
%label END, "END";
%label HEXNUM, "hexadecimal number";
%label CHARSEQ, "character sequence";
%label _INITIAL, "initial";
%label _STATE, "state";
%label MACHINE_SEPARATOR, "machine separator";
%token TAG, SURROGATES, ACTION, STRING, NUMBER, PRECISION;

%start parse_ucm, ucm;
%start parse_states_file, states_file;

{
#include <stdlib.h>
#include <stdio.h>

#include "genconv.h"

extern char *yytext;

void LLmessage(int class) {
	switch (class) {
		case LL_MISSINGEOF:
			fatal("%s:%d: Expected %s, found %s (%s).\n", file_name, line_number, LLgetSymbol(EOFILE), LLgetSymbol(LLsymb), yytext);
			break;
		case LL_DELETE:
			fatal("%s:%d: Unexpected %s (%s).\n", file_name, line_number, LLgetSymbol(LLsymb), yytext);
			break;
		default:
			fatal("%s:%d: Expected %s, found %s (%s).\n", file_name, line_number, LLgetSymbol(class), LLgetSymbol(LLsymb), yytext);
			break;
	}
}

static ucm_t *ucm;

}

ucm<void *>:
	{ LLretval = ucm = new_ucm(); }
	'\n'*
	[
		header_line
		'\n'+
	]+
	{
		process_header_part1(ucm);
		flatten_states_with_default(ucm);
		validate_states((flat_states_t *) ucm);
		process_header_part2(ucm);
		calculate_state_attributes(ucm);
		//print_states(ucm);
		allocate_charmap(ucm);
	}
	CHARMAP '\n'+
	[
		mapping
		'\n'+
	]+
	END CHARMAP
	[
		'\n'+
		[
			CHARMAP '\n'+
			[
				mapping
				'\n'+
			]+
			END CHARMAP
			'\n'*
		]?
	]?
;

header_line {
	tag_t tag;
} :
	TAG
	{ tag = string_to_tag(yytext); }
	value
	{ set_tag_value(ucm, tag, yytext); }
|
	_STATE
	state
;

value:
	STRING
|
	NUMBER
|
	CHARSEQ
;

state {
	int flags = 0;
} :
	[
		[
			_INITIAL { flags |= STATE_INITIAL; }
		|
			SURROGATES
		]
		','
	]?
	{ new_state(flags); }
	[
		entry
		[
			','
			...
		]*
	]?
;

entry {
	linked_entry_t result = { 0, 0, 0, ACTION_FINAL, NULL, NULL };
} :
	HEXNUM
	//FIXME: check for range of numbers!
	{ result.low = result.high = (int) strtol(yytext, NULL, 16); }
	[
		'-'
		HEXNUM
		{ result.high = (int) strtol(yytext, NULL, 16); }
	]?
	[
		':'
		HEXNUM
		{
			result.next_state = (int) strtol(yytext, NULL, 16);
			result.action = ACTION_VALID;
		}
	]?
	[
		'.'
		[
			ACTION
			{
				switch (yytext[0]) {
					case 'u':
						result.action = ACTION_UNASSIGNED;
						break;
					case 's':
						result.action = ACTION_SHIFT;
						break;
					case 'p':
						result.action = ACTION_FINAL_PAIR;
						break;
					case 'i':
						result.action = ACTION_ILLEGAL;
						break;
					default:
						PANIC();
				}
			}
		|
			{ result.action = ACTION_FINAL; }
		]
	]?
	{ new_entry(result); }
;

mapping {
	uint32_t codepoints[17];
	int codepoints_size = 0;
	uint32_t mapped[31];
	int mapped_size;
	int precision = 0;
} :
	TAG
	{
		if (sscanf(yytext, "<U%" SCNx32 ">", &codepoints[codepoints_size]) == 0 || codepoints[codepoints_size] > 0x10ffff)
			fatal("%s:%d: Tag does not specify a valid unicode codepoint\n", file_name, line_number);
		codepoints_size++;
	}
	[
		'+'?
		...
	]*
	CHARSEQ
	{
		if (!map_charseq(ucm, yytext, mapped, &mapped_size))
			fatal("%s:%d: Character sequence '%s' is not valid in the state machine\n", file_name, line_number, yytext);
	}
	[
		PRECISION
		{ precision = yytext[1] - '0'; }
	]?
	{ add_mapping(ucm, codepoints, codepoints_size, mapped, mapped_size, precision); }
;

states_file :
	'\n'*
	[
		_STATE state
		'\n'+
	]*
	{
		flatten_states(&codepage_machine);
		validate_states(&codepage_machine);
	}
	MACHINE_SEPARATOR '\n'+
	[
		_STATE state
		'\n'+
	]*
	{
		flatten_states(&unicode_machine);
		validate_states(&unicode_machine);
	}
;
