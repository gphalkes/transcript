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
#ifndef UCM2CTT_H
#define UCM2CTT_H

#include <vector>
#include <inttypes.h>

using namespace std;

enum action_t {
	ACTION_FINAL,
	ACTION_FINAL_PAIR,
	ACTION_VALID,
	ACTION_UNASSIGNED,
	ACTION_SHIFT,
	ACTION_ILLEGAL
};

struct Entry {
	int low, high;
	int next_state;
	action_t action;
	int base;
	int mul;
	int max;

	Entry(int _low, int _high, int _next_state, action_t _action, int _base, int _mul, int _max) :
		low(_low), high(_high), next_state(_next_state), action(_action), base(_base), mul(_mul), max(_max) {}
};

class State {
	public:
		enum {
			INITIAL = (1<<0)
		};

		int flags;
		vector<Entry> entries;
		int base, range;
		bool complete;

		State(void);
		void new_entry(Entry entry);
};

class Mapping {
	public:
		vector<uint32_t> codepoints;
		vector<uint8_t> codepage_bytes;
		uint8_t flags, precision;

		Mapping() : flags(0), precision(0) {};
		//~ Mapping(const Mapping &other) : codepoints(other.codepoints), codepage_bytes(other.codepage_bytes),
			//~ flags(other.flags), precision(other.precision) {}
};


class Ucm {
	public:
		vector<State> codepage_states;
		vector<State> unicode_states;
		vector<Mapping> simple_mappings;
		vector<Mapping> multi_mappings;

		enum tag_t {
			IGNORED = -1,
			CODE_SET_NAME,
			UCONV_CLASS,
			SUBCHAR,
			SUBCHAR1,
			ICU_BASE,

			/* All tags must be defined before this value. */
			LAST_TAG
		};

		enum {
			CLASS_MBCS = 1,
			CLASS_SBCS,
			CLASS_DBCS,
			CLASS_EBCDIC_STATEFUL
		};

		enum {
			MULTIBYTE_START_STATE_1 = (1<<0)
		};

	private:
		char *tag_values[LAST_TAG];
		int uconv_class;
		int flags;

		int max_bytes;

		bool check_map(int state, int byte, action_t action, int next_state);
		void set_default_codepage_states(void);
		int check_codepage_bytes(vector<uint8_t> &bytes);
		void check_duplicates(vector<Mapping> &mappings);

	public:
		Ucm(void);
		void set_tag_value(tag_t tag, const char *value);
		void new_codepage_state(int _flags = 0);
		void new_codepage_entry(Entry entry);
		void process_header(void);
		void validate_states(void);
		void add_mapping(Mapping &mapping);
		void check_duplicates(void);
};

extern "C" int line_number;
extern "C" char *file_name;

extern "C" void fatal(const char *fmt, ...);
#define PANIC() fatal("Program logic error at line: %s:%d\n", __FILE__, __LINE__)
#define OOM() fatal("Out of memory\n")

extern bool option_verbose;

Ucm::tag_t string_to_tag(const char *str);
#endif
