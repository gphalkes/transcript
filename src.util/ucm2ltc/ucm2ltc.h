/* Copyright (C) 2011-2012 G.P. Halkes
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

#include <cstdio>
#include <deque>
#include <inttypes.h>
#include <list>
#include <vector>

#ifdef _WIN32
#define DIRSEPS "/\\"
#else
#define DIRSEPS "/"
#endif

using namespace std;

enum action_t {
  ACTION_FINAL,
  ACTION_FINAL_NOFLAGS,
  ACTION_FINAL_LEN1_NOFLAGS,
  ACTION_FINAL_LEN2_NOFLAGS,
  ACTION_FINAL_LEN3_NOFLAGS,
  ACTION_FINAL_LEN4_NOFLAGS,
  /* Define lengths 5 through 8 such that we don't have to renumber later.
     Not used right now. */
  ACTION_FINAL_LEN5_NOFLAGS,
  ACTION_FINAL_LEN6_NOFLAGS,
  ACTION_FINAL_LEN7_NOFLAGS,
  ACTION_FINAL_LEN8_NOFLAGS,
  ACTION_VALID,
  ACTION_UNASSIGNED,
  ACTION_SHIFT,
  ACTION_ILLEGAL,

  ACTION_FLAG_PAIR = (1 << 7),
  ACTION_FINAL_PAIR = ACTION_FINAL | ACTION_FLAG_PAIR,
  ACTION_FINAL_PAIR_NOFLAGS = ACTION_FINAL_NOFLAGS | ACTION_FLAG_PAIR,
  /* List the different combinations with the ACTION_FLAG_PAIR flag, to shut
     up the compiler. It also has the advantage that we don't define other
     constants with the same value accidentally. */
  _ACTION_FINAL_PAIR_LEN1_NOFLAGS,
  _ACTION_FINAL_PAIR_LEN2_NOFLAGS,
  _ACTION_FINAL_PAIR_LEN3_NOFLAGS,
  _ACTION_FINAL_PAIR_LEN4_NOFLAGS,

  ACTION_LOOP = 0xff
};

struct Entry {
  int low, high;
  int next_state;
  action_t action;
  int base;
  int mul;

  Entry(int _low, int _high, int _next_state, action_t _action, int _base, int _mul)
      : low(_low), high(_high), next_state(_next_state), action(_action), base(_base), mul(_mul) {}
};

class State {
 public:
  enum { INITIAL = (1 << 0) };

  int flags;
  vector<Entry> entries;
  int base, range;
  bool complete;
  unsigned int entries_start;

  State(void);
  void new_entry(Entry entry);
};

class Mapping {
 public:
  vector<uint32_t> codepoints;
  vector<uint8_t> codepage_bytes;
  uint8_t from_unicode_flags, to_unicode_flags, precision;
  uint16_t idx;

  enum {
    FROM_UNICODE_LENGTH_MASK = (3 << 0),
    FROM_UNICODE_NOT_AVAIL = (1 << 2),
    FROM_UNICODE_FALLBACK = (1 << 3),
    FROM_UNICODE_SUBCHAR1 = (1 << 4),
    FROM_UNICODE_MULTI_START = (1 << 5),
    FROM_UNICODE_VARIANT = (1 << 6)
  };

  enum {
    TO_UNICODE_FALLBACK = (1 << 0),
    TO_UNICODE_MULTI_START = (1 << 1),
    TO_UNICODE_PRIVATE_USE = (1 << 2),
    TO_UNICODE_VARIANT = (1 << 3)
  };

  Mapping() : from_unicode_flags(0), to_unicode_flags(0), precision(0){};
};

struct shift_sequence_t {
  deque<uint8_t> bytes;
  uint8_t from_state, to_state;
};

class UcmBase {
 public:
  vector<Mapping *> simple_mappings;
  vector<Mapping *> multi_mappings;
  uint8_t used_from_unicode_flags, used_to_unicode_flags;

  enum tag_t {
    IGNORED = -1,
    CODE_SET_NAME,
    UCONV_CLASS,
    SUBCHAR,
    SUBCHAR1,
    MB_MAX,
    MB_MIN,
    CHARSET_FAMILY,
    INTERNAL,

    /* All tags must be defined before this value. */
    LAST_TAG
  };

  UcmBase(void) : used_from_unicode_flags(0), used_to_unicode_flags(0) {}
  void add_mapping(Mapping *mapping);
  virtual int check_codepage_bytes(vector<uint8_t> &bytes) = 0;
  virtual const char *get_tag_value(tag_t tag) = 0;
};

class Ucm;

class Variant : public UcmBase {
 public:
  Ucm *base;
  char *id, *normalized_id;
  uint8_t flags;

 public:
  Variant(Ucm *_base, const char *_id, bool internal = false);
  virtual int check_codepage_bytes(vector<uint8_t> &bytes);
  virtual const char *get_tag_value(tag_t tag);
  void sort_simple_mappings(void);
  void dump(void);
  void write_simple_mappings(FILE *output, int variant_nr);
};

class Ucm : public UcmBase {
 public:
  vector<State *> codepage_states;
  vector<State *> unicode_states;

  Variant variant;
  deque<Variant *> variants;

  uint32_t codepage_range;
  uint32_t unicode_range;

  const char *name;
  int flags;

  enum { CLASS_MBCS = 1, CLASS_SBCS, CLASS_DBCS, CLASS_EBCDIC_STATEFUL };

  enum {
    FROM_UNICODE_FLAGS_TABLE_INCLUDED = (1 << 0),
    TO_UNICODE_FLAGS_TABLE_INCLUDED = (1 << 1),
    MULTI_MAPPINGS_AVAILABLE = (1 << 2),
    SUBCHAR1_VALID = (1 << 3),
    MULTIBYTE_START_STATE_1 = (1 << 4),
    INTERNAL_TABLE = (1 << 5),
    VARIANTS_AVAILABLE = (1 << 6)
  };

  enum { WHERE_MAIN = (1 << 0), WHERE_VARIANTS = (1 << 1) };

  class StateMachineInfo {
   protected:
    deque<Variant *>::const_iterator variant_iter;
    Ucm &source;
    bool iterating_simple_mappings;
    size_t idx;

   public:
    StateMachineInfo(Ucm &_source)
        : variant_iter(_source.variants.begin()),
          source(_source),
          iterating_simple_mappings(true),
          idx(0) {}
    virtual ~StateMachineInfo(void) {}
    virtual const vector<State *> &get_state_machine(void) = 0;
    virtual void replace_state_machine(vector<State *> &states) = 0;
    virtual bool get_next_byteseq(uint8_t *bytes, size_t &length, action_t &mark_action) = 0;
    virtual double get_single_cost(void) = 0;
    virtual bool unassigned_needs_flags(void) = 0;
  };

 private:
  struct tag_value_t {
    char *str;
    int line_number;
  };

  tag_value_t tag_values[LAST_TAG];
  int single_bytes;
  int uconv_class;

  double from_flag_costs, to_flag_costs;
  uint8_t from_unicode_flags, to_unicode_flags;
  /* uint8_t from_unicode_flags_save, to_unicode_flags_save; */

  vector<shift_sequence_t> shift_sequences;

  bool check_map(int state, int byte, action_t action, int next_state);
  void set_default_codepage_states(void);
  void check_duplicates(vector<Mapping *> &mappings, const char *variant_name);
  void check_variant_duplicates(vector<Mapping *> &base_mappings,
                                vector<Mapping *> &variant_mappings, const char *variant_id);
  int calculate_depth(Entry *entry);
  void trace_back(size_t idx, shift_sequence_t &shift_sequence);

  static void write_entries(FILE *output, vector<State *> &states, unsigned int &total_entries);
  static void write_states(FILE *output, vector<State *> &states, const char *name);
  static void write_multi_mappings(FILE *output, vector<Mapping *> &mappings,
                                   unsigned int &mapping_idx);
  void write_sorted_multi_mappings(FILE *output, int variant_nr);
  void write_to_unicode_table(FILE *output);
  void write_from_unicode_table(FILE *output);
  void write_to_unicode_flags(FILE *output);
  void write_from_unicode_flags(FILE *output);
  void write_interface(FILE *output, const char *normalized_name, int variant_nr);
  uint8_t *write_simple_from_unicode(FILE *output);

  void check_state_machine(Ucm *other, int this_state, int other_state);
  static void subtract(vector<Mapping *> &this_mappings, vector<Mapping *> &other_mappings,
                       vector<Mapping *> &this_variant_mappings);
  void find_used_flags(vector<Mapping *> &mappings, int *length_counts);
  void remove_generic_fallbacks_internal(UcmBase *check, Variant *variant);
  void remove_private_use_fallbacks_internal(UcmBase *check);
  void check_base_mul_ranges(vector<State *> &states);

  Mapping *find_mapping_by_codepoint(uint32_t codepoint, int where, int precision_types);
  Mapping *find_mapping_by_codepoints(const vector<uint32_t> &codepoints, int where,
                                      int precision_types);
  Mapping *find_mapping_by_codepage_bytes(const vector<uint8_t> &codepage_bytes, int where,
                                          int precision_types);

  class CodepageBytesStateMachineInfo : public StateMachineInfo {
   public:
    CodepageBytesStateMachineInfo(Ucm &_source) : StateMachineInfo(_source) {}
    virtual const vector<State *> &get_state_machine(void);
    virtual void replace_state_machine(vector<State *> &states);
    virtual bool get_next_byteseq(uint8_t *bytes, size_t &length, action_t &mark_action);
    virtual double get_single_cost(void);
    virtual bool unassigned_needs_flags(void);
  };

  class UnicodeStateMachineInfo : public StateMachineInfo {
   public:
    UnicodeStateMachineInfo(Ucm &_source) : StateMachineInfo(_source) {}
    virtual const vector<State *> &get_state_machine(void);
    virtual void replace_state_machine(vector<State *> &states);
    virtual bool get_next_byteseq(uint8_t *bytes, size_t &length, action_t &mark_action);
    virtual double get_single_cost(void);
    virtual bool unassigned_needs_flags(void);
  };

 public:
  Ucm(const char *_name);
  void set_tag_value(tag_t tag, const char *value);
  virtual const char *get_tag_value(tag_t tag);
  void new_codepage_state(int _flags = 0);
  void new_codepage_entry(Entry entry);
  void process_header(void);
  void validate_states(void);
  virtual int check_codepage_bytes(vector<uint8_t> &bytes);
  void check_duplicates(void);
  void remove_generic_fallbacks(void);
  void remove_private_use_fallbacks(void);
  void ensure_ascii_controls(void);
  void calculate_item_costs(void);
  void minimize_state_machines(void);
  void find_shift_sequences(void);
  void write_table(FILE *output);
  void add_variant(Variant *variant);
  void check_compatibility(Ucm *other);
  void prepare_subtract(void);
  void subtract(Ucm *other);
  void fixup_variants(void);
  void merge_variants(Ucm *other);
  void variants_done(void);
  void check_base_mul_ranges(void);
  void write_namelist_entries(FILE *output);
  bool is_simple_table(void);
  void write_simple(FILE *output);
  void ensure_subchar_mapping(void);

  void dump(void);
};

extern "C" int line_number;
extern "C" char *file_name;

extern "C"
#if __cplusplus >= 201103L
  [[noreturn]]
#endif
void fatal(const char *fmt, ...);
#define PANIC() fatal("Program logic error at line: %s:%d\n", __FILE__, __LINE__)
#define OOM() fatal("Out of memory\n")
#define ASSERT(x)      \
  do {                 \
    if (!(x)) PANIC(); \
  } while (0)

extern const char *option_converter_name;
extern int option_verbose;
extern bool option_internal_table, option_allow_ibm_rotate;

Ucm::tag_t string_to_tag(const char *str);
void parse_byte_sequence(char *charseq, vector<uint8_t> &store);
void print_state_machine(const vector<State *> &states);
const char *sprint_sequence(vector<uint8_t> &bytes);
const char *sprint_codepoints(vector<uint32_t> &codepoints);
uint32_t map_charseq(vector<State *> &states, uint8_t *charseq, int length, int flags);
int popcount(int x);
uint8_t create_mask(uint8_t used_flags);

void minimize_state_machine(Ucm::StateMachineInfo *info, int flags);

bool compare_codepage_bytes(Mapping *a, Mapping *b);
bool compare_codepoints(Mapping *a, Mapping *b);

char *safe_strdup(const char *str);
void *safe_malloc(size_t size);
#endif
