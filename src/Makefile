# Copyright (C) 2010 G.P. Halkes
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SOURCES.libtranscript.la := transcript.c transcript_io.c utf.c transcript_iconv.c \
	state_table_converter.c aliases.c generic_fallbacks.c sbcs_table_converter.c
LDFLAGS.libtranscript.la := -lltdl
CFLAGS.read_aliases := -Wno-shadow -Wno-switch-default -Wno-unused
LCFLAGS := -DTRANSCRIPT_BUILD_DSO

MODULE_FLAGS := -module -avoid-version -L.libs -ltranscript -shrext .ltc

MODULES := ascii unicode iso2022

# If SOURCES is not defined for a module, assume that module*.c are the sources
$(foreach MODULE, $(MODULES), $(eval SOURCES.modules/$(MODULE).la ?= $(wildcard modules/$(MODULE)*.c)))
# Modules need to be linked with special flags
$(foreach MODULE, $(MODULES), $(eval LDFLAGS.modules/$(MODULE).la += $(MODULE_FLAGS)))

TABLES := $(patsubst %.c, %, $(wildcard tables/*.c))
$(foreach TABLE, $(TABLES), $(eval SOURCES.$(TABLE).la := $(TABLE).c))
$(foreach TABLE, $(TABLES), $(eval LDFLAGS.$(TABLE).la += $(MODULE_FLAGS)))

MODULESOURCES := $(foreach MODULE, $(MODULES), $(SOURCES.modules/$(MODULE).la))
TABLESOURCES := $(foreach TABLE, $(TABLES), $(SOURCES.$(TABLE).la))

SOURCES.test := test.c
LDFLAGS.test := -L.libs
LDLIBS.test := -ltranscript

TARGETS := test
LTTARGETS := libtranscript.la $(patsubst %, modules/%.la, $(MODULES)) $(TABLES:=.la)
EXTRATARGETS := converter-links
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#
CFLAGS += -DDB_DIRECTORY=\"$(CURDIR)/modules/.libs:$(CURDIR)/tables/.libs:$(CURDIR)\" #-O2
CFLAGS += -DUSE_ENDIAN
CFLAGS += -DHAS_INLINE
CFLAGS += -DHAS_NL_LANGINFO
CFLAGS += -DHAS_STRDUP
#~ CFLAGS += -DUSE_GETTEXT -DLOCALEDIR=\"locales\"
#~ CFLAGS += -std=c89

test $(patsubst %, modules/%.la, $(MODULES)) $(TABLES:=.la): | libtranscript.la

$(OBJECTS): generic_fallbacks.c

generic_fallbacks.c generic_fallbacks.h: generic_fallbacks.txt
	$(if $(VERBOSE),, @echo [GEN] $* ;) ../../statrie/src/statrie -fgeneric_fallbacks -nget_generic_fallback -b16 -p \
		-r0x10000 -DFFFF -H'#include "transcript.h"' -e'TRANSCRIPT_LOCAL extern' transcript_generic_fallbacks < $<

clean::
	rm -rf generic_fallbacks.[ch] 2>/dev/null
	rm -rf modules/.libs modules/*.la 2>/dev/null
	rm -rf tables/.libs tables/*.la 2>/dev/null

$(patsubst %.c, .objects/%.lo, $(MODULESOURCES)): | links
$(patsubst %.c, .objects/%.lo, $(TABLESOURCES)): | links

links:
	$(if $(VERBOSE), @echo [SH] making links ;,)
	@[ -L transcript ] || ln -s . transcript

converter-links: | linkltc $(LTTARGETS)
	@cd modules/.libs ; LD_LIBRARY_PATH=../../.libs ../../../src.util/linkltc/linkltc *.ltc
	@cd tables/.libs ; LD_LIBRARY_PATH=../../.libs ../../../src.util/linkltc/linkltc *.ltc

linkltc: libtranscript.la
	@$(MAKE) -q -C ../src.util/linkltc || $(MAKE) --no-print-directory -C ../src.util/linkltc

.PHONY: links converter-links linkltc
