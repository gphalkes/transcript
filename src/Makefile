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

SOURCES.libtranscript.la := transcript.c utf.c transcript_iconv.c cct_convertor.c aliases.c generic_fallbacks.c
LDFLAGS.libtranscript.la := -lltdl
CFLAGS.read_aliases := -Wno-shadow -Wno-switch-default -Wno-unused
LCFLAGS := -DTRANSCRIPT_BUILD_DSO

MODULE_FLAGS := -module -avoid-version -L.libs -ltranscript -shrext .tct

MODULES := iso-8859-1 unicode iso-2022

# If SOURCES is not defined for a module, assume that module*.c are the sources
$(foreach MODULE, $(MODULES), $(eval SOURCES.modules/$(MODULE).la ?= $(wildcard modules/$(MODULE)*.c)))
# Modules need to be linked with special flags
$(foreach MODULE, $(MODULES), $(eval LDFLAGS.modules/$(MODULE).la += $(MODULE_FLAGS)))

TABLES := $(patsubst %.c, %, $(wildcard tables/*.c))
$(foreach TABLE, $(TABLES), $(eval SOURCES.$(TABLE).la := $(TABLE).c))
$(foreach TABLE, $(TABLES), $(eval LDFLAGS.$(TABLE).la += $(MODULE_FLAGS)))

SOURCES.test := test.c
LDFLAGS.test := -L.libs
LDLIBS.test := -ltranscript

TARGETS := test
LTTARGETS := libtranscript.la $(patsubst %, modules/%.la, $(MODULES)) $(TABLES:=.la)
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#
CFLAGS += -DDB_DIRECTORY=\"$(PWD)/modules/.libs:$(PWD)/tables/.libs\" -O2
CFLAGS += -DUSE_ENDIAN
CFLAGS += -DHAS_INLINE
CFLAGS += -DHAS_NL_LANGINFO
CFLAGS += -DHAS_STRDUP
#~ CFLAGS += -DUSE_GETTEXT -DLOCALEDIR=\"locales\"
#~ CFLAGS += -std=c89

test $(patsubst %, modules/%.la, $(MODULES)) $(TABLES:=.la): | libtranscript.la

$(OBJECTS): generic_fallbacks.c

generic_fallbacks.c generic_fallbacks.h: ../src.util/generic_fallbacks.txt
	$(if $(VERBOSE),, @echo [GEN] $* ;) ../../statrie/src/statrie -fgeneric_fallbacks -nget_generic_fallback -b16 -p \
		-r0x10000 -DFFFF -H'#include "transcript.h"' -e'TRANSCRIPT_LOCAL extern' transcript_generic_fallbacks < $< \
		$(if $(VERBOSE),,2>/dev/null)

clean::
	rm generic_fallbacks.[ch] 2>/dev/null
	rm -rf modules/.libs 2>/dev/null

links:
	[ -d transcript ] || mkdir transcript
	[ -L transcript/moduledefs.h ] || ln -s ../moduledefs.h transcript
	[ -L transcript/api.h ] || ln -s ../api.h transcript
	[ -L transcript/bool.h ] || ln -s ../bool.h transcript
	[ -L transcript/handle.h ] || ln -s ../handle.h transcript
	[ -L transcript/static_assert.h ] || ln -s ../static_assert.h transcript

.PHONY: links
