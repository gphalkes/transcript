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

SOURCES.libtranscript.la := transcript.c utf.c transcript_iconv.c cct_convertor.c \
	cct_convertor_io.c unicode_convertor.c unicode_convertor_utf7.c \
	unicode_convertor_gb18030.c iso-2022_convertor.c \
	aliases.c generic_fallbacks.c
LDFLAGS.libtranscript.la := -pthread -lltdl
CFLAGS.cct_convertor := -pthread
CFLAGS.read_aliases := -Wno-shadow -Wno-switch-default -Wno-unused

MODULES := iso-8859-1_convertor

SOURCES.modules/iso-8859-1_convertor.la := modules/iso-8859-1_convertor.c

#$(foreach MODULE, $(MODULES), $(eval $(foreach SOURCE, $(SOURCES.modules/$(MODULE).la), $(eval CFLAGS.$(SOURCE:.c=) := -shared))))
$(foreach MODULE, $(MODULES), $(eval LDFLAGS.modules/$(MODULE).la := -module -avoid-version -L.libs -ltranscript))

SOURCES.test := test.c
LDFLAGS.test := -L.libs
LDLIBS.test := -ltranscript

TARGETS := test
LTTARGETS := libtranscript.la $(patsubst %, modules/%.la, $(MODULES))
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#
CFLAGS += -DDB_DIRECTORY=\"$(PWD)/transcript\" -O2
CFLAGS += -DUSE_ENDIAN
CFLAGS += -DHAS_INLINE
CFLAGS += -DHAS_NL_LANGINFO
CFLAGS += -DHAS_STRDUP
#~ CFLAGS += -DUSE_GETTEXT -DLOCALEDIR=\"locales\"
#~ CFLAGS += -DWITHOUT_PTHREAD
#~ CFLAGS += -std=c89

test: | libtranscript.la

$(OBJECTS): generic_fallbacks.c

generic_fallbacks.c generic_fallbacks.h: ../src.util/generic_fallbacks.txt
	../../statrie/src/statrie -fgeneric_fallbacks -nget_generic_fallback -b16 -p -r0x10000 -DFFFF transcript_generic_fallbacks < $<

clean::
	rm generic_fallbacks.[ch]
