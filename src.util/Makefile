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

SOURCES.ucm2cct := ucm2cct.cc ucm.cc ucm_write_tables.cc ucm_analyse.cc minimize_state_machine.cc variant.cc \
	ucmparser.gg ucmlexer.l generic_fallbacks.c
DEPS.ucmparser.gg := ucmlexer.l ucm2cct.cc
CFLAGS.ucmlexer := -Wno-shadow -Wno-switch-default -Wno-unused
LDFLAGS.ucm2cct := -L../src/.libs -ltranscript

CXXTARGETS := ucm2cct
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#
CXXFLAGS += -I. -I../src -I.objects -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS #-O2

generic_fallbacks.c generic_fallbacks.h: generic_fallbacks.txt
	$(if $(VERBOSE),, @echo [GEN] $* ;) ../../statrie/src/statrie -fgeneric_fallbacks \
		-nget_generic_fallback -b16 -p -r0x10000 -DFFFF transcript_generic_fallbacks < $<

ucm2cct: | library

library:
	$(MAKE) -C ../src libtranscript.la

clean::
	rm generic_fallbacks.[ch]

.PHONY: library
