# Copyright (C) 2010,2012 G.P. Halkes
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SOURCES.linkltc := linkltc.c
LDFLAGS.linkltc := -L../../src/.libs
LDLIBS.linkltc := -ltranscript
CFLAGS.linkltc := -I../../include

TARGETS := linkltc
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../../makesys/rules.mk
#================================================#

CFLAGS += -DHAS_DLFCN
LDLIBS += -ldl
#~ LDLIBS += -lltdl


linkltc: | library

library:
	@$(MAKE) -q -C ../../src libtranscript.la || $(MAKE) -C ../../src libtranscript.la

clang-format:
	clang-format -i *.c *.h

.PHONY: library clang-format
