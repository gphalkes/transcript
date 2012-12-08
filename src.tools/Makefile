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

SOURCES.check_converter := check_converter.c
LDFLAGS.check_converter := -L../src/.libs
LDLIBS.check_converter := -ltranscript
CFLAGS.check_converter := -I../src

SOURCES.generate_table := generate_table.c
LDFLAGS.generate_table := -L../src/.libs
LDLIBS.generate_table := -ltranscript
CFLAGS.generate_table := -I../src

TARGETS := check_converter generate_table
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#

check_converter: | library
generate_table: | library

library:
	@$(MAKE) -q -C ../src libtranscript.la || $(MAKE) -C ../src libtranscript.la

.PHONY: library
