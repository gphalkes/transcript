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

LCFILES.libcharconv.la := charconv.c utf.c cc_iconv.c cct_convertor.c cct_convertor_io.c unicode_convertor.c \
	unicode_convertor_utf7.c unicode_convertor_gb18030.c iso-8859-1_convertor.c iso-2022_convertor.c
LDFLAGS.libcharconv.la := -pthread
CFLAGS.cct_convertor := -pthread

CFILES.test := test.c
LDFLAGS.test := -L.libs
LDLIBS.test := -lcharconv

TARGETS := libcharconv.la test

#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#
CFLAGS += -DDB_DIRECTORY=\"$(PWD)/charconv\" -DUSE_ENDIAN

test: | libcharconv.la
