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

CFILES.genconv := genconv.c common.c minimize_state_machine.c
GFILES.genconv := ucmparser.g
LFILES.genconv := ucmlexer.l
DEPS.ucmparser.g := ucmlexer.l genconv.c
CFLAGS.ucmlexer := -Wno-shadow -Wno-switch-default -Wno-unused

TARGETS := genconv
#================================================#
# NO RULES SHOULD BE DEFINED BEFORE THIS INCLUDE #
#================================================#
include ../../makesys/rules.mk
#================================================#
CFLAGS += -I. -I../src -I.objects
