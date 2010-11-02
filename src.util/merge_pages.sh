# #!/bin/bash
# Copyright (C) 2010 G.P. Halkes
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ $# -lt 2 ] ; then
	echo "Usage: merge_pages.sh <PAGE 1> <PAGE 2> ..."
	echo "NOTE: this script assumes that the state machines are compatible!"
	exit
fi

BASETMP="`mktemp`"

sed -r 's/^[[:space:]]+//;s/[[:space:]]+/ /g' "$@" | egrep '^<U' | sort | uniq -d >> "$BASETMP"

BASEPAGE="$1"

declare -A PARTTMP

for PAGE; do
	PARTTMP["$PAGE"]="`mktemp`"
	sed -r 's/^[[:space:]]+//;s/[[:space:]]+/ /g' "$PAGE" "$BASETMP" | egrep '^<U' | sort | uniq -u >> "${PARTTMP[$PAGE]}"
	if [ ! -s "${PARTTMP[$PAGE]}" ] ; then
		BASEPAGE="$PAGE"
	fi
done

OUTNAME="`basename \"$BASEPAGE\"`"
OUTNAME="${OUTNAME%.ucm}_shared.ucm"
{
	sed -r '/^[[:space:]]*CHARMAP/,$d' "$BASEPAGE"
	echo "CHARMAP"
	cat "$BASETMP"
	echo "END CHARMAP"

	COUNTER=65536

	for PAGE; do
		echo
		if [ "$PAGE" = "$BASEPAGE" ] ; then
			if [ -s "${PARTTMP[$PAGE]}" ] ; then
				echo "VARIANT 0 # $PAGE"
				cat "${PARTTMP[$PAGE]}"
				echo "END VARIANT"
			fi
			continue
		fi
		if echo "$PAGE" | egrep -q "^(.*/)?ibm-[0-9]+([-_].*)?.ucm$" ; then
			NUMBER="`echo \"$PAGE\" | sed -r 's%^(.*/)?ibm-([0-9]+).*\$%\\2%'`"
			echo "VARIANT $NUMBER # $PAGE"
		else
			echo "VARIANT $COUNTER # $PAGE"
			let COUNTER++
		fi
		cat "${PARTTMP[$PAGE]}"
		echo "END VARIANT"
	done
} > "$OUTNAME"

rm "$BASETMP"
for PAGE; do
	rm "${PARTTMP[$PAGE]}"
done
