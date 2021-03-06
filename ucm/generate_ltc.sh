#!/bin/bash

unset REGENERATE

for OPT ; do
	case "$OPT" in
		-r) REGENERATE=1 ;;
		-n) NO_BUILD=1 ;;
	esac
done

die() {
	echo "$*" >&2
	exit 1
}

cd "$(dirname "$0")" || die "Could not cd to script dir"


make --no-print-directory -q -C ../src.util/ucm2ltc || make --no-print-directory -C ../src.util/ucm2ltc
[[ -d ../src/tables ]] || mkdir ../src/tables

# The script below uses the following sed script:
# '/\\$/{$ s/\\$//;$! H};/\\$/!{H;g;s/[[:space:]]+\\\n[[:space:]]+/ /g;s/^\n//;p;z;h}'
# Unwrap lines with a trailing backslash. This works as follows:
# If the line ends in a backslash, there are two cases:
# - if the line is the last line in the file, just remove the backslash [forcing
#   a fallthrough to case without trailing backslash]
# - if the line is not the last in the file, append to hold space
# If the line does not end in a backslash:
# - append to hold space
# - copy hold space to pattern space
# - replace all trailing backslashes by a single space
# - remove starting backslash introduced by H commands
# - print output
# - clear pattern space
# - copy pattern space to hold space
# The last two commands are necessary because there is no command to clear the
# hold space.
{
	echo "SHELL := /bin/bash"
	unset HANDLED
	while read TARGET FILES ; do
		out="`echo \"${TARGET%:}\" | sed -r 's/\.ucm$//;s/[^a-zA-Z0-9]//g;s/(^|[^0-9])0+/\1/' | tr [:upper:] [:lower:]`"
		echo "../src/tables/${out}.c: `echo \"$FILES\" | sed -r 's/(^| )(-[^ \t]+ )+/ /g'`"
		echo "	@echo \"Generating ../src/tables/${out}.c\""
		echo "	@../src.util/ucm2ltc/ucm2ltc -o \"../src/tables/${out}.c\" $FILES"
		ALLTARGETS="${ALLTARGETS} ../src/tables/${out}.c"
		for f in $FILES ; do
			if [ "x${f#-}" != "x$f" ] ; then
				continue
			fi
			HANDLED="$HANDLED$f"$'\n'
		done
	done < <(sed -r -n '/\\$/{$ s/\\$//;$! H};/\\$/!{H;g;s/[[:space:]]+\\\n[[:space:]]+/ /g;s/^\n//;p;z;h}' rules | \
		sed -r 's/#.*//;/^[[:space:]]*$/d')

	for f in `{ echo "$HANDLED$HANDLED" ; find -name '*.ucm' -printf '%P\n' ; } | sort | uniq -u` ; do
		out="`echo \"${f##*/}\" | sed -r 's/\.ucm$//;s/[^a-zA-Z0-9]//g;s/(^|[^0-9])0+/\1/' | tr [:upper:] [:lower:]`"
		echo "../src/tables/${out}.c: $f"
		echo "	@echo \"Generating ../src/tables/${out}.c\""
		echo "	@../src.util/ucm2ltc/ucm2ltc -o \"../src/tables/${out}.c\" $f"
		ALLTARGETS="${ALLTARGETS} ../src/tables/${out}.c"
	done
	cat <<EOF
all:${ALLTARGETS}

remove-stale:
	@export LANG=C;REMOVE=\$\$(comm -2 -3 <( ls ../src/tables/*.c ) <( echo "${ALLTARGETS}" | tr ' ' '\n' | sort )) ; [[ -n \$\$REMOVE ]] && { echo "Removing \$\$REMOVE" ; rm \$\$REMOVE ; } || true
EOF
} | make -f - ${REGENERATE:+-B} all remove-stale || exit 1
[[ -z $NO_BUILD ]] && make -C ../src --no-print-directory
