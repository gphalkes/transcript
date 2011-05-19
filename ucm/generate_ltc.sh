#!/bin/bash

unset REGENERATE
if [ "$1" = "-r" ] ; then
	REGENERATE=1
fi

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
	unset HANDLED
	while read TARGET FILES ; do
		out="`echo \"${TARGET%:}\" | sed -r 's/\.ucm$//;s/[^a-zA-Z0-9]//g;s/(^|[^0-9])0+/\1/' | tr [:upper:] [:lower:]`"
		echo "../src/tables/${out}.c: `echo \"$FILES\" | sed -r 's/(^| )(-[ci] )+/ /g'`"
		echo "	@echo \"Generating ../src/tables/${out}.c\""
		echo "	@../src.util/ucm2ltc -o \"../src/tables/${out}.c\" $FILES"
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
		echo "	@../src.util/ucm2ltc -o \"../src/tables/${out}.c\" $f"
		ALLTARGETS="${ALLTARGETS} ../src/tables/${out}.c"
	done
	echo "all:${ALLTARGETS}"
} | make -f - ${REGENERATE:+-B} all && make -C ../src --no-print-directory
