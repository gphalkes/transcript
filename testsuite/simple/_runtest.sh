#!/bin/bash

if [ $# -eq 0 ] ; then
	echo "Usage: _runtest.sh [-n<num>] <test file>"
	exit 0
fi

if [ "${PWD##*/}" != work ] ; then
	echo "Execute this script in the work subdirectory"
	exit 1
fi

unset TESTNR
while [ $# -gt 1 ] ; do
	case "$1" in
		-n*)
			TESTNR="`printf \"test%02d\"  \"${1#-n}\"`"
			shift
			;;
		*)
			echo "Error in command line: $1"
			exit 1
			;;
	esac
done

rm -f *.txt test[0-9][0-9] 2>/dev/null
csplit -ftest -z -s "$1" '/^--/'
sed -i '/^--/d' test[0-9][0-9]

for i in test[0-9][0-9] ; do
	if [ -n "$TESTNR" ] && [ "$i" != "$TESTNR" ] ; then
		continue
	fi

	printf "  - executing test %d\n" "${i#test}"
	sed -r '/^%%/,$d;s/#.*//' "$i" > input.txt
	sed -r '1,/^%%/d;s/#.*//;s/[[:space:]]+//g' "$i" > output.txt

	OPTIONS="`grep '^#%' \"$i\" | sed -r 's/^#%//'`"
	ulimit -v 393216
	TRANSCRIPT_PATH=../converters/.libs LD_LIBRARY_PATH=../../../src/.libs ../test $OPTIONS < input.txt > result.txt
	diff -uBw output.txt result.txt

	if [ -n "$TESTNR" ] && [ "$i" == "$TESTNR" ] ; then
		break
	fi
done
