#!/bin/bash

rm -f *.txt 2>/dev/null
sed -r '/^%%/,$d;s/#.*//' "$1" > input.txt
sed -r '1,/^%%/d;s/#.*//;s/[[:space:]]+//g' "$1" > output.txt

OPTIONS="`head -n 1 \"$1\" | sed -r 's/^#//'`"
ulimit -v 393216
TRANSCRIPT_PATH=../convertors/.libs LD_LIBRARY_PATH=../../../src/.libs ../test  $OPTIONS < input.txt > result.txt
diff -uBw output.txt result.txt
