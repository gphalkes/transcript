#!/bin/bash

rm -f map*.ucm 2>/dev/null
csplit -k -s -z -f map -b '%02d.ucm' "$1" '/^%%/' 2> /dev/null
OPTIONS="`head -n 1 \"$1\" | sed -r 's/^#%//;s/%.*//'`"

../../../src.util/ucm2ltc $OPTIONS `ls map*.ucm | sort -n`

