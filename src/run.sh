#!/bin/bash
DIR="`dirname \"$0\"`"

ulimit -v 262144
export LD_LIBRARY_PATH="$DIR/.libs"
"$DIR/test" "$@"
