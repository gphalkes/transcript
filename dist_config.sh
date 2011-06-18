PACKAGE=libtranscript
SRCDIRS="src `hg manifest | egrep -o 'src\.util/[^/]+' | sort | uniq`"
EXCLUDESRC="/(Makefile|TODO.*|SciTE.*|run\.sh|test\.c)$"
GENSOURCES="`echo src/generic_fallbacks.{c,h} src/tables/*.c src.util/ucm2ltc/.objects/*.{cc,c,h}`"
