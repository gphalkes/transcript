PACKAGE=libtranscript
SRCDIRS="src `hg manifest | egrep -o 'src\.util/[^/]+' | egrep -v 'Makefile$' | sort | uniq`"
EXCLUDESRC="/(Makefile|TODO.*|SciTE.*|run\.sh|test\.c|aliases_full\.txt)$"
GENSOURCES="`echo src/generic_fallbacks.{c,h} src/tables/*.c src.util/ucm2ltc/.objects/*.{cc,c,h}`"
VERSIONINFO="1:0:0"
