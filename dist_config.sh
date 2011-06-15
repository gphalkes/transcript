PACKAGE=libtranscript
SRCDIRS="src src.util"
EXCLUDESRC="/(Makefile|TODO.*|SciTE.*|run\.sh|test\.c)$"
GENSOURCES="`echo src/generic_fallbacks.{c,h} src/tables/*.c src.util/ucm2ltc/.objects/*.{cc,c,h}`"
AUXFILES="README"
