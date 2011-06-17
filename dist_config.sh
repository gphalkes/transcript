PACKAGE=libtranscript
SRCDIRS="src `find src.util -mindepth 1 -maxdepth 1 -type d`"
EXCLUDESRC="/(Makefile|TODO.*|SciTE.*|run\.sh|test\.c)$"
GENSOURCES="`echo src/generic_fallbacks.{c,h} src/tables/*.c src.util/ucm2ltc/.objects/*.{cc,c,h}`"
