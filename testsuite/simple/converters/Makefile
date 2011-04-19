CONVERTERS := ibm-1390-1399.la

all: $(CONVERTERS) links

ibm-1390-1399.c: ../../../icu-mappings/ibm-1390_P110-2003.ucm ../../../icu-mappings/ibm-1399_P110-2003.ucm
	LD_LIBRARY_PATH=../../../src/.libs ../../../src.util/ucm2ltc -o $@ $^

%.la: .libs/%.lo
	libtool --mode=link --tag=CC $(CC) -o $@ $< -L../../../src/.libs -ltranscript \
		-module -shared -shrext .ltc -rpath /usr/lib

.libs/%.lo: %.c
	libtool --mode=compile --tag=CC $(CC) -I../../../src -c -o $@ $< -L../../../transcript/.libs -ltranscript

links: | $(CONVERTERS)
	LD_LIBRARY_PATH=../../../src/.libs ../../../src.util/linkltc $(patsubst %.la, .libs/%.ltc, $(CONVERTERS))

clean:
	rm -rf *.la .libs $(CONVERTERS:.la=.c)

.PHONY: all clean links
