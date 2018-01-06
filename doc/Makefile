# Rules for documentation files generated from the shared directories.
# Define T3NAME before including this file.

all: doxygen motivation.html

doxygen: doxygen.conf DoxygenLayout.xml
	doxygen doxygen.conf

motivation.html: motivation.txt
	@echo [GEN] $@ ; { echo "<html><title>Motivation</title><body>" && markdown $< && echo "</body></html>" ; } > $@

clean:
	rm -rf API motivation.html

upload: doxygen
	find API -type f -exec chmod 0644 '{}' ';'
	find API -type d -exec chmod 0755 '{}' ';'
	rsync -arv --delete API/ www.ghalkes.nl:os.ghalkes.nl/doc/libtranscript/

.PHONY: clean doxygen
