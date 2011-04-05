# Rules for documentation files generated from the shared directories.
# Define T3NAME before including this file.

all: doxygen motivation.html

doxygen: doxygen.conf DoxygenLayout.xml
	doxygen doxygen.conf

motivation.html: motivation.txt
	@echo [GEN] $@ ; { echo "<html><title>Motivation</title><body>" ; markdown $< ; echo "</body></html>" ; } > $@

.PHONY: clean doxygen