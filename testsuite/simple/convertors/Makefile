all: ibm-1390-1399.cct ibm-1390_P110-2003.cct ibm-1399_P110-2003.cct


ibm-1390-1399.cct: ../../../icu-mappings/ibm-1390_P110-2003.ucm ../../../icu-mappings/ibm-1399_P110-2003.ucm
	../../../src.util/ucm2cct -o $@ $^

ibm-1390_P110-2003.cct:
	ln -s ibm-1390-1399.cct ibm-1390_P110-2003.cct

ibm-1399_P110-2003.cct:
	ln -s ibm-1390-1399.cct ibm-1399_P110-2003.cct

clean:
	rm *.cct

.PHONY: all clean
