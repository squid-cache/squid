## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

all:
	dyn-docs
	html-docs

dyn-docs:
	rm -f -r tmp
	cd ../../ && (cat squid.dox ; echo HTML_FILE_EXTENSION = .dyn ; echo HTML_OUTPUT = tmp ) | doxygen - 2>doxygen.log
	rm -f -r dyn
	mv tmp dyn

html-docs:
	rm -f -r tmp
	cd ../../ && (cat squid.dox | sed s/dyn/html/g | sed s/CALL_GRAPH/#/ | sed s/CALLER_GRAPH/#/ | doxygen -) 2>doxygen.log
	rm -f -r html
	mv tmp html

clean:
	rm -f -r tmp html dyn
