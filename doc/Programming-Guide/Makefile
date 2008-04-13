
all:
	dyn-docs
	html-docs

dyn-docs:
	rm -f -r tmp
	cd ../../ && (cat squid3.dox ; echo HTML_FILE_EXTENSION = .dyn ; echo HTML_OUTPUT = tmp ) | doxygen - 2>doxygen.log
	mv tmp dyn

html-docs:
	rm -f -r tmp
	cd ../../ && (cat squid3.dox | sed s/dyn/html/g | sed s/CALL_GRAPH/#/ | sed s/CALLER_GRAPH/#/ | doxygen -) 2>doxygen.log
	mv tmp html

clean:
	rm -f -r tmp html dyn
