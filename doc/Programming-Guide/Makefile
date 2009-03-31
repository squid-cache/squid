
all:
	dyn-docs
	html-docs

dyn-docs:
	rm -f -r tmp
	cd ../../ && (cat squid3.dox ; echo HTML_FILE_EXTENSION = .dyn ; echo HTML_OUTPUT = tmp ) | doxygen - 2>doxygen.log
	mv dyn dyn.bak && mv tmp dyn && rm -r dyn.bak

html-docs:
	rm -f -r tmp
	cd ../../ && (cat squid3.dox | sed s/dyn/html/g | sed s/CALL_GRAPH/#/ | sed s/CALLER_GRAPH/#/ | doxygen -) 2>doxygen.log
	mv html html.bak && mv tmp html && rm -r html.bak

clean:
	rm -f -r tmp html dyn dyn.bak html.bak
