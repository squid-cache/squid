## Copyright (C) 1996-2014 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

all: release-3.5.html

DOC= release-3.5

$(DOC).ps: $(DOC).sgml
	linuxdoc -B latex -o ps $(DOC)

#$(DOC).dvi: $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#

%.txt: %.sgml
	linuxdoc -B txt --filter $<

%.html: %.sgml
	linuxdoc -B html -T 2 --split=0 $<
	perl -i -p -e "s%$@%%" $@

%.man: %.sgml
	linuxdoc -B txt -T 2 -m $(DOC)

clean:
	rm -f *.html
	rm -f *.tex *.ps *.dvi *.aux *.log *.toc
	rm -f *.txt *.man
