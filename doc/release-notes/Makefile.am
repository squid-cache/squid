## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# requires the linuxdoc tools
if ENABLE_RELEASE_DOCS

DOC= release-5

%.ps: %.sgml
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
	cp -p $@ $(top_builddir)/RELEASENOTES.html

%.man: %.sgml
	linuxdoc -B txt -T 2 -m $(DOC)

dist-hook: $(DOC).html
	@if test -f $(builddir)/$(DOC).html; then \
	  cp -p $(builddir)/$(DOC).html $(top_distdir)/RELEASENOTES.html; \
	fi

EXTRA_DIST= $(DOC).html

CLEANFILES= \
	*.html \
	*.tex *.ps *.dvi *.aux *.log *.toc \
	*.txt *.man \
	$(top_builddir)/RELEASENOTES.html

endif
