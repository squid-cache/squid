## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

html: release-$(SQUID_RELEASE).html

EXTRA_DIST = release-$(SQUID_RELEASE).sgml.in

SUFFIXES= .sgml.in .sgml

.sgml.in.sgml:
	sed \
        -e "s%[@]SQUID_VERSION[@]%$(VERSION)%g" \
        -e "s%[@]SQUID_RELEASE[@]%$(SQUID_RELEASE)%g" \
        -e "s%[@]SQUID_RELEASE_OLD[@]%$$(( $(SQUID_RELEASE) - 1 ))%g" \
        < $< >$@
	test `grep -c "@SQUID" $@` -eq 0

.sgml.txt:
	$(LINUXDOC) -B txt --filter $<

.sgml.html:
	$(LINUXDOC) -B html -T 2 --split=0 $< && \
	perl -i -p -e "s%$@%%" $@

.sgml.man:
	$(LINUXDOC) -B txt --manpage $<

.sgml.info:
	$(LINUXDOC) -B info $<

CLEANFILES= \
	*.html *.sgml \
	*.tex *.ps *.dvi *.aux *.log *.toc \
	*.txt *.man
