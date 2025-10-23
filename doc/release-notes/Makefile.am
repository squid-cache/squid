## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

DOC= release-$(SQUID_RELEASE)

EXTRA_DIST= $(DOC).sgml

SUFFIXES= .sgml.in .sgml

.sgml.in.sgml:
	sed \
        -e "s%[@]SQUID_VERSION[@]%$(VERSION)%g" \
        -e "s%[@]SQUID_RELEASE[@]%$(SQUID_RELEASE)%g" \
        -e "s%[@]SQUID_RELEASE_OLD[@]%$$(( $(SQUID_RELEASE) - 1 ))%g" \
        < $< >$@
	test `grep -c "@SQUID" $@` -eq 0

if ENABLE_DOCUMENTATION
.sgml.txt:
	$(LINUXDOC) -B txt --filter $<

.sgml.html:
	$(LINUXDOC) -B html -T 2 --split=0 $< && $(PERL) -i -p -e "s%$@%%" $@

.sgml.man:
	$(LINUXDOC) -B txt --manpage $<

.sgml.info:
	$(LINUXDOC) -B info $<

CLEANFILES= \
	*.html \
	*.tex *.ps *.dvi *.aux *.log *.toc \
	*.txt *.man
endif
