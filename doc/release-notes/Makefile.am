## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# requires the linuxdoc tools
if ENABLE_RELEASE_DOCS

DOC= release-$(SQUID_RELEASE)

%.sgml: %.sgml.in
	sed \
        -e "s%[@]SQUID_VERSION[@]%$(VERSION)%g" \
        -e "s%[@]SQUID_RELEASE[@]%$(SQUID_RELEASE)%g" \
        -e "s%[@]SQUID_RELEASE_OLD[@]%$$(( $(SQUID_RELEASE) - 1 ))%g" \
        < $< >$@
	test `grep -c "@SQUID" $@` -eq 0

%.txt: %.sgml
	linuxdoc -B txt --filter $<

%.html: %.sgml
	linuxdoc -B html -T 2 --split=0 $<
	perl -i -p -e "s%$@%%" $@
	cp -p $@ $(top_builddir)/RELEASENOTES.html

%.man: %.sgml
	linuxdoc -B txt --manpage $<

%.info: %.sgml
	linuxdoc -B info $<

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
