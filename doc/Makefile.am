## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

SUBDIRS = manuals release-notes

DEFAULT_CONFIG_FILE = $(sysconfdir)/squid.conf
DEFAULT_MIME_TABLE      = $(sysconfdir)/mime.conf
DEFAULT_ERROR_DIR       = $(datadir)/errors

EXTRA_DIST = \
	debug-messages.dox \
	debug-sections.txt

cfgman: $(top_builddir)/src/cf.data $(top_srcdir)/scripts/www/build-cfg-help.pl
	@mkdir -p cfgman
	$(top_srcdir)/scripts/www/build-cfg-help.pl --version $(VERSION) -o cfgman $(top_builddir)/src/cf.data
	$(top_srcdir)/scripts/www/build-cfg-help.pl --version $(VERSION) -o squid-$(VERSION)-cfgman.html -f singlehtml $(top_builddir)/src/cf.data
