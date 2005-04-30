#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.4 2005/04/30 15:30:57 serassio Exp $
#
#  Uncomment and customize the following to suit your needs:
#

DEFAULT_CONFIG_FILE = $(sysconfdir)/squid.conf
DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf
DEFAULT_MIME_TABLE      = $(sysconfdir)/mime.conf
DEFAULT_ERROR_DIR       = $(datadir)/errors/@ERR_DEFAULT_LANGUAGE@

SUBSTITUTE=sed "\
	s%@DEFAULT_CONFIG_FILE@%$(DEFAULT_CONFIG_FILE)%g;\
	s%@DEFAULT_CACHEMGR_CONFIG@%$(DEFAULT_CACHEMGR_CONFIG)%g;\
	s%@DEFAULT_ERROR_DIR@%$(DEFAULT_ERROR_DIR)%g;\
	s%@DEFAULT_MIME_TABLE@%$(DEFAULT_MIME_TABLE)%g;\
	"

squid.8: squid.8.in Makefile
	$(SUBSTITUTE) < $< > $@

cachemgr.cgi.8: cachemgr.cgi.8.in Makefile
	$(SUBSTITUTE) < $< > $@

man_MANS = \
	squid.8 \
	cachemgr.cgi.8

EXTRA_DIST = \
	squid.8.in \
	cachemgr.cgi.8.in \
	debug-sections.txt

CLEANFILES = \
	squid.8 \
	cachemgr.cgi.8
