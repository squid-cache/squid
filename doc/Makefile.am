
SUBDIRS = manuals

DEFAULT_CONFIG_FILE = $(sysconfdir)/squid.conf
DEFAULT_MIME_TABLE      = $(sysconfdir)/mime.conf
DEFAULT_ERROR_DIR       = $(datadir)/errors

include $(top_srcdir)/doc/manuals/Substitute.am

squid.8: $(srcdir)/squid.8.in Makefile
	$(SUBSTITUTE) < $(srcdir)/squid.8.in > $@

man_MANS = squid.8

EXTRA_DIST = \
	squid.8.in \
	debug-sections.txt

CLEANFILES = squid.8
