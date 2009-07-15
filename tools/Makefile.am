#
#  Makefile for the Squid Object Cache server
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


SUBDIRS		= 

bin_PROGRAMS = \
	squidclient

libexec_PROGRAMS = \
	cachemgr$(CGIEXT)

man_MANS = \
	squidclient.1

DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf

squidclient_SOURCES = squidclient.cc
cachemgr__CGIEXT__SOURCES = cachemgr.cc
cachemgr__CGIEXT__CXXFLAGS = -DDEFAULT_CACHEMGR_CONFIG=\"$(DEFAULT_CACHEMGR_CONFIG)\" $(AM_CXXFLAGS)

LDADD = \
	../compat/libcompat.la \
	../src/ip/libip.la \
	-L../lib -lmiscutil \
	$(XTRA_LIBS)

EXTRA_DIST = \
	cachemgr.conf \
	squidclient.1

$(OBJS): $(top_srcdir)/include/version.h ../include/autoconf.h

install-data-local:
	$(INSTALL_DATA) $(srcdir)/cachemgr.conf $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG).default
	@if test -f $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG) ; then \
	        echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG)" ; \
	else \
	        echo "$(INSTALL_DATA) $(srcdir)/cachemgr.conf $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG)"; \
	        $(INSTALL_DATA) $(srcdir)/cachemgr.conf $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG); \
	fi

uninstall-local:
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG)
	$(RM) -f $(DESTDIR)$(DEFAULT_CACHEMGR_CONFIG).default

DISTCLEANFILES = 

