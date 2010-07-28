#
#  Makefile for the Squid Object Cache server
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

##  src/stub_debug.cc provides a usable stub debugs() API.
stub_debug.cc: $(top_srcdir)/src/stub_debug.cc
	cp $(top_srcdir)/src/stub_debug.cc .

##  src/time.cc provides a usable time API.
time.cc: $(top_srcdir)/src/time.cc
	cp $(top_srcdir)/src/time.cc .

# Neither of these should be disted from here.
TESTSOURCES= stub_debug.cc time.cc
CLEANFILES += stub_debug.cc time.cc

SUBDIRS		= 

bin_PROGRAMS = \
	squidclient

libexec_PROGRAMS = \
	cachemgr$(CGIEXT)

man_MANS = \
	squidclient.1

DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf

squidclient_SOURCES = squidclient.cc
nodist_squidclient_SOURCES=time.cc stub_debug.cc

cachemgr__CGIEXT__SOURCES = cachemgr.cc
nodist_cachemgr__CGIEXT__SOURCES = time.cc stub_debug.cc
cachemgr__CGIEXT__CXXFLAGS = -DDEFAULT_CACHEMGR_CONFIG=\"$(DEFAULT_CACHEMGR_CONFIG)\" $(AM_CXXFLAGS)

LDADD = \
	../src/ip/libip.la \
	../compat/libcompat.la \
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

