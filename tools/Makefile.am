## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

SUBDIRS = purge squidclient systemd sysvinit
EXTRA_DIST = 
man_MANS = 
DISTCLEANFILES = 

LDADD = \
	$(top_builddir)/src/ip/libip.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(KRB5LIBS) \
	$(XTRA_LIBS)

include $(top_srcdir)/doc/manuals/Substitute.am

## Several files need to be shared but we cannot depend on the other
## directories to be built.
test_tools.cc: $(top_srcdir)/test-suite/test_tools.cc
	cp $(top_srcdir)/test-suite/test_tools.cc .

stub_debug.cc: $(top_srcdir)/src/tests/stub_debug.cc
	cp $(top_srcdir)/src/tests/stub_debug.cc .

time.cc: $(top_srcdir)/src/time.cc
	cp $(top_srcdir)/src/time.cc .

# stock tools for unit tests - library independent versions of dlink_list
# etc.
# globals.cc is needed by test_tools.cc.
# Neither of these should be disted from here.
TESTSOURCES= test_tools.cc
CLEANFILES += test_tools.cc stub_debug.cc time.cc

## ##### helper-mux #####

libexec_SCRIPTS = helper-mux.pl
EXTRA_DIST += helper-mux.pl helper-mux.README

## Test Scripts
EXTRA_DIST += helper-ok-dying.pl helper-ok.pl


## ##### cachemgr.cgi  #####

DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf

libexec_PROGRAMS = cachemgr$(CGIEXT)

cachemgr__CGIEXT__SOURCES = cachemgr.cc \
	stub_debug.cc \
	test_tools.cc \
	time.cc

cachemgr__CGIEXT__CXXFLAGS = -DDEFAULT_CACHEMGR_CONFIG=\"$(DEFAULT_CACHEMGR_CONFIG)\" $(AM_CXXFLAGS)

EXTRA_DIST += cachemgr.conf cachemgr.cgi.8 cachemgr.cgi.8.in
CLEANFILES += cachemgr.cgi.8
man_MANS += cachemgr.cgi.8

cachemgr.cgi.8: $(srcdir)/cachemgr.cgi.8.in Makefile
	$(SUBSTITUTE) < $(srcdir)/cachemgr.cgi.8.in > $@



## Shared

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
