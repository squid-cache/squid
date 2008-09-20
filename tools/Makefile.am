#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.2 2006/05/11 12:25:39 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#


AUTOMAKE_OPTIONS = subdir-objects

INCLUDES        = -I. -I$(srcdir) -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir)/lib/libTrie/include
INCLUDES	+= @SQUID_CPPUNIT_INC@

TESTS=$(check_PROGRAMS)
check_PROGRAMS=

SUBDIRS		= 

bin_PROGRAMS = \
	squidclient

libexec_PROGRAMS = \
	cachemgr$(CGIEXT)

DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf

squidclient_SOURCES = squidclient.cc
cachemgr__CGIEXT__SOURCES = cachemgr.cc
cachemgr__CGIEXT__CXXFLAGS = -DDEFAULT_CACHEMGR_CONFIG=\"$(DEFAULT_CACHEMGR_CONFIG)\" $(AM_CXXFLAGS)

LDADD = -L../lib -lmiscutil $(XTRA_LIBS)

EXTRA_DIST = \
	cachemgr.conf

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

# Don't automatically uninstall config files
#	@if test -f $(DESTDIR)$(DEFAULT_CONFIG_FILE) ; then \
#		echo "rm -f $(DESTDIR)$(DEFAULT_CONFIG_FILE)"; \
#		$(RM) -f $(DESTDIR)$(DEFAULT_CONFIG_FILE); \
#	fi

DISTCLEANFILES = 

