#
#  Makefile for the Squid Object Cache server
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

AUTOMAKE_OPTIONS = subdir-objects

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

SUBDIRS = 
EXTRA_DIST = 
man_MANS = 
DISTCLEANFILES = 

LDADD = \
	../compat/libcompat.la \
	../src/ip/libip.la \
	-L../lib -lmiscutil \
	$(XTRA_LIBS)

include $(top_srcdir)/doc/manuals/Substitute.am


## ##### squidclient  #####

bin_PROGRAMS = squidclient

squidclient_SOURCES = squidclient.cc

EXTRA_DIST += squidclient.1
man_MANS += squidclient.1



## ##### cachemgr.cgi  #####

DEFAULT_CACHEMGR_CONFIG = $(sysconfdir)/cachemgr.conf

libexec_PROGRAMS = cachemgr$(CGIEXT)

cachemgr__CGIEXT__SOURCES = cachemgr.cc
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
