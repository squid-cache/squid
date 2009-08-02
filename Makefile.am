## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.27 2006/05/11 01:36:57 hno Exp $
#

AUTOMAKE_OPTIONS = dist-bzip2 subdir-objects 1.5 foreign
DIST_SUBDIRS	= lib snmplib scripts src icons errors contrib doc helpers test-suite tools
SUBDIRS		= lib @makesnmplib@ scripts src icons errors doc helpers test-suite tools

DISTCLEANFILES = include/stamp-h include/stamp-h[0-9]*
DEFAULT_PINGER		= $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`

dist-hook:
	@ for subdir in include; do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	    cp -p $(srcdir)/$$subdir/*.h  $(distdir)/$$subdir \
	      || exit 1; \
	    rm -f $(distdir)/$$subdir/autoconf.h; \
	  fi; \
	done
	@if [ -f $(top_srcdir)/RELEASENOTES.html ]; then \
	  cp -p $(top_srcdir)/RELEASENOTES.html $(distdir)/RELEASENOTES.html; \
	else \
	  cp $(top_srcdir)/doc/release-notes/release-3.0.html $(distdir)/RELEASENOTES.html; \
	fi

EXTRA_DIST = \
	ChangeLog \
	CONTRIBUTORS \
	COPYING \
	COPYRIGHT \
	CREDITS \
	INSTALL \
	QUICKSTART \
	README \
	SPONSORS \
	bootstrap.sh

install-pinger:
	chown root $(DESTDIR)$(DEFAULT_PINGER)
	chmod 4711 $(DESTDIR)$(DEFAULT_PINGER)

all-am:
	@echo "Build Successful."

## hack to insert the test first, before building recursive child directories
check: have-cppunit check-recursive

have-cppunit:
	@if test "@SQUID_CPPUNIT_INC@@SQUID_CPPUNIT_LA@@SQUID_CPPUNIT_LIBS@" = "" ; then \
		echo "FATAL: 'make check' requires cppunit and cppunit development packages. They do not appear to be installed." ; \
		exit 1 ; \
	fi

.PHONY: have-cppunit
