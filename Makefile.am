## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.13 2002/08/31 13:16:13 robertc Exp $
#

AUTOMAKE_OPTIONS = dist-bzip2 subdir-objects 1.5
DIST_SUBDIRS	= lib snmplib scripts src icons errors contrib doc helpers
SUBDIRS		= lib @makesnmplib@ scripts src icons errors doc helpers

DISTCLEANFILES = include/stamp-h include/stamp-h[0-9]*

dist-hook:
	@ for subdir in "include"; do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	    cp -p $(srcdir)/$$subdir/*.h  $(distdir)/$$subdir \
	      || exit 1; \
	    rm -f $(distdir)/$$subdir/autoconf.h; \
	  fi; \
	done
	cp $(top_srcdir)/doc/release-notes/release-2.5.html $(distdir)/RELEASENOTES.html

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
	chown root $(libexecdir)/pinger$(EXEEXT)
	chmod 4711 $(libexecdir)/pinger$(EXEEXT)
