## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.6 2002/05/06 06:25:14 hno Exp $
#

AUTOMAKE_OPTIONS = dist-bzip2 subdir-objects VERSION=1.5
DIST_SUBDIRS	= lib snmplib scripts src icons errors contrib doc
SUBDIRS		= lib @makesnmplib@ scripts src icons errors doc

DISTCLEANFILES = include/stamp-h include/stamp-h[0-9]*

dist-hook:
	@ for subdir in "include"; do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	    cp -p $(srcdir)/$$subdir/*.h  $(distdir)/$$subdir \
	      || exit 1; \
	    rm $(distdir)/$$subdir/autoconf.h; \
	  fi; \
	done

EXTRA_DIST = \
	ChangeLog \
	CONTRIBUTORS \
	COPYING \
	COPYRIGHT \
	CREDITS \
	INSTALL \
	QUICKSTART \
	README \
	SPONSORS
