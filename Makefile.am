## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.2 2001/09/02 12:16:54 robertc Exp $
#

AUTOMAKE_OPTIONS = dist-bzip2 subdir-objects VERSION=1.5
DIST_SUBDIRS	= lib snmplib scripts src icons errors contrib
SUBDIRS		= lib @makesnmplib@ scripts src icons errors

EXTRA_DIST = include/config.h.in
DISTCLEANFILES = include/stamp-h include/stamp-h[0-9]*

dist-hook:
	@ for subdir in "include"; do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	    cp -p $(srcdir)/$$subdir/*.h  $(distdir)/$$subdir \
	      || exit 1; \
	  fi; \
	done

##&&  cp -p $(srcdir)/$$subdir/*.in  $(distdir)/$$subdir
