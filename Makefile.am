## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.3 2001/09/25 23:45:12 robertc Exp $
#

AUTOMAKE_OPTIONS = dist-bzip2 subdir-objects VERSION=1.5
DIST_SUBDIRS	= lib snmplib scripts src icons errors contrib
SUBDIRS		= lib @makesnmplib@ scripts src icons errors

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
