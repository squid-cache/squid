## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AUTOMAKE_OPTIONS = dist-bzip2 1.5 foreign
DIST_SUBDIRS	= compat lib libltdl scripts icons errors contrib doc src test-suite tools
SUBDIRS		= compat lib
if ENABLE_LOADABLE_MODULES
SUBDIRS += libltdl
endif
SUBDIRS += scripts icons errors doc src tools test-suite

DISTCLEANFILES = include/stamp-h include/stamp-h[0-9]*
DEFAULT_PINGER = $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`

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

EXTRA_DIST = \
	ChangeLog \
	CONTRIBUTORS \
	COPYING \
	CREDITS \
	INSTALL \
	QUICKSTART \
	README \
	SPONSORS \
	bootstrap.sh \
	po4a.conf

install-pinger:
	chown root $(DESTDIR)$(DEFAULT_PINGER)
	chmod 4711 $(DESTDIR)$(DEFAULT_PINGER)

## hack to insert the test first, before building recursive child directories
check: have-cppunit check-recursive

have-cppunit:
	@if test "$(LIBCPPUNIT_CFLAGS)$(LIBCPPUNIT_LIBS)" = "" ; then \
		echo "FATAL: 'make check' requires cppunit and cppunit development packages. They do not appear to be installed." ; \
		exit 1 ; \
	fi

.PHONY: have-cppunit
