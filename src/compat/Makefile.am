#
#  Makefile for the Squid Portability Library
#

# Housekeeping, shared by all Squid Makefiles.
# TODO: make this set by configure?
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
DEFS = @DEFS@
CLEANFILES = 

INCLUDES = -I$(top_srcdir)/src @SQUID_CPPUNIT_INC@ -I$(top_srcdir)/include -I$(top_builddir)/lib
$(OBJS): $(top_srcdir)/include/version.h $(top_srcdir)/include/autoconf.h

# Ideally this would be 100% inline functions and macro wrappers.

# Port Specific Configurations

noinst_LTLIBRARIES = libcompat.la

libcompat_la_SOURCES = \
	compat.h \
	osdetect.h \
	compat_shared.h \
	squid_fdsetsize.h \
	\
	os/squid_aix.h \
	os/squid_freebsd.h \
	os/squid_hpux.h \
	os/squid_linux.h \
	os/squid_mswin.h \
	os/squid_next.h \
	os/squid_openbsd.h \
	os/squid_qnx.h \
	os/squid_sgi.h \
	os/squid_solaris.h \
	os/squid_sunos.h \
	os/squid_windows.h \
	\
	compat.cc


check_PROGRAMS= testHeaders
TESTS= $(check_PROGRAMS)

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/compat/*.h $(top_srcdir)/src/compat/os/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/compat/" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/compat/os/" || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c

#
#testIpAddress_SOURCES= \
#	testIpAddress.cc \
#	testIpAddress.h
#nodist_testIpAddress_SOURCES= \
#	../tests/testMain.cc
#testIpAddress_LDADD= \
#	libip.la \
#	-L$(top_builddir)/lib -lmiscutil \
#	@SQUID_CPPUNIT_LA@ \
#	@SQUID_CPPUNIT_LIBS@
#testIpAddress_LDFLAGS= $(LIBADD_DL)
