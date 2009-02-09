#
#  Makefile for the Squid Portability Library
#

# Housekeeping, shared by all Squid Makefiles.
# TODO: make this set by configure?
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
DEFS = @DEFS@
CLEANFILES = 

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib \
	@SQUID_CPPUNIT_INC@

$(OBJS): $(top_srcdir)/include/version.h $(top_srcdir)/include/autoconf.h

# Ideally this would be 100% inline functions and macro wrappers.

# Port Specific Configurations

noinst_LTLIBRARIES = libcompat.la

libcompat_la_SOURCES = \
	compat.h \
	osdetect.h \
	compat_shared.h \
	fdsetsize.h \
	gnuregex.h \
	stdvarargs.h \
	valgrind.h \
	\
	os/aix.h \
	os/freebsd.h \
	os/hpux.h \
	os/linux.h \
	os/mswin.h \
	os/next.h \
	os/openbsd.h \
	os/qnx.h \
	os/sgi.h \
	os/solaris.h \
	os/sunos.h \
	os/windows.h \
	\
	compat.cc \
	GnuRegex.c


check_PROGRAMS= testHeaders
TESTS= $(check_PROGRAMS)

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/squid-compat/*.h $(top_srcdir)/squid-compat/os/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/squid-compat/" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/squid-compat/os/" || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
