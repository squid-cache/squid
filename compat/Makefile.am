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
	-I$(top_builddir)/include \
	-I$(top_builddir)/lib \
	@SQUID_CPPUNIT_INC@

$(OBJS): $(top_srcdir)/include/version.h $(top_srcdir)/include/autoconf.h

# Ideally this would be 100% inline functions and macro wrappers.

# Port Specific Configurations

noinst_LTLIBRARIES = libcompat.la

libcompat_la_SOURCES = \
	assert.h \
	compat.h \
	compat_shared.h \
	fdsetsize.h \
	osdetect.h \
	stdvarargs.h \
	valgrind.h \
	\
	os/aix.h \
	os/dragonfly.h \
	os/freebsd.h \
	os/hpux.h \
	os/linux.h \
	os/mswin.h \
	os/next.h \
	os/openbsd.h \
	os/os2.h \
	os/qnx.h \
	os/sgi.h \
	os/solaris.h \
	os/sunos.h \
	os/windows.h \
	\
	assert.cc \
	compat.cc \
	GnuRegex.h \
	GnuRegex.c


check_PROGRAMS= testHeaders
TESTS= $(check_PROGRAMS)

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/compat/*.h $(top_srcdir)/compat/os/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/compat/" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/compat/os/" || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
