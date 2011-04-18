#
#  Makefile for the Squid Portability Library
#

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

# Ideally this would be 100% inline functions and macro wrappers.

# Port Specific Configurations

noinst_LTLIBRARIES = libcompat.la

libcompat_la_SOURCES = \
	assert.h \
	compat.h \
	compat_shared.h \
	fdsetsize.h \
	osdetect.h \
	stdio.h \
	stdvarargs.h \
	valgrind.h \
	\
	os/aix.h \
	os/dragonfly.h \
	os/freebsd.h \
	os/hpux.h \
	os/linux.h \
	os/mswin.h \
	os/macosx.h \
	os/next.h \
	os/openbsd.h \
	os/opensolaris_10_netdb.h \
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

check_PROGRAMS += testPreCompiler
TESTS += testPreCompiler

testPreCompiler_SOURCES= \
	testPreCompiler.h \
	testPreCompiler.cc \
	$(top_srcdir)/src/tests/testMain.cc
testPreCompiler_LDADD= $(SQUID_CPPUNIT_LA) $(SQUID_CPPUNIT_LIBS)
testPreCompiler_LDFLAGS=
