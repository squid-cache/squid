#
#  Makefile for the Squid Portability Library
#

include $(top_srcdir)/src/Common.am


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

check_PROGRAMS += testPreCompiler
TESTS += testPreCompiler

testPreCompiler_SOURCES= \
	testPreCompiler.h \
	testPreCompiler.cc \
	$(top_srcdir)/src/tests/testMain.cc
testPreCompiler_LDADD= $(SQUID_CPPUNIT_LA) $(SQUID_CPPUNIT_LIBS)
testPreCompiler_LDFLAGS=

# os/ subdir prevents us using src/TestHeaders.am
#
TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/*.h $(srcdir)/os/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(srcdir)/os" || exit 1

CLEANFILES += testHeaders

.PHONY: testHeaders
