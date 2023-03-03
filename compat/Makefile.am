## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.

#
#  Makefile for the Squid Portability Library
#

include $(top_srcdir)/src/Common.am

# Ideally this would be 100% inline functions and macro wrappers.

# Port Specific Configurations

noinst_LTLIBRARIES = libcompatsquid.la
libcompatsquid_la_SOURCES = \
	assert.cc \
	assert.h \
	cmsg.h \
	compat.cc \
	compat.h \
	compat_shared.h \
	cppunit.h \
	cpu.h \
	debug.cc \
	debug.h \
	eui64_aton.c \
	eui64_aton.h \
	fdsetsize.h \
	getaddrinfo.cc \
	getaddrinfo.h \
	getnameinfo.cc \
	getnameinfo.h \
	inet_ntop.cc \
	inet_ntop.h \
	inet_pton.cc \
	inet_pton.h \
	initgroups.h \
	krb5.h \
	memrchr.cc \
	memrchr.h \
	mswindows.cc \
	openssl.h \
	os/aix.h \
	os/android.h \
	os/dragonfly.h \
	os/freebsd.h \
	os/hpux.h \
	os/linux.h \
	os/macosx.h \
	os/mswindows.h \
	os/netbsd.h \
	os/openbsd.h \
	os/opensolaris_10_netdb.h \
	os/os2.h \
	os/qnx.h \
	os/sgi.h \
	os/solaris.h \
	os/sunos.h \
	osdetect.h \
	psignal.h \
	shm.cc \
	shm.h \
	statvfs.cc \
	statvfs.h \
	stdio.h \
	stdvarargs.h \
	strnrchr.c \
	strnrchr.h \
	strnstr.cc \
	strtoll.h \
	tempnam.h \
	types.h \
	valgrind.h \
	xalloc.cc \
	xalloc.h \
	xis.h \
	xstrerror.cc \
	xstrerror.h \
	xstring.cc \
	xstring.h \
	xstrto.cc \
	xstrto.h

libcompatsquid_la_LIBADD= $(LTLIBOBJS)

check_PROGRAMS += testPreCompiler
TESTS += testPreCompiler

testPreCompiler_SOURCES = \
	testPreCompiler.cc \
	testPreCompiler.h
testPreCompiler_LDADD= $(LIBCPPUNIT_LIBS)
testPreCompiler_LDFLAGS=

# os/ subdir prevents us using src/TestHeaders.am
#
TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(srcdir)/*.h $(srcdir)/os/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1

CLEANFILES += testHeaders

.PHONY: testHeaders
