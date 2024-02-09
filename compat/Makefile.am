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

COMPAT_SSL_ALL_SOURCES = \
	openssl.h

if ENABLE_SSL
COMPAT_SSL_SOURCES = $(COMPAT_SSL_ALL_SOURCES)
else
COMPAT_SSL_SOURCES =
EXCLUDE_FROM_HDR_TESTING += $(COMPAT_SSL_ALL_SOURCES)
endif

noinst_LTLIBRARIES = libcompatsquid.la
libcompatsquid_la_SOURCES = \
	$(COMPAT_SSL_SOURCES) \
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
	initgroups.h \
	krb5.h \
	memrchr.cc \
	memrchr.h \
	mswindows.cc \
	os/aix.h \
	os/android.h \
	os/dragonfly.h \
	os/freebsd.h \
	os/hpux.h \
	os/linux.h \
	os/macosx.h \
	os/mingw.h \
	os/mswindows.h \
	os/netbsd.h \
	os/openbsd.h \
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
