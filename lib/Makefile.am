## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

DIST_SUBDIRS = ntlmauth profiler rfcnb smblib libTrie snmplib
SUBDIRS=
EXTRA_DIST=

if USE_ESI
SUBDIRS += libTrie
endif
if ENABLE_SNMP
SUBDIRS += snmplib
endif
if ENABLE_XPROF_STATS
SUBDIRS += profiler
endif

install: all
install-strip: all

noinst_LTLIBRARIES = \
	libmiscencoding.la \
	libmisccontainers.la \
	libmiscutil.la

#
# Some libraries are only available on Windows
# and others are unable to be built.
#
if ENABLE_WIN32SPECIFIC
noinst_LTLIBRARIES += libsspwin32.la
libsspwin32_la_SOURCES = sspwin32.cc
else
SUBDIRS += rfcnb smblib
EXTRA_DIST += sspwin32.cc
endif
if ENABLE_AUTH_NTLM
SUBDIRS += ntlmauth
endif

#
# dirent.c, encrypt.c and getopt.c are needed for native Windows support.
#
EXTRA_libmiscutil_la_SOURCES = \
	dirent.c \
	encrypt.c \
	getopt.c

libmiscencoding_la_SOURCES = \
	base64.c \
	charset.c \
	html_quote.c \
	md5.c \
	rfc1738.c \
	rfc2617.c \
	uudecode.c

libmisccontainers_la_SOURCES = \
	hash.cc

libmiscutil_la_SOURCES = \
	MemPool.cc \
	MemPoolChunked.cc \
	MemPoolMalloc.cc \
	getfullhostname.c \
	heap.c \
	iso3307.c \
	radix.c \
	rfc1035.c \
	rfc1123.c \
	rfc2671.c \
	rfc3596.c \
	$(SNPRINTFSOURCE) \
	Splay.cc \
	stub_memaccount.c \
	util.c \
	xusleep.c

TESTS += tests/testRFC1035 tests/testRFC1738

check_PROGRAMS += tests/testRFC1035 tests/testRFC1738

tests_testRFC1035_SOURCES= \
	tests/testRFC1035.h \
	tests/testRFC1035.cc

tests_testRFC1035_LDADD= \
	$(SQUID_CPPUNIT_LA) $(SQUID_CPPUNIT_LIBS) \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB)

tests_testRFC1035_LDFLAGS = $(LIBADD_DL)

tests_testRFC1738_SOURCES= \
	tests/testRFC1738.h \
	tests/testRFC1738.cc

tests_testRFC1738_LDADD= \
	$(SQUID_CPPUNIT_LA) $(SQUID_CPPUNIT_LIBS) \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(COMPAT_LIB)

tests_testRFC1738_LDFLAGS = $(LIBADD_DL)


## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/include/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1

TESTS += testHeaders
CLEANFILES += testHeaders
.PHONY: testHeaders
