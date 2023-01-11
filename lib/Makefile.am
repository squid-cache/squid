## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

DIST_SUBDIRS = ntlmauth profiler rfcnb smblib libTrie snmplib
SUBDIRS=
EXTRA_DIST=

if ENABLE_ESI
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
EXTRA_DIST += sspwin32.cc
endif
if ENABLE_SMBLIB
# smblib is the only user of the rfcnb library
SUBDIRS += rfcnb smblib
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
	html_quote.c \
	md5.c \
	rfc1738.c \
	rfc2617.c

libmisccontainers_la_SOURCES = \
	hash.cc

libmiscutil_la_SOURCES = \
	$(SNPRINTFSOURCE) \
	Splay.cc \
	getfullhostname.c \
	heap.c \
	iso3307.c \
	radix.c \
	rfc1123.c \
	stub_memaccount.c \
	util.c \
	xusleep.c

TESTS += tests/testRFC1738

check_PROGRAMS += tests/testRFC1738

tests_testRFC1738_SOURCES = \
	tests/testRFC1738.cc \
	tests/testRFC1738.h

tests_testRFC1738_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(LIBCPPUNIT_LIBS) \
	$(COMPAT_LIB)

tests_testRFC1738_LDFLAGS = $(LIBADD_DL)


## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/include/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1

TESTS += testHeaders
CLEANFILES += testHeaders
.PHONY: testHeaders
