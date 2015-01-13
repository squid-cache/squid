## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

EXTRA_PROGRAMS = \
	testTokenizer
	
check_PROGRAMS += testTokenizer
TESTS += testTokenizer

noinst_LTLIBRARIES = libsquid-parser.la

libsquid_parser_la_SOURCES = \
	Tokenizer.h \
	Tokenizer.cc

SBUF_SOURCE= \
	$(top_srcdir)/src/base/CharacterSet.h \
	$(top_srcdir)/src/SBuf.h \
	$(top_srcdir)/src/SBuf.cc \
	$(top_srcdir)/src/MemBlob.h \
	$(top_srcdir)/src/MemBlob.cc \
	$(top_srcdir)/src/OutOfBoundsException.h \
	$(top_srcdir)/src/SBufExceptions.h \
	$(top_srcdir)/src/SBufExceptions.cc \
	$(top_srcdir)/src/String.cc \
	$(top_srcdir)/src/SquidString.h \
	$(top_srcdir)/src/base/TextException.h \
	$(top_srcdir)/src/base/TextException.cc

testTokenizer_SOURCES = \
	$(SBUF_SOURCE) \
	testTokenizer.h \
	testTokenizer.cc \
	Tokenizer.h
nodist_testTokenizer_SOURCES = \
	$(top_srcdir)/src/tests/stub_mem.cc \
	$(top_srcdir)/src/tests/stub_debug.cc \
	$(top_srcdir)/src/tests/stub_time.cc \
	$(top_srcdir)/src/tests/stub_SBufDetailedStats.cc
testTokenizer_LDFLAGS = $(LIBADD_DL)
testTokenizer_LDADD = \
	libsquid-parser.la \
	$(top_builddir)/lib/libmiscutil.la \
	$(top_builddir)/src/base/libbase.la \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	$(COMPAT_LIB)
testTokenizer_DEPENDENCIES = $(SQUID_CPPUNIT_LA)
