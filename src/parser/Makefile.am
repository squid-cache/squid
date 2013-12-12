include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

EXTRA_PROGRAMS = \
	testTokenizer
	
check_PROGRAMS += testTokenizer
TESTS += testTokenizer

noinst_LTLIBRARIES = libsquid-parser.la

libsquid_parser_la_SOURCES = \
	CharacterSet.h \
	Tokenizer.h \
	Tokenizer.cc

SBUF_SOURCE= \
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
	CharacterSet.h \
	$(SBUF_SOURCE) \
	testTokenizer.h \
	testTokenizer.cc \
	Tokenizer.h \
	Tokenizer.cc
nodist_testTokenizer_SOURCES = \
	$(top_srcdir)/src/tests/testMain.cc
testIcmp_LDFLAGS = $(LIBADD_DL)
testIcmp_LDADD = \
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
testIcmp_DEPENDENCIES = $(SQUID_CPPUNIT_LA)
