## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libbase.la

libbase_la_SOURCES = \
	AsyncCall.cc \
	AsyncCall.h \
	AsyncCbdataCalls.h \
	AsyncJob.h \
	AsyncJob.cc \
	AsyncJobCalls.h \
	AsyncCallQueue.cc \
	AsyncCallQueue.h \
	CharacterSet.h \
	CharacterSet.cc \
	TidyPointer.h \
	CbcPointer.h \
	InstanceId.h \
	Lock.h \
	LruMap.h \
	RunnersRegistry.cc \
	RunnersRegistry.h \
	Subscription.h \
	TextException.cc \
	TextException.h

EXTRA_PROGRAMS = \
	testCharacterSet

check_PROGRAMS += testCharacterSet
TESTS += testCharacterSet

testCharacterSet_SOURCES = \
	CharacterSet.h \
	testCharacterSet.h \
	testCharacterSet.cc
nodist_testCharacterSet_SOURCES = \
	$(top_srcdir)/src/tests/stub_debug.cc \
	$(top_srcdir)/src/tests/stub_MemBuf.cc \
	$(top_srcdir)/src/tests/stub_cbdata.cc
testCharacterSet_LDFLAGS = $(LIBADD_DL)
testCharacterSet_LDADD=\
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	libbase.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
testCharacterSet_DEPENDENCIES= $(SQUID_CPPUNIT_LA)
