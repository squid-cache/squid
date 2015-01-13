## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libip.la

libip_la_SOURCES = \
	forward.h \
	Address.h \
	Address.cc \
	Intercept.h \
	Intercept.cc \
	QosConfig.h \
	QosConfig.cc \
	Qos.cci \
	tools.cc \
	tools.h


check_PROGRAMS += testIpAddress
TESTS += testIpAddress

testIpAddress_SOURCES= \
	testAddress.cc \
	testAddress.h
nodist_testIpAddress_SOURCES= \
	$(top_srcdir)/src/tests/stub_debug.cc \
	$(top_srcdir)/src/tests/stub_tools.cc
testIpAddress_LDADD= \
	libip.la \
	../base/libbase.la \
	$(XTRA_LIBS) \
	$(COMPAT_LIB) \
	$(SQUID_CPPUNIT_LA) \
	$(SQUID_CPPUNIT_LIBS)
testIpAddress_LDFLAGS= $(LIBADD_DL)
