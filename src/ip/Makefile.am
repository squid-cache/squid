include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libip.la

libip_la_SOURCES = \
	IpAddress.h \
	IpAddress.cc \
	IpIntercept.h \
	IpIntercept.cc \
	QosConfig.h \
	QosConfig.cc


check_PROGRAMS += testIpAddress
TESTS += testIpAddress

testIpAddress_SOURCES= \
	testIpAddress.cc \
	testIpAddress.h
nodist_testIpAddress_SOURCES= \
	../tests/testMain.cc
testIpAddress_LDADD= \
	libip.la \
	$(COMPAT_LIB) \
	@SQUID_CPPUNIT_LA@ \
	@SQUID_CPPUNIT_LIBS@
testIpAddress_LDFLAGS= $(LIBADD_DL)
