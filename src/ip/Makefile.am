#
#  Makefile for the Squid IP layer API
#

# Housekeeping, shared by all Squid Makefiles.
# TODO: make this set by configure?
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
DEFS = @DEFS@
CLEANFILES = 

INCLUDES = -I$(top_srcdir)/src @SQUID_CPPUNIT_INC@ -I$(top_srcdir)/include -I$(top_builddir)/lib
$(OBJS): $(top_srcdir)/include/version.h $(top_srcdir)/include/autoconf.h


# IP Specific Configurations

noinst_LTLIBRARIES = libip.la

libip_la_SOURCES = \
	IpAddress.h \
	IpAddress.cc \
	IpIntercept.h \
	IpIntercept.cc \
	QosConfig.h \
	QosConfig.cc


check_PROGRAMS= testHeaders testIpAddress
TESTS= $(check_PROGRAMS)

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/ip/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/ip/" || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c


testIpAddress_SOURCES= \
	testIpAddress.cc \
	testIpAddress.h
nodist_testIpAddress_SOURCES= \
	../tests/testMain.cc
testIpAddress_LDADD= \
	libip.la \
	-L$(top_builddir)/lib -lmiscutil \
	@SQUID_CPPUNIT_LA@ \
	@SQUID_CPPUNIT_LIBS@
testIpAddress_LDFLAGS= $(LIBADD_DL)
