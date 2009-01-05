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

#EXTRA_PROGRAMS = \
#	testIcmp

noinst_LTLIBRARIES = libip.la

libip_la_SOURCES = \
	QosConfig.h \
	QosConfig.cc


check_PROGRAMS= testHeaders
TESTS= $(check_PROGRAMS)

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/icmp/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/icmp/" || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
