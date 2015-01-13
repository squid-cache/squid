## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

# TODO: get rid of this when config filename is no longer a global constant.
#	its only here so the testIcmp will link .
DEFS += -DDEFAULT_CONFIG_FILE=NULL


# ICMP Specific Configurations

if ENABLE_PINGER
PINGER = pinger
else
PINGER =
endif

EXTRA_PROGRAMS = \
	pinger \
	testIcmp

libexec_PROGRAMS = $(PINGER)

noinst_LTLIBRARIES = libicmp-core.la libicmp.la

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

# ICMP API definition ...
libicmp_core_la_SOURCES = \
	Icmp.h \
	Icmp.cc

# Squid Internal ICMP helper interface
libicmp_la_SOURCES = \
	IcmpConfig.h \
	IcmpSquid.h \
	IcmpSquid.cc \
	net_db.h \
	net_db.cc

# ICMP lookup helper
pinger_SOURCES = \
	Icmp.h \
	IcmpPinger.h \
	IcmpPinger.cc \
	Icmp4.h \
	Icmp4.cc \
	Icmp6.h \
	Icmp6.cc \
	pinger.cc

# depends on these but install/dist is done elsewhere.
# TODO: remove when these are cleaned up in their own way.
nodist_pinger_SOURCES = \
	$(top_srcdir)/src/debug.cc \
	$(top_builddir)/src/globals.cc \
	$(top_srcdir)/src/time.cc \
	$(top_srcdir)/src/SquidConfig.cc \
	$(top_srcdir)/src/SquidNew.cc \
	$(top_srcdir)/src/tests/stub_HelperChildConfig.cc

pinger_LDFLAGS = $(LIBADD_DL)
pinger_LDADD=\
	libicmp-core.la \
	../ip/libip.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)


##install-pinger:
##	@f=$(PINGER_EXE); \
##	if test -f $(libexecdir)/$$f; then \
##		echo $(MV) $(libexecdir)/$$f $(libexecdir)/-$$f; \
##		$(MV) $(libexecdir)/$$f $(libexecdir)/-$$f; \
##	fi; \
##	echo $(INSTALL_SUID) $$f $(libexecdir); \
##	$(INSTALL_SUID) $$f $(libexecdir) || exit 1; \
##	if test -f $(libexecdir)/-$$f; then \
##		echo $(RM) -f $(libexecdir)/-$$f; \
##		$(RM) -f $(libexecdir)/-$$f; \
##	fi


check_PROGRAMS += testIcmp
TESTS += testIcmp

## Tests of the ICMP base module.
# Its used by pinger so SHOULD NOT require more dependancies! :-(
testIcmp_SOURCES = \
	Icmp.h \
	testIcmp.h \
	testIcmp.cc
nodist_testIcmp_SOURCES = \
	$(top_srcdir)/src/SquidTime.h \
	$(top_srcdir)/src/tests/stub_debug.cc \
	$(top_srcdir)/src/time.cc \
	$(top_srcdir)/test-suite/test_tools.cc \
	$(top_builddir)/src/globals.cc
testIcmp_LDFLAGS = $(LIBADD_DL)
testIcmp_LDADD=\
	$(SQUID_CPPUNIT_LIBS) \
	$(SQUID_CPPUNIT_LA) \
	libicmp-core.la \
	../ip/libip.la \
	../base/libbase.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
testIcmp_DEPENDENCIES= $(SQUID_CPPUNIT_LA)
