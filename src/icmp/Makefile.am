## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

# ICMP Specific Configurations

if ENABLE_PINGER
libexec_PROGRAMS = pinger
else
EXTRA_PROGRAMS = pinger
endif

noinst_LTLIBRARIES = libicmpcore.la libicmp.la

# ICMP API definition ...
libicmpcore_la_SOURCES = \
	Icmp.cc \
	Icmp.h

# Squid Internal ICMP helper interface
libicmp_la_SOURCES = \
	IcmpConfig.cc \
	IcmpConfig.h \
	IcmpSquid.cc \
	IcmpSquid.h \
	net_db.cc \
	net_db.h

libicmp_la_LIBADD= libicmpcore.la

# pinger depends on these but install/dist is done elsewhere.
COPIED_SOURCE= \
	globals.cc \
	SquidConfig.cc \
	tests/stub_HelperChildConfig.cc \
	tests/STUB.h

# ICMP lookup helper
pinger_SOURCES = \
	Icmp.h \
	Icmp4.cc \
	Icmp4.h \
	Icmp6.cc \
	Icmp6.h \
	IcmpPinger.cc \
	IcmpPinger.h \
	pinger.cc
nodist_pinger_SOURCES = $(COPIED_SOURCE)
pinger_LDFLAGS = $(LIBADD_DL)
pinger_LDADD=\
	libicmpcore.la \
	$(top_builddir)/src/ip/libip.la \
	$(top_builddir)/src/sbuf/libsbuf.la \
	$(top_builddir)/src/debug/libdebug.la \
	$(top_builddir)/src/comm/libminimal.la \
	$(top_builddir)/src/time/libtime.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/src/mem/libminimal.la \
	$(LIBCAP_LIBS) \
	$(COMPAT_LIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

CLEANFILES += $(COPIED_SOURCE)

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

## files we need to pull in from other locations
## copied like this to avoid subdir-objects collisions on 'make clean'
globals.cc: $(top_srcdir)/src/globals.h
	cp $(top_builddir)/src/globals.cc $@

SquidConfig.cc: $(top_srcdir)/src/SquidConfig.cc
	cp $(top_srcdir)/src/SquidConfig.cc $@

tests/stub_HelperChildConfig.cc: $(top_srcdir)/src/tests/stub_HelperChildConfig.cc | tests
	cp $(top_srcdir)/src/tests/stub_HelperChildConfig.cc $@

tests/STUB.h: $(top_srcdir)/src/tests/STUB.h | tests
	cp $(top_srcdir)/src/tests/STUB.h $@

tests:
	mkdir -p $@
