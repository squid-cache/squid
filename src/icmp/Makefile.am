## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

# TODO: get rid of this when config filename is no longer a global constant.
#      its only here so the pinger globals.cc will link.
DEFS += -DDEFAULT_CONFIG_FILE=NULL


# ICMP Specific Configurations

if ENABLE_PINGER
libexec_PROGRAMS = pinger
else
EXTRA_PROGRAMS = pinger
endif

noinst_LTLIBRARIES = libicmpcore.la libicmp.la

# ICMP API definition ...
libicmpcore_la_SOURCES = \
	Icmp.h \
	Icmp.cc

# Squid Internal ICMP helper interface
libicmp_la_SOURCES = \
	IcmpConfig.cc \
	IcmpConfig.h \
	IcmpSquid.h \
	IcmpSquid.cc \
	net_db.h \
	net_db.cc

libicmp_la_LIBADD= libicmpcore.la

# pinger depends on these but install/dist is done elsewhere.
COPIED_SOURCE= \
	debug.cc \
	globals.cc \
	SquidConfig.cc \
	SquidNew.cc \
	stub_HelperChildConfig.cc \
	stub_libmem.cc \
	STUB.h \
	time.cc

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
nodist_pinger_SOURCES = $(COPIED_SOURCE)
pinger_LDFLAGS = $(LIBADD_DL)
pinger_LDADD=\
	libicmpcore.la \
	$(top_builddir)/src/ip/libip.la \
	$(top_builddir)/src/base/libbase.la \
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
debug.cc: $(top_srcdir)/src/debug.cc
	cp $(top_srcdir)/src/debug.cc $@

globals.cc: $(top_srcdir)/src/globals.h
	cp $(top_builddir)/src/globals.cc $@

time.cc: $(top_srcdir)/src/time.cc
	cp $(top_srcdir)/src/time.cc $@

SquidConfig.cc: $(top_srcdir)/src/SquidConfig.cc
	cp $(top_srcdir)/src/SquidConfig.cc $@

SquidNew.cc: $(top_srcdir)/src/SquidNew.cc
	cp $(top_srcdir)/src/SquidNew.cc $@

stub_HelperChildConfig.cc: $(top_srcdir)/src/tests/stub_HelperChildConfig.cc
	cp $(top_srcdir)/src/tests/stub_HelperChildConfig.cc $@

stub_libmem.cc: $(top_srcdir)/src/tests/stub_libmem.cc STUB.h
	cp $(top_srcdir)/src/tests/stub_libmem.cc $@

STUB.h: $(top_srcdir)/src/tests/STUB.h
	cp $(top_srcdir)/src/tests/STUB.h $@
