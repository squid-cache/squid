## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)

if ENABLE_WIN32SPECIFIC
libexec_PROGRAMS = basic_sspi_auth
endif

basic_sspi_auth_SOURCES = \
	basic_sspi_auth.cc \
	valid.cc valid.h
basic_sspi_auth_CXXFLAGS = -Wl,--enable-auto-import
basic_sspi_auth_LDADD = \
	$(COMPAT_LIB) \
	-L$(top_builddir)/lib \
	-lsspwin32 \
	-lmiscencoding \
	-lnetapi32 -ladvapi32 \
	$(XTRA_LIBS)

man_MANS = basic_sspi_auth.8
EXTRA_DIST = basic_sspi_auth.8 required.m4
