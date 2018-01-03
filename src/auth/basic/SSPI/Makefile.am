## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

if ENABLE_WIN32SPECIFIC
libexec_PROGRAMS = basic_sspi_auth
endif

basic_sspi_auth_SOURCES = \
	basic_sspi_auth.cc \
	valid.cc valid.h
basic_sspi_auth_CXXFLAGS = -Wl,--enable-auto-import
basic_sspi_auth_LDADD = \
	$(top_builddir)/lib/libsspwin32.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-lnetapi32 -ladvapi32 \
	$(XTRA_LIBS)

man_MANS = basic_sspi_auth.8
EXTRA_DIST = basic_sspi_auth.8 required.m4
