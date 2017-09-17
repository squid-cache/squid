## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = negotiate_sspi_auth

man_MANS = negotiate_sspi_auth.8

negotiate_sspi_auth_SOURCES = \
	negotiate_sspi_auth.cc
negotiate_sspi_auth_LDADD = \
	$(top_builddir)/lib/libsspwin32.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST= \
	negotiate_sspi_auth.8 \
	required.m4
