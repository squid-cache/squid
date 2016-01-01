## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = negotiate_sspi_auth

negotiate_sspi_auth_SOURCES = negotiate_sspi_auth.cc

LDADD	= \
	-L$(top_builddir)/lib -lsspwin32 \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt required.m4
