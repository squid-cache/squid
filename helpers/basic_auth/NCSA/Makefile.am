## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS	= basic_ncsa_auth
basic_ncsa_auth_SOURCES	= basic_ncsa_auth.cc crypt_md5.cc crypt_md5.h
man_MANS 		= basic_ncsa_auth.8
EXTRA_DIST		= basic_ncsa_auth.8 required.m4
LDADD = \
	$(top_builddir)/lib/libmisccontainers.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

## we need our local files too (but avoid -I. at all costs)
AM_CPPFLAGS += -I$(srcdir)
