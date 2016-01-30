## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

man_MANS		= basic_pam_auth.8
EXTRA_DIST		= basic_pam_auth.8 required.m4
libexec_PROGRAMS	= basic_pam_auth

basic_pam_auth_SOURCES	= basic_pam_auth.cc
basic_pam_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-lpam \
	$(XTRA_LIBS)
