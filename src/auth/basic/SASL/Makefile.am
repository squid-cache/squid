## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

man_MANS= basic_sasl_auth.8
libexec_PROGRAMS= basic_sasl_auth

basic_sasl_auth_SOURCES = \
	basic_sasl_auth.cc
basic_sasl_auth_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LIBSASL) \
	$(XTRA_LIBS)

EXTRA_DIST= \
	basic_sasl_auth.8 \
	basic_sasl_auth.conf \
	basic_sasl_auth.pam \
	required.m4
