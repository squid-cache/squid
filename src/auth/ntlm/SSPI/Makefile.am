## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

man_MANS= ntlm_sspi_auth.8
libexec_PROGRAMS= ntlm_sspi_auth

ntlm_sspi_auth_SOURCES= ntlm_sspi_auth.cc
ntlm_sspi_auth_LDADD= \
	$(top_builddir)/lib/ntlmauth/libntlmauth.la \
	$(top_builddir)/lib/libsspwin32.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	-lnetapi32 \
	-ladvapi32 \
	$(XTRA_LIBS)

EXTRA_DIST= \
	ntlm_sspi_auth.8 \
	required.m4
