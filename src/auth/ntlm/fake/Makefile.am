## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= ntlm_fake_auth

ntlm_fake_auth_SOURCES = ntlm_fake_auth.cc
ntlm_fake_auth_LDADD= \
	$(top_builddir)/src/anyp/libanyp.la \
	$(top_builddir)/src/sbuf/libsbuf.la \
	$(top_builddir)/src/debug/libdebug.la \
	$(top_builddir)/src/error/liberror.la \
	$(top_builddir)/src/comm/libminimal.la \
	$(top_builddir)/src/mem/libminimal.la \
	$(top_builddir)/src/base/libbase.la \
	$(top_builddir)/src/time/libtime.la \
	$(top_builddir)/lib/ntlmauth/libntlmauth.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LIBNETTLE_LIBS) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

## Demo using perl.
## ntlm_fake_auth.pl: ntlm_fake_auth.pl.in
##	$(subst_perlshell)

EXTRA_DIST= \
	ntlm_fake_auth.pl.in \
	required.m4
