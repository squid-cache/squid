## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ntlm_smb_lm_auth

ntlm_smb_lm_auth_SOURCES = ntlm_smb_lm_auth.cc
ntlm_smb_lm_auth_LDADD = \
	$(top_builddir)/lib/smblib/libsmblib.la \
	$(top_builddir)/lib/rfcnb/librfcnb.la \
	$(top_builddir)/lib/ntlmauth/libntlmauth.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = required.m4
