## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= digest_ldap_auth

digest_ldap_auth_SOURCES= \
	digest_common.h \
	digest_pw_auth.cc \
	ldap_backend.cc \
	ldap_backend.h

digest_ldap_auth_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

EXTRA_DIST= required.m4
