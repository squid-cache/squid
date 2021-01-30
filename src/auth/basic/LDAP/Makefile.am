## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 	= basic_ldap_auth
man_MANS 		= basic_ldap_auth.8
EXTRA_DIST		= basic_ldap_auth.8 required.m4
basic_ldap_auth_SOURCES	= basic_ldap_auth.cc

basic_ldap_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB)
