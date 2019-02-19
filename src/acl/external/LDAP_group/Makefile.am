## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= ext_ldap_group_acl
man_MANS= ext_ldap_group_acl.8

ext_ldap_group_acl_SOURCES= \
	ext_ldap_group_acl.cc
ext_ldap_group_acl_LDADD= \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(XTRA_LIBS)

EXTRA_DIST= \
	ext_ldap_group_acl.8 \
	required.m4
