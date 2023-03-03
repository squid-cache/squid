## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

EXTRA_DIST= \
	cert_tool \
	ext_kerberos_ldap_group_acl.8 \
	README \
	required.m4

AM_CPPFLAGS += -I$(srcdir)

libexec_SCRIPTS = cert_tool

libexec_PROGRAMS = ext_kerberos_ldap_group_acl

ext_kerberos_ldap_group_acl_SOURCES = \
	kerberos_ldap_group.cc \
	support.h \
	support_group.cc \
	support_krb5.cc \
	support_ldap.cc \
	support_log.cc \
	support_lserver.cc \
	support_member.cc \
	support_netbios.cc \
	support_resolv.cc \
	support_sasl.cc

ext_kerberos_ldap_group_acl_LDFLAGS =
ext_kerberos_ldap_group_acl_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LIBLDAP_LIBS) \
	$(LIBSASL) \
	$(KRB5LIBS) \
	$(XTRA_LIBS)
