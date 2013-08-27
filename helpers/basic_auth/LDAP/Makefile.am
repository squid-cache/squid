include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 	= basic_ldap_auth
man_MANS 		= basic_ldap_auth.8
EXTRA_DIST		= basic_ldap_auth.8 required.m4
basic_ldap_auth_SOURCES	= basic_ldap_auth.cc

LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB)
