include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 		= ext_ldap_group_acl
ext_ldap_group_acl_SOURCES	= ext_ldap_group_acl.cc

man_MANS 			= ext_ldap_group_acl.8
EXTRA_DIST			= ext_ldap_group_acl.8 config.test

LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(XTRA_LIBS)
