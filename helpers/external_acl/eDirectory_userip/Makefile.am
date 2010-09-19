include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_edirectory_userip_acl

ext_edirectory_userip_acl_SOURCES = \
	ext_edirectory_userip_acl.c

ext_edirectory_userip_acl_LDADD = \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = config.test
