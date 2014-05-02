include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_edirectory_userip_acl

ext_edirectory_userip_acl_SOURCES = \
	ext_edirectory_userip_acl.cc

ext_edirectory_userip_acl_LDADD = \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(XTRA_LIBS)

man_MANS = ext_edirectory_userip_acl.8

EXTRA_DIST = required.m4 ext_edirectory_userip_acl.8
