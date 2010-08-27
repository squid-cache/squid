include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_edirectory_userip_acl

ext_edirectory_userip_acl_SOURCES = \
	edui_config.h main.h edui_util.h iplookup.h \
	main.c edui_util.c iplookup.c

ext_edirectory_userip_acl_LDADD = \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = config.test README ISSUES INSTALL
