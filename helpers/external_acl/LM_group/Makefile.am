include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_lm_group_acl
ext_lm_group_acl_SOURCES = ext_lm_group_acl.cc

LDADD = \
	$(COMPAT_LIB) \
	-lnetapi32 \
	-ladvapi32 \
	-lntdll \
	$(XTRA_LIBS)

man_MANS = ext_lm_group_acl.8

EXTRA_DIST = config.test ext_lm_group_acl.8
