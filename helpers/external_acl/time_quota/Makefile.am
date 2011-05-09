include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 		= ext_time_quota_acl
man_MANS 			= ext_time_quota_acl.8
EXTRA_DIST			= ext_time_quota_acl.8 config.test
ext_time_quota_acl_SOURCES	= ext_time_quota_acl.cc

DEFS += -DDEFAULT_QUOTA_DB=\"$(localstatedir)/ext_time_quota.db\" 

LDADD = \
	$(COMPAT_LIB) \
	$(LIB_DB)
