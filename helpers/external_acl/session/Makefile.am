include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 		= ext_session_acl
man_MANS 			= ext_session_acl.8
EXTRA_DIST			= ext_session_acl.8 required.m4
ext_session_acl_SOURCES		= ext_session_acl.cc

LDADD = \
	$(COMPAT_LIB) \
	$(LIB_DB)
