include $(top_srcdir)/src/Common.am

libexec_PROGRAMS 		= ext_unix_group_acl
man_MANS 			= ext_unix_group_acl.8
EXTRA_DIST			= ext_unix_group_acl.8 required.m4
ext_unix_group_acl_SOURCES	= check_group.cc

LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
