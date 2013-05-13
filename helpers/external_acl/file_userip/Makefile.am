include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_file_userip_acl
ext_file_userip_acl_SOURCES = ext_file_userip_acl.cc
man_MANS = ext_file_userip_acl.8

EXTRA_DIST = \
	example.conf \
	example-deny_all_but.conf \
	ext_file_userip_acl.8 \
	required.m4

LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
