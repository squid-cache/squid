include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = basic_getpwnam_auth

basic_getpwnam_auth_SOURCES = basic_getpwnam_auth.cc
basic_getpwnam_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(CRYPTLIB)

man_MANS = basic_getpwnam_auth.8

EXTRA_DIST = basic_getpwnam_auth.8 required.m4
