include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = basic_getpwname_auth

basic_getpwname_auth_SOURCES = basic_getpwnam_auth.cc
basic_getpwname_auth_LDADD = \
	$(COMPAT_LIB) \
	$(CRYPTLIB)

man_MANS = basic_getpwname_auth.8
