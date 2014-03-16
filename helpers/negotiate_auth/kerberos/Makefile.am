include $(top_srcdir)/src/Common.am

EXTRA_DIST = README COPYING required.m4 negotiate_kerberos_auth.8
SUBDIRS = 

libexec_PROGRAMS = negotiate_kerberos_auth negotiate_kerberos_auth_test

AM_CPPFLAGS = $(INCLUDES) -I$(srcdir)

negotiate_kerberos_auth_SOURCES = negotiate_kerberos_auth.cc negotiate_kerberos_pac.cc negotiate_kerberos.h
negotiate_kerberos_auth_LDFLAGS = 
negotiate_kerberos_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(KRB5LIBS) \
	$(XTRA_LIBS)

negotiate_kerberos_auth_test_SOURCES = negotiate_kerberos_auth_test.cc
negotiate_kerberos_auth_test_LDFLAGS = 
negotiate_kerberos_auth_test_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(KRB5LIBS) \
	$(XTRA_LIBS)

man_MANS = negotiate_kerberos_auth.8
