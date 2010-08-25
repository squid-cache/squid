include $(top_srcdir)/src/Common.am

EXTRA_DIST = README COPYING config.test negotiate_kerberos_auth.8
SUBDIRS = 

libexec_PROGRAMS = negotiate_kerberos_auth negotiate_kerberos_auth_test

SOURCE = negotiate_kerberos_auth.cc base64.cc base64.h
SOURCE_test = negotiate_kerberos_auth_test.cc base64.cc base64.h

negotiate_kerberos_auth_SOURCES = $(SOURCE)
AM_CPPFLAGS = $(INCLUDES) -I$(srcdir)
negotiate_kerberos_auth_test_SOURCES = $(SOURCE_test)


negotiate_kerberos_auth_LDFLAGS = 
negotiate_kerberos_auth_LDADD = $(COMPAT_LIB) $(XTRA_LIBS) $(KRB5LIBS)
negotiate_kerberos_auth_test_LDFLAGS = 
negotiate_kerberos_auth_test_LDADD = $(COMPAT_LIB) $(XTRA_LIBS) $(KRB5LIBS)

man_MANS = negotiate_kerberos_auth.8
