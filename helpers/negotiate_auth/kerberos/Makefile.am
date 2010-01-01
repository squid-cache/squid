include $(top_srcdir)/src/Common.am

EXTRA_DIST = README COPYING config.test
SUBDIRS = 

libexec_PROGRAMS = negotiate_kerberos_auth negotiate_kerberos_auth_test

SOURCE = negotiate_kerberos_auth.cc base64.cc base64.h
SOURCE_test = negotiate_kerberos_auth_test.cc base64.cc base64.h
SPNEGO = \
	spnegohelp/derparse.cc spnegohelp/derparse.h \
	spnegohelp/spnego.cc spnegohelp/spnego.h \
	spnegohelp/spnegohelp.cc spnegohelp/spnegohelp.h \
	spnegohelp/spnegoparse.cc spnegohelp/spnegoparse.h

if HAVE_SPNEGO
negotiate_kerberos_auth_SOURCES = $(SOURCE)
AM_CPPFLAGS = $(INCLUDES) -I$(srcdir)
else
negotiate_kerberos_auth_SOURCES = $(SOURCE) $(SPNEGO)
AM_CPPFLAGS = $(INCLUDES) -I$(srcdir)/spnegohelp -I$(srcdir)
endif
negotiate_kerberos_auth_test_SOURCES = $(SOURCE_test)


negotiate_kerberos_auth_LDFLAGS = 
negotiate_kerberos_auth_LDADD = $(COMPAT_LIB) $(XTRA_LIBS) $(KRB5LIBS)
negotiate_kerberos_auth_test_LDFLAGS = 
negotiate_kerberos_auth_test_LDADD = $(COMPAT_LIB) $(XTRA_LIBS) $(KRB5LIBS)
