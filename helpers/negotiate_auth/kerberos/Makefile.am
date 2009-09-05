EXTRA_DIST = README NEWS ChangeLog AUTHORS INSTALL
SUBDIRS = 

bin_PROGRAMS = negotiate_kerberos_auth negotiate_kerberos_auth_test

SOURCE = negotiate_kerberos_auth.cc base64.cc base64.h
SOURCE_test = negotiate_kerberos_auth_test.cc base64.cc base64.h
SPNEGO = spnegohelp/derparse.c spnegohelp/derparse.h \
	spnegohelp/spnego.c spnegohelp/spnego.h \
	spnegohelp/spnegohelp.c spnegohelp/spnegohelp.h \
	spnegohelp/spnegparse.c spnegohelp/spnegoparse.h
if HAVE_SPNEGO
negotiate_kerberos_auth_SOURCES = $(SOURCE)
AM_CPPFLAGS = $(KERBINCS) -I.
else
negotiate_kerberos_auth_SOURCES = $(SOURCE) $(SPNEGO)
AM_CPPFLAGS = $(KERBINCS) -I$(srcdir)/spnegohelp -I.
endif
negotiate_kerberos_auth_test_SOURCES = $(SOURCE_test)


negotiate_kerberos_auth_LDFLAGS = 
negotiate_kerberos_auth_LDADD = -L../../../lib -lmiscutil -lm $(KERBLIBS)
negotiate_kerberos_auth_test_LDFLAGS = 
negotiate_kerberos_auth_test_LDADD = -L../../../lib -lmiscutil -lm $(KERBLIBS)

KERBINCS = @KRB5INCS@
KERBLIBS = @KRB5LIBS@
