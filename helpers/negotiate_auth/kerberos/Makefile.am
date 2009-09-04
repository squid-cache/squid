EXTRA_DIST = configure README NEWS ChangeLog AUTHORS INSTALL
SUBDIRS = 

bin_PROGRAMS = squid_kerb_auth squid_kerb_auth_test

SOURCE = squid_kerb_auth.c base64.c base64.h
SOURCE_test = squid_kerb_auth_test.c base64.c base64.h
SPNEGO = spnegohelp/derparse.c spnegohelp/derparse.h spnegohelp/Makefile spnegohelp/spnego.c spnegohelp/spnego.h spnegohelp/spnegohelp.c spnegohelp/spnegohelp.h spnegohelp/spnegop
if HAVE_SPNEGO
squid_kerb_auth_SOURCES = $(SOURCE)
AM_CPPFLAGS = $(KERBINCS) -I.
else
squid_kerb_auth_SOURCES = $(SOURCE) $(SPNEGO)
AM_CPPFLAGS = $(KERBINCS) -I$(srcdir)/spnegohelp -I.
endif
squid_kerb_auth_test_SOURCES = $(SOURCE_test)


squid_kerb_auth_LDFLAGS = 
squid_kerb_auth_LDADD = -L../../../lib -lmiscutil -lm $(KERBLIBS)
squid_kerb_auth_test_LDFLAGS = 
squid_kerb_auth_test_LDADD = -L../../../lib -lmiscutil -lm $(KERBLIBS)

KERBINCS = @KRB5INCS@
KERBLIBS = @KRB5LIBS@
