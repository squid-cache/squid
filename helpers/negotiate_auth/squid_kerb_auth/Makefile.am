EXTRA_DIST = configure README NEWS ChangeLog AUTHORS INSTALL
SUBDIRS = 

libexec_PROGRAMS = squid_kerb_auth squid_kerb_auth_test negotiate_kerb_auth negotiate_kerb_auth_test

SPNEGO_SOURCE= \
	spnegohelp/derparse.c \
	spnegohelp/derparse.h \
	spnegohelp/spnego.c \
	spnegohelp/spnego.h \
	spnegohelp/spnegohelp.c \
	spnegohelp/spnegohelp.h \
	spnegohelp/spnegoparse.c \
	spnegohelp/spnegoparse.h

EXTRA_DIST += $(SPNEGO_SOURCE)

if HAVE_SPNEGO
squid_kerb_auth_SOURCES = squid_kerb_auth.c base64.c base64.h squid_compat.h
squid_kerb_auth_test_SOURCES = squid_kerb_auth_test.c base64.c base64.h squid_compat.h
else
squid_kerb_auth_SOURCES = squid_kerb_auth.c base64.c base64.h $(SPNEGO_SOURCE) squid_compat.h
INCLUDES = -Ispnegohelp 
squid_kerb_auth_test_SOURCES = squid_kerb_auth_test.c base64.c base64.h squid_compat.h
endif


squid_kerb_auth_LDFLAGS = 
squid_kerb_auth_LDADD =
squid_kerb_auth_test_LDFLAGS = 
squid_kerb_auth_test_LDADD =
negotiate_kerb_auth_SOURCES = 
negotiate_kerb_auth_test_SOURCES = 

negotiate_kerb_auth: squid_kerb_auth
	cp squid_kerb_auth negotiate_kerb_auth

negotiate_kerb_auth_test: squid_kerb_auth_test
	cp squid_kerb_auth_test negotiate_kerb_auth_test


