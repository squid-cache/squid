EXTRA_DIST = reconf configure
SUBDIRS = 

bin_PROGRAMS = squid_kerb_auth squid_kerb_auth_test

if HAVE_SPNEGO
squid_kerb_auth_SOURCES = squid_kerb_auth.c base64.c
squid_kerb_auth_test_SOURCES = squid_kerb_auth_test.c base64.c
else
squid_kerb_auth_SOURCES = squid_kerb_auth.c base64.c spnegohelp/derparse.c  spnegohelp/spnego.c  spnegohelp/spnegohelp.c  spnegohelp/spnegoparse.c
INCLUDES = -Ispnegohelp 
squid_kerb_auth_test_SOURCES = squid_kerb_auth_test.c base64.c
endif


squid_kerb_auth_LDFLAGS = 
squid_kerb_auth_LDADD =
squid_kerb_auth_test_LDFLAGS = 
squid_kerb_auth_test_LDADD =
