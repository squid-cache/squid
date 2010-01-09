EXTRA_DIST = configure README NEWS ChangeLog AUTHORS INSTALL
SUBDIRS = 

libexec_PROGRAMS = squid_kerb_auth squid_kerb_auth_test negotiate_kerb_auth negotiate_kerb_auth_test

EXTRA_DIST += $(SPNEGO_SOURCE)

squid_kerb_auth_SOURCES = squid_kerb_auth.c base64.c base64.h squid_compat.h
squid_kerb_auth_test_SOURCES = squid_kerb_auth_test.c base64.c base64.h squid_compat.h
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


