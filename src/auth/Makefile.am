include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

noinst_LTLIBRARIES = libauth.la libacls.la $(AUTH_LIBS_TO_BUILD)
EXTRA_LTLIBRARIES = libbasic.la libdigest.la libntlm.la libnegotiate.la

## authentication framework; this library is always built
libauth_la_SOURCES = \
	AuthType.h \
	AuthType.cc \
	Config.cc \
	Config.h \
	Gadgets.cc \
	Gadgets.h \
	Scheme.cc \
	Scheme.h \
	State.h \
	State.cc \
	User.h \
	User.cci \
	User.cc \
	UserRequest.h \
	UserRequest.cc

libauth_la_LIBADD = $(AUTH_LIBS_TO_BUILD)
libauth_la_DEPENDENCIES = $(AUTH_LIBS_TO_BUILD)

## authentication-dependent ACLs and authentication code they share
libacls_la_SOURCES = \
	Acl.cc \
	Acl.h \
	\
	AclMaxUserIp.cc \
	AclMaxUserIp.h \
	AclProxyAuth.cc \
	AclProxyAuth.h \
	AuthAclState.h

libbasic_la_SOURCES = \
	basic/basicScheme.cc \
	basic/basicScheme.h \
	basic/auth_basic.cc \
	basic/auth_basic.h \
	basic/basicUserRequest.cc \
	basic/basicUserRequest.h

libdigest_la_SOURCES = \
	digest/digestScheme.cc \
	digest/digestScheme.h \
	digest/auth_digest.cc \
	digest/auth_digest.h \
	digest/digestUserRequest.cc \
	digest/digestUserRequest.h

libntlm_la_SOURCES = \
	ntlm/ntlmScheme.cc \
	ntlm/ntlmScheme.h \
	ntlm/auth_ntlm.cc \
	ntlm/auth_ntlm.h \
	ntlm/ntlmUserRequest.cc \
	ntlm/ntlmUserRequest.h

libnegotiate_la_SOURCES = \
	negotiate/negotiateScheme.cc \
	negotiate/negotiateScheme.h \
	negotiate/auth_negotiate.cc \
	negotiate/auth_negotiate.h \
	negotiate/negotiateUserRequest.cc \
	negotiate/negotiateUserRequest.h

AuthType.cc: AuthType.h $(top_srcdir)/src/mk-string-arrays.awk
	$(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk < $(srcdir)/AuthType.h > $@ || (rm -f $@ ; exit 1)

CLEANFILES += AuthType.cc


TESTS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/auth/*.h $(top_srcdir)/src/auth/basic/*.h $(top_srcdir)/src/auth/digest/*.h $(top_srcdir)/src/auth/ntlm/*.h $(top_srcdir)/src/auth/negotiate/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" $^ || exit 1

CLEANFILES += testHeaders
.PHONY: testHeaders
