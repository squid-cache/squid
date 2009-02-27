include $(top_srcdir)/src/Common.am

EXTRA_LIBRARIES	= libbasic.a libdigest.a libntlm.a libnegotiate.a
noinst_LIBRARIES = libauth.a @AUTH_LIBS_TO_BUILD@

## authentication framework; this library is always built
## TODO: use libtool and add @AUTH_LIBS_TO_BUILD@ to libauth.la
libauth_a_SOURCES = \
	Config.cc \
	Config.h \
	Scheme.cc \
	Scheme.h \
	User.h \
	User.cci \
	User.cc \
	UserRequest.h \
	UserRequest.cc

libbasic_a_SOURCES = \
	basic/basicScheme.cc \
	basic/basicScheme.h \
	basic/auth_basic.cc \
	basic/auth_basic.h

libdigest_a_SOURCES = \
	digest/digestScheme.cc \
	digest/digestScheme.h \
	digest/auth_digest.cc \
	digest/auth_digest.h

libntlm_a_SOURCES = \
	ntlm/ntlmScheme.cc \
	ntlm/ntlmScheme.h \
	ntlm/auth_ntlm.cc \
	ntlm/auth_ntlm.h

libnegotiate_a_SOURCES = \
	negotiate/negotiateScheme.cc \
	negotiate/negotiateScheme.h \
	negotiate/auth_negotiate.cc \
	negotiate/auth_negotiate.h

# TODO: fix #include statements so that this is not needed
INCLUDES += -I.


check_PROGRAMS += testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/auth/*.h $(top_srcdir)/src/auth/basic/*.h $(top_srcdir)/src/auth/digest/*.h $(top_srcdir)/src/auth/ntlm/*.h $(top_srcdir)/src/auth/negotiate/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/auth/" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/auth/basic" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/auth/digest" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/auth/ntlm" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "$(top_srcdir)/src/auth/negotiate" || exit 1

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
