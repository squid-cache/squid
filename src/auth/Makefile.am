#  Makefile for authentication modules in the Squid Object Cache server
#
#  $Id$
#
AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = @SQUID_CFLAGS@
AM_CXXFLAGS = @SQUID_CXXFLAGS@
CLEANFILES =

EXTRA_LIBRARIES	= libbasic.a libdigest.a libntlm.a libnegotiate.a
noinst_LIBRARIES	= @AUTH_LIBS@

libbasic_a_SOURCES	= basic/auth_basic.cc basic/auth_basic.h
libdigest_a_SOURCES	= digest/auth_digest.cc digest/auth_digest.h
libntlm_a_SOURCES	= ntlm/auth_ntlm.cc ntlm/auth_ntlm.h
libnegotiate_a_SOURCES	= negotiate/auth_negotiate.cc negotiate/auth_negotiate.h negotiate/negotiateScheme.cc negotiate/negotiateScheme.h

INCLUDES = \
	-I$(top_srcdir) \
	-I. \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src

check_PROGRAMS= testHeaders

## Special Universal .h dependency test script
## aborts if error encountered
testHeaders: $(top_srcdir)/src/auth/basic/*.h $(top_srcdir)/src/auth/digest/*.h $(top_srcdir)/src/auth/ntlm/*.h $(top_srcdir)/src/auth/negotiate/*.h
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "basic" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "digest" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "ntlm" || exit 1
	$(SHELL) $(top_srcdir)/test-suite/testheaders.sh "$(CXXCOMPILE)" "negotiate" || exit 1
## ./ has no .h files

## No such file...
testHeaders.c:
	touch testHeaders.c
CLEANFILES += testHeaders.c
