## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

SUBDIRS = $(AUTH_MODULES)
DIST_SUBDIRS = basic digest negotiate ntlm

noinst_LTLIBRARIES = libauth.la libacls.la
## not needed? $(AUTH_LIBS_TO_BUILD)
## EXTRA_LTLIBRARIES = libdigest.la libntlm.la libnegotiate.la

## authentication framework; this library is always built
libauth_la_SOURCES = \
	Config.cc \
	Config.h \
	CredentialState.cc \
	CredentialState.h \
	CredentialsCache.cc \
	CredentialsCache.h \
	Gadgets.cc \
	Gadgets.h \
	QueueNode.h \
	Scheme.cc \
	Scheme.h \
	SchemeConfig.cc \
	SchemeConfig.h \
	SchemesConfig.cc \
	SchemesConfig.h \
	State.cc \
	State.h \
	Type.cc \
	Type.h \
	User.cc \
	User.h \
	UserRequest.cc \
	UserRequest.h \
	forward.h \
	toUtf.cc \
	toUtf.h

libauth_la_LIBADD = $(AUTH_LIBS_TO_BUILD)
libauth_la_DEPENDENCIES = $(AUTH_LIBS_TO_BUILD)

## authentication-dependent ACLs and authentication code they share
libacls_la_SOURCES = \
	Acl.cc \
	Acl.h \
	AclMaxUserIp.cc \
	AclMaxUserIp.h \
	AclProxyAuth.cc \
	AclProxyAuth.h \
	AuthAclState.h

CredentialState.cc: CredentialState.h $(top_srcdir)/src/mk-string-arrays.awk
	$(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk < $(srcdir)/CredentialState.h > $@ || (rm -f $@ ; exit 1)

Type.cc: Type.h $(top_srcdir)/src/mk-string-arrays.awk
	$(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk < $(srcdir)/Type.h > $@ || (rm -f $@ ; exit 1)

CLEANFILES += CredentialState.cc Type.cc
