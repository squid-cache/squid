## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libsslsquid.la libsslutil.la

## SSL stuff used by main Squid but not by certgen helper
libsslsquid_la_SOURCES = \
	Config.cc \
	Config.h \
	ErrorDetail.cc \
	ErrorDetail.h \
	ErrorDetailManager.cc \
	ErrorDetailManager.h \
	PeekingPeerConnector.cc \
	PeekingPeerConnector.h \
	ProxyCerts.h \
	ServerBump.cc \
	ServerBump.h \
	bio.cc \
	bio.h \
	cert_validate_message.cc \
	cert_validate_message.h \
	context_storage.cc \
	context_storage.h \
	helper.cc \
	helper.h \
	support.cc \
	support.h

## SSL stuff used by main Squid and certgen helper
libsslutil_la_SOURCES = \
	crtd_message.cc \
	crtd_message.h \
	gadgets.cc \
	gadgets.h
