## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

SUBDIRS= cert_generators cert_validators

noinst_LTLIBRARIES = libsecurity.la

libsecurity_la_SOURCES= \
	Context.h \
	EncryptorAnswer.cc \
	EncryptorAnswer.h \
	forward.h \
	KeyData.h \
	LockingPointer.h \
	NegotiationHistory.cc \
	NegotiationHistory.h \
	PeerOptions.cc \
	PeerOptions.h \
	ServerOptions.cc \
	ServerOptions.h \
	Session.cc \
	Session.h
