## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

SUBDIRS = \
	cert_generators \
	cert_validators

noinst_LTLIBRARIES = libsecurity.la

libsecurity_la_SOURCES = \
	BlindPeerConnector.cc \
	BlindPeerConnector.h \
	CertError.h \
	Certificate.cc \
	Certificate.h \
	CommunicationSecrets.cc \
	CommunicationSecrets.h \
	Context.h \
	EncryptorAnswer.cc \
	EncryptorAnswer.h \
	ErrorDetail.cc \
	ErrorDetail.h \
	Handshake.cc \
	Handshake.h \
	Io.cc \
	Io.h \
	KeyData.cc \
	KeyData.h \
	KeyLog.cc \
	KeyLog.h \
	KeyLogger.cc \
	KeyLogger.h \
	LockingPointer.h \
	NegotiationHistory.cc \
	NegotiationHistory.h \
	PeerConnector.cc \
	PeerConnector.h \
	PeerOptions.cc \
	PeerOptions.h \
	ServerOptions.cc \
	ServerOptions.h \
	Session.cc \
	Session.h \
	forward.h
