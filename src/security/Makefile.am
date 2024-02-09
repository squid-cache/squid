## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

SUBDIRS= . cert_generators cert_validators

noinst_LTLIBRARIES = libsecurity.la libsecuritybase.la

# Pieces linked to both Squid and security helpers
libsecuritybase_la_SOURCES= \
	Algorithms.cc \
	CertAdaptAlgorithm.cc \
	CertAdaptAlgorithm.h \
	CertificateProperties.h \
	CertSignAlgorithm.cc \
	CertSignAlgorithm.h \
	DigestAlgorithm.h

# Pieces only linked to squid binary
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

libsecurity_la_LIBADD= libsecuritybase.la

CertAdaptAlgorithm.cc: CertAdaptAlgorithm.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk <$(srcdir)/CertAdaptAlgorithm.h | sed -e 's%algSet%set%' >$@) || ($(RM) -f $@ && exit 1)

CertSignAlgorithm.cc: CertSignAlgorithm.h $(top_srcdir)/src/mk-string-arrays.awk
	($(AWK) -f $(top_srcdir)/src/mk-string-arrays.awk <$(srcdir)/CertSignAlgorithm.h | sed -e 's%algSign%sign%' >$@) || ($(RM) -f $@ && exit 1)

CLEANFILES += CertAdaptAlgorithm.cc CertSignAlgorithm.cc
