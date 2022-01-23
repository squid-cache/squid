## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

SUBDIRS= external

noinst_LTLIBRARIES = libapi.la libstate.la libacls.la

## General data-independent ACL API
libapi_la_SOURCES = \
	Acl.cc \
	Acl.h \
	BoolOps.cc \
	BoolOps.h \
	Checklist.cc \
	Checklist.h \
	InnerNode.cc \
	InnerNode.h \
	Options.cc \
	Options.h \
	Tree.cc \
	Tree.h \
	forward.h

## Data-dependent Squid/transaction state used by specific ACLs.
## Does not refer to specific ACLs to avoid circular dependencies.
libstate_la_SOURCES = \
	Address.cc \
	Address.h \
	CharacterSetOption.h \
	Data.h \
	FilledChecklist.cc \
	FilledChecklist.h \
	Strategised.cc \
	Strategised.h \
	Strategy.h

## data-specific ACLs
libacls_la_SOURCES = \
	AclDenyInfoList.h \
	AclSizeLimit.cc \
	AclSizeLimit.h \
	AllOf.cc \
	AllOf.h \
	AnnotateClient.cc \
	AnnotateClient.h \
	AnnotateTransaction.cc \
	AnnotateTransaction.h \
	AnnotationData.cc \
	AnnotationData.h \
	AnyOf.cc \
	AnyOf.h \
	Asn.cc \
	Asn.h \
	AtStep.cc \
	AtStep.h \
	AtStepData.cc \
	AtStepData.h \
	ConnMark.cc \
	ConnMark.h \
	ConnectionsEncrypted.cc \
	ConnectionsEncrypted.h \
	DestinationAsn.h \
	DestinationDomain.cc \
	DestinationDomain.h \
	DestinationIp.cc \
	DestinationIp.h \
	DomainData.cc \
	DomainData.h \
	ExtUser.cc \
	ExtUser.h \
	Gadgets.cc \
	Gadgets.h \
	HasComponent.cc \
	HasComponent.h \
	HasComponentData.cc \
	HasComponentData.h \
	HierCode.cc \
	HierCode.h \
	HierCodeData.cc \
	HierCodeData.h \
	HttpHeaderData.cc \
	HttpHeaderData.h \
	HttpRepHeader.cc \
	HttpRepHeader.h \
	HttpReqHeader.cc \
	HttpReqHeader.h \
	HttpStatus.cc \
	HttpStatus.h \
	IntRange.cc \
	IntRange.h \
	Ip.cc \
	Ip.h \
	LocalIp.cc \
	LocalIp.h \
	LocalPort.cc \
	LocalPort.h \
	MaxConnection.cc \
	MaxConnection.h \
	Method.cc \
	Method.h \
	MethodData.cc \
	MethodData.h \
	MyPortName.cc \
	MyPortName.h \
	Note.cc \
	Note.h \
	NoteData.cc \
	NoteData.h \
	PeerName.cc \
	PeerName.h \
	Protocol.cc \
	Protocol.h \
	ProtocolData.cc \
	ProtocolData.h \
	Random.cc \
	Random.h \
	RegexData.cc \
	RegexData.h \
	ReplyHeaderStrategy.h \
	ReplyMimeType.h \
	RequestHeaderStrategy.h \
	RequestMimeType.h \
	SourceAsn.h \
	SourceDomain.cc \
	SourceDomain.h \
	SourceIp.cc \
	SourceIp.h \
	SquidError.cc \
	SquidError.h \
	SquidErrorData.cc \
	SquidErrorData.h \
	StringData.cc \
	StringData.h \
	Tag.cc \
	Tag.h \
	Time.cc \
	Time.h \
	TimeData.cc \
	TimeData.h \
	TransactionInitiator.cc \
	TransactionInitiator.h \
	Url.cc \
	Url.h \
	UrlLogin.cc \
	UrlLogin.h \
	UrlPath.cc \
	UrlPath.h \
	UrlPort.cc \
	UrlPort.h \
	UserData.cc \
	UserData.h

## Add conditional sources
## TODO: move these to their respective dirs when those dirs are created

EXTRA_libacls_la_SOURCES =

SSL_ACLS = \
        CertificateData.cc \
        CertificateData.h  \
        Certificate.cc \
        Certificate.h  \
	ServerCertificate.cc \
	ServerCertificate.h \
	ServerName.cc \
	ServerName.h \
        SslError.cc \
        SslError.h \
        SslErrorData.cc \
        SslErrorData.h

if ENABLE_SSL
libacls_la_SOURCES += $(SSL_ACLS)
endif
EXTRA_libacls_la_SOURCES += $(SSL_ACLS)

ADAPT_ACLS= \
	AdaptationService.h \
	AdaptationService.cc \
	AdaptationServiceData.h \
	AdaptationServiceData.cc

if ENABLE_ADAPTATION
libacls_la_SOURCES += $(ADAPT_ACLS)
endif
EXTRA_libacls_la_SOURCES += $(ADAPT_ACLS)

ARP_ACLS = Arp.cc Arp.h Eui64.cc Eui64.h

if ENABLE_EUI
libacls_la_SOURCES += $(ARP_ACLS)
endif
EXTRA_libacls_la_SOURCES += $(ARP_ACLS)
