## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
	forward.h \
	InnerNode.cc \
	InnerNode.h \
	Options.h \
	Options.cc \
	Tree.cc \
	Tree.h

## Data-dependent Squid/transaction state used by specific ACLs.
## Does not refer to specific ACLs to avoid circular dependencies.
libstate_la_SOURCES = \
	CharacterSetOption.h \
	Data.h \
	Strategy.h \
	Strategised.cc \
	Strategised.h \
	FilledChecklist.cc \
	FilledChecklist.h \
	Address.h \
	Address.cc

## data-specific ACLs
libacls_la_SOURCES = \
	IntRange.cc \
	IntRange.h \
	RegexData.cc \
	RegexData.h \
	StringData.cc \
	StringData.h \
	Time.cc \
	Time.h \
	TimeData.cc \
	TimeData.h \
	AllOf.cc \
	AllOf.h \
	AnyOf.cc \
	AnyOf.h \
	Asn.cc \
	Asn.h \
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
	HasComponent.cc \
	HasComponent.h \
	HasComponentData.cc \
	HasComponentData.h \
	HierCodeData.cc \
	HierCodeData.h \
	HierCode.cc \
	HierCode.h \
	HttpHeaderData.cc \
	HttpHeaderData.h \
	HttpRepHeader.cc \
	HttpRepHeader.h \
	HttpReqHeader.cc \
	HttpReqHeader.h \
	HttpStatus.cc \
	HttpStatus.h \
	Ip.cc \
	Ip.h \
	LocalIp.cc \
	LocalIp.h \
	LocalPort.cc \
	LocalPort.h \
	MaxConnection.cc \
	MaxConnection.h \
	Method.cc \
	MethodData.cc \
	MethodData.h \
	Method.h \
	MyPortName.cc \
	MyPortName.h \
	Note.h \
	Note.cc \
	NoteData.h \
	NoteData.cc \
	PeerName.cc \
	PeerName.h \
	Protocol.cc \
	ProtocolData.cc \
	ProtocolData.h \
	Protocol.h \
	Random.cc \
	Random.h \
	ReplyHeaderStrategy.h \
	ReplyMimeType.h \
	RequestHeaderStrategy.h \
	RequestMimeType.h \
	SourceAsn.h \
	SourceDomain.cc \
	SourceDomain.h \
	SourceIp.cc \
	SourceIp.h \
	SquidError.h \
	SquidError.cc \
	SquidErrorData.cc \
	SquidErrorData.h \
	Tag.cc \
	Tag.h \
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
	UserData.h \
	AclNameList.h \
	AclDenyInfoList.h \
	Gadgets.cc \
	Gadgets.h \
	AclSizeLimit.cc \
	AclSizeLimit.h

## Add conditional sources
## TODO: move these to their respective dirs when those dirs are created

EXTRA_libacls_la_SOURCES =

SSL_ACLS = \
	AtStep.cc \
	AtStep.h \
	AtStepData.cc \
	AtStepData.h \
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
