include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

noinst_LTLIBRARIES = libapi.la libstate.la libacls.la

## General data-independent ACL API
libapi_la_SOURCES = \
	Acl.cc \
	Acl.h \
	Checklist.cc \
	Checklist.h

## Data-dependent Squid/transaction state used by specific ACLs.
## Does not refer to specific ACLs to avoid circular dependencies.
libstate_la_SOURCES = \
	Data.h \
	Strategy.h \
	Strategised.cc \
	Strategised.h \
	\
	FilledChecklist.cc \
	FilledChecklist.h

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
	\
	Asn.cc \
	Asn.h \
	Browser.cc \
	Browser.h \
	DestinationAsn.h \
	DestinationDomain.cc \
	DestinationDomain.h \
	DestinationIp.cc \
	DestinationIp.h \
	DomainData.cc \
	DomainData.h \
	ExtUser.cc \
	ExtUser.h \
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
	MaxConnection.cc \
	MaxConnection.h \
	Method.cc \
	MethodData.cc \
	MethodData.h \
	Method.h \
	MyIp.cc \
	MyIp.h \
	MyPort.cc \
	MyPort.h \
	MyPortName.cc \
	MyPortName.h \
	PeerName.cc \
	PeerName.h \
	Protocol.cc \
	ProtocolData.cc \
	ProtocolData.h \
	Protocol.h \
	Referer.cc \
	Referer.h \
	ReplyHeaderStrategy.h \
	ReplyMimeType.cc \
	ReplyMimeType.h \
	RequestHeaderStrategy.h \
	RequestMimeType.cc \
	RequestMimeType.h \
	SourceAsn.h \
	SourceDomain.cc \
	SourceDomain.h \
	SourceIp.cc \
	SourceIp.h \
	Tag.cc \
	Tag.h \
	Url.cc \
	Url.h \
	UrlPath.cc \
	UrlPath.h \
	UrlPort.cc \
	UrlPort.h \
	UserData.cc \
	UserData.h \
	\
	Gadgets.cc \
	Gadgets.h

## Add conditional sources
## TODO: move these to their respectful dirs when those dirs are created

EXTRA_libacls_la_SOURCES =

SSL_ACLS = \
        CertificateData.cc \
        CertificateData.h  \
        Certificate.cc \
        Certificate.h  \
        SslError.cc \
        SslError.h \
        SslErrorData.cc \
        SslErrorData.h

if ENABLE_SSL
libacls_la_SOURCES += $(SSL_ACLS)
endif

EXTRA_libacls_la_SOURCES += $(SSL_ACLS)


ARP_ACLS = Arp.cc Arp.h

if ENABLE_ARP_ACL
libacls_la_SOURCES += $(ARP_ACLS)
endif

EXTRA_libacls_la_SOURCES += $(ARP_ACLS)
