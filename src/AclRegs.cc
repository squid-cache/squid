/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

/** This file exists to provide satic registration code to executables
    that need ACLs. We cannot place this code in acl/lib*.la because it
    does not get linked in, because nobody is using these classes by name.
*/

#if USE_ADAPTATION
#include "acl/AdaptationService.h"
#include "acl/AdaptationServiceData.h"
#endif
#include "acl/AllOf.h"
#include "acl/AnyOf.h"
#if USE_SQUID_EUI
#include "acl/Arp.h"
#include "acl/Eui64.h"
#endif
#if USE_OPENSSL
#include "acl/AtStep.h"
#include "acl/AtStepData.h"
#endif
#include "acl/Asn.h"
#include "acl/Browser.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/DestinationAsn.h"
#include "acl/DestinationDomain.h"
#include "acl/DestinationIp.h"
#include "acl/DomainData.h"
#if USE_AUTH
#include "acl/ExtUser.h"
#endif
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "acl/HierCode.h"
#include "acl/HierCodeData.h"
#include "acl/HttpHeaderData.h"
#include "acl/HttpRepHeader.h"
#include "acl/HttpReqHeader.h"
#include "acl/HttpStatus.h"
#include "acl/IntRange.h"
#include "acl/Ip.h"
#include "acl/LocalIp.h"
#include "acl/LocalPort.h"
#include "acl/MaxConnection.h"
#include "acl/Method.h"
#include "acl/MethodData.h"
#include "acl/MyPortName.h"
#include "acl/Note.h"
#include "acl/NoteData.h"
#include "acl/PeerName.h"
#include "acl/Protocol.h"
#include "acl/ProtocolData.h"
#include "acl/Random.h"
#include "acl/Referer.h"
#include "acl/RegexData.h"
#include "acl/ReplyHeaderStrategy.h"
#include "acl/ReplyMimeType.h"
#include "acl/RequestHeaderStrategy.h"
#include "acl/RequestMimeType.h"
#include "acl/SourceAsn.h"
#include "acl/SourceDomain.h"
#include "acl/SourceIp.h"
#if USE_OPENSSL
#include "acl/Certificate.h"
#include "acl/CertificateData.h"
#include "acl/ServerName.h"
#include "acl/SslError.h"
#include "acl/SslErrorData.h"
#endif
#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "acl/StringData.h"
#if USE_OPENSSL
#include "acl/ServerCertificate.h"
#endif
#include "acl/Tag.h"
#include "acl/Time.h"
#include "acl/TimeData.h"
#include "acl/Url.h"
#include "acl/UrlLogin.h"
#include "acl/UrlPath.h"
#include "acl/UrlPort.h"
#include "acl/UserData.h"
#if USE_AUTH
#include "auth/AclMaxUserIp.h"
#include "auth/AclProxyAuth.h"
#endif
#if USE_IDENT
#include "ident/AclIdent.h"
#endif

ACL::Prototype ACLBrowser::RegistryProtoype(&ACLBrowser::RegistryEntry_, "browser");
ACLStrategised<char const *> ACLBrowser::RegistryEntry_(new ACLRegexData, ACLRequestHeaderStrategy<HDR_USER_AGENT>::Instance(), "browser");
ACLFlag  DestinationDomainFlags[] = {ACL_F_NO_LOOKUP, ACL_F_END};
ACL::Prototype ACLDestinationDomain::LiteralRegistryProtoype(&ACLDestinationDomain::LiteralRegistryEntry_, "dstdomain");
ACLStrategised<char const *> ACLDestinationDomain::LiteralRegistryEntry_(new ACLDomainData, ACLDestinationDomainStrategy::Instance(), "dstdomain", DestinationDomainFlags);
ACL::Prototype ACLDestinationDomain::RegexRegistryProtoype(&ACLDestinationDomain::RegexRegistryEntry_, "dstdom_regex");
ACLFlag  DestinationDomainRegexFlags[] = {ACL_F_NO_LOOKUP, ACL_F_REGEX_CASE, ACL_F_END};
ACLStrategised<char const *> ACLDestinationDomain::RegexRegistryEntry_(new ACLRegexData,ACLDestinationDomainStrategy::Instance() ,"dstdom_regex", DestinationDomainRegexFlags);
ACL::Prototype ACLDestinationIP::RegistryProtoype(&ACLDestinationIP::RegistryEntry_, "dst");
ACLDestinationIP ACLDestinationIP::RegistryEntry_;
#if USE_AUTH
ACL::Prototype ACLExtUser::UserRegistryProtoype(&ACLExtUser::UserRegistryEntry_, "ext_user");
ACLExtUser ACLExtUser::UserRegistryEntry_(new ACLUserData, "ext_user");
ACL::Prototype ACLExtUser::RegexRegistryProtoype(&ACLExtUser::RegexRegistryEntry_, "ext_user_regex" );
ACLExtUser ACLExtUser::RegexRegistryEntry_(new ACLRegexData, "ext_user_regex");
#endif
ACL::Prototype ACLHierCode::RegistryProtoype(&ACLHierCode::RegistryEntry_, "hier_code");
ACLStrategised<hier_code> ACLHierCode::RegistryEntry_(new ACLHierCodeData, ACLHierCodeStrategy::Instance(), "hier_code");
ACL::Prototype ACLHTTPRepHeader::RegistryProtoype(&ACLHTTPRepHeader::RegistryEntry_, "rep_header");
ACLStrategised<HttpHeader*> ACLHTTPRepHeader::RegistryEntry_(new ACLHTTPHeaderData, ACLHTTPRepHeaderStrategy::Instance(), "rep_header");
ACL::Prototype ACLHTTPReqHeader::RegistryProtoype(&ACLHTTPReqHeader::RegistryEntry_, "req_header");
ACLStrategised<HttpHeader*> ACLHTTPReqHeader::RegistryEntry_(new ACLHTTPHeaderData, ACLHTTPReqHeaderStrategy::Instance(), "req_header");
ACL::Prototype ACLHTTPStatus::RegistryProtoype(&ACLHTTPStatus::RegistryEntry_, "http_status");
ACLHTTPStatus ACLHTTPStatus::RegistryEntry_("http_status");
ACL::Prototype ACLMaxConnection::RegistryProtoype(&ACLMaxConnection::RegistryEntry_, "maxconn");
ACLMaxConnection ACLMaxConnection::RegistryEntry_("maxconn");
ACL::Prototype ACLMethod::RegistryProtoype(&ACLMethod::RegistryEntry_, "method");
ACLStrategised<HttpRequestMethod> ACLMethod::RegistryEntry_(new ACLMethodData, ACLMethodStrategy::Instance(), "method");
ACL::Prototype ACLLocalIP::RegistryProtoype(&ACLLocalIP::RegistryEntry_, "localip");
ACLLocalIP ACLLocalIP::RegistryEntry_;
ACL::Prototype ACLLocalPort::RegistryProtoype(&ACLLocalPort::RegistryEntry_, "localport");
ACLStrategised<int> ACLLocalPort::RegistryEntry_(new ACLIntRange, ACLLocalPortStrategy::Instance(), "localport");
ACL::Prototype ACLMyPortName::RegistryProtoype(&ACLMyPortName::RegistryEntry_, "myportname");
ACLStrategised<const char *> ACLMyPortName::RegistryEntry_(new ACLStringData, ACLMyPortNameStrategy::Instance(), "myportname");
ACL::Prototype ACLPeerName::RegistryProtoype(&ACLPeerName::RegistryEntry_, "peername");
ACLStrategised<const char *> ACLPeerName::RegistryEntry_(new ACLStringData, ACLPeerNameStrategy::Instance(), "peername");
ACL::Prototype ACLPeerName::RegexRegistryProtoype(&ACLPeerName::RegexRegistryEntry_, "peername_regex");
ACLStrategised<char const *> ACLPeerName::RegexRegistryEntry_(new ACLRegexData, ACLPeerNameStrategy::Instance(), "peername_regex");
ACL::Prototype ACLProtocol::RegistryProtoype(&ACLProtocol::RegistryEntry_, "proto");
ACLStrategised<AnyP::ProtocolType> ACLProtocol::RegistryEntry_(new ACLProtocolData, ACLProtocolStrategy::Instance(), "proto");
ACL::Prototype ACLRandom::RegistryProtoype(&ACLRandom::RegistryEntry_, "random");
ACLRandom ACLRandom::RegistryEntry_("random");
ACL::Prototype ACLReferer::RegistryProtoype(&ACLReferer::RegistryEntry_, "referer_regex");
ACLStrategised<char const *> ACLReferer::RegistryEntry_(new ACLRegexData, ACLRequestHeaderStrategy<HDR_REFERER>::Instance(), "referer_regex");
ACL::Prototype ACLReplyMIMEType::RegistryProtoype(&ACLReplyMIMEType::RegistryEntry_, "rep_mime_type");
ACLStrategised<char const *> ACLReplyMIMEType::RegistryEntry_(new ACLRegexData, ACLReplyHeaderStrategy<HDR_CONTENT_TYPE>::Instance(), "rep_mime_type");
ACL::Prototype ACLRequestMIMEType::RegistryProtoype(&ACLRequestMIMEType::RegistryEntry_, "req_mime_type");
ACLStrategised<char const *> ACLRequestMIMEType::RegistryEntry_(new ACLRegexData, ACLRequestHeaderStrategy<HDR_CONTENT_TYPE>::Instance(), "req_mime_type");
ACL::Prototype ACLSourceDomain::LiteralRegistryProtoype(&ACLSourceDomain::LiteralRegistryEntry_, "srcdomain");
ACLStrategised<char const *> ACLSourceDomain::LiteralRegistryEntry_(new ACLDomainData, ACLSourceDomainStrategy::Instance(), "srcdomain");
ACL::Prototype ACLSourceDomain::RegexRegistryProtoype(&ACLSourceDomain::RegexRegistryEntry_, "srcdom_regex");
ACLStrategised<char const *> ACLSourceDomain::RegexRegistryEntry_(new ACLRegexData,ACLSourceDomainStrategy::Instance() ,"srcdom_regex");
ACL::Prototype ACLSourceIP::RegistryProtoype(&ACLSourceIP::RegistryEntry_, "src");
ACLSourceIP ACLSourceIP::RegistryEntry_;
ACL::Prototype ACLTime::RegistryProtoype(&ACLTime::RegistryEntry_, "time");
ACLStrategised<time_t> ACLTime::RegistryEntry_(new ACLTimeData, ACLTimeStrategy::Instance(), "time");
ACL::Prototype ACLUrl::RegistryProtoype(&ACLUrl::RegistryEntry_, "url_regex");
ACLStrategised<char const *> ACLUrl::RegistryEntry_(new ACLRegexData, ACLUrlStrategy::Instance(), "url_regex");
ACL::Prototype ACLUrlLogin::RegistryProtoype(&ACLUrlLogin::RegistryEntry_, "urllogin");
ACLStrategised<char const *> ACLUrlLogin::RegistryEntry_(new ACLRegexData, ACLUrlLoginStrategy::Instance(), "urllogin");
ACL::Prototype ACLUrlPath::LegacyRegistryProtoype(&ACLUrlPath::RegistryEntry_, "pattern");
ACL::Prototype ACLUrlPath::RegistryProtoype(&ACLUrlPath::RegistryEntry_, "urlpath_regex");
ACLStrategised<char const *> ACLUrlPath::RegistryEntry_(new ACLRegexData, ACLUrlPathStrategy::Instance(), "urlpath_regex");
ACL::Prototype ACLUrlPort::RegistryProtoype(&ACLUrlPort::RegistryEntry_, "port");
ACLStrategised<int> ACLUrlPort::RegistryEntry_(new ACLIntRange, ACLUrlPortStrategy::Instance(), "port");

#if USE_OPENSSL
ACL::Prototype ACLSslError::RegistryProtoype(&ACLSslError::RegistryEntry_, "ssl_error");
ACLStrategised<const Ssl::CertErrors *> ACLSslError::RegistryEntry_(new ACLSslErrorData, ACLSslErrorStrategy::Instance(), "ssl_error");
ACL::Prototype ACLCertificate::UserRegistryProtoype(&ACLCertificate::UserRegistryEntry_, "user_cert");
ACLStrategised<X509 *> ACLCertificate::UserRegistryEntry_(new ACLCertificateData (Ssl::GetX509UserAttribute, "*"), ACLCertificateStrategy::Instance(), "user_cert");
ACL::Prototype ACLCertificate::CARegistryProtoype(&ACLCertificate::CARegistryEntry_, "ca_cert");
ACLStrategised<X509 *> ACLCertificate::CARegistryEntry_(new ACLCertificateData (Ssl::GetX509CAAttribute, "*"), ACLCertificateStrategy::Instance(), "ca_cert");
ACL::Prototype ACLServerCertificate::X509FingerprintRegistryProtoype(&ACLServerCertificate::X509FingerprintRegistryEntry_, "server_cert_fingerprint");
ACLStrategised<X509 *> ACLServerCertificate::X509FingerprintRegistryEntry_(new ACLCertificateData(Ssl::GetX509Fingerprint, "-sha1", true), ACLServerCertificateStrategy::Instance(), "server_cert_fingerprint");

ACL::Prototype ACLAtStep::RegistryProtoype(&ACLAtStep::RegistryEntry_, "at_step");
ACLStrategised<Ssl::BumpStep> ACLAtStep::RegistryEntry_(new ACLAtStepData, ACLAtStepStrategy::Instance(), "at_step");

ACL::Prototype ACLServerName::LiteralRegistryProtoype(&ACLServerName::LiteralRegistryEntry_, "ssl::server_name");
ACLStrategised<char const *> ACLServerName::LiteralRegistryEntry_(new ACLServerNameData, ACLServerNameStrategy::Instance(), "ssl::server_name");
ACL::Prototype ACLServerName::RegexRegistryProtoype(&ACLServerName::RegexRegistryEntry_, "ssl::server_name_regex");
ACLFlag  ServerNameRegexFlags[] = {ACL_F_REGEX_CASE, ACL_F_END};
ACLStrategised<char const *> ACLServerName::RegexRegistryEntry_(new ACLRegexData, ACLServerNameStrategy::Instance(), "ssl::server_name_regex", ServerNameRegexFlags);
#endif

#if USE_SQUID_EUI
ACL::Prototype ACLARP::RegistryProtoype(&ACLARP::RegistryEntry_, "arp");
ACLARP ACLARP::RegistryEntry_("arp");
ACL::Prototype ACLEui64::RegistryProtoype(&ACLEui64::RegistryEntry_, "eui64");
ACLEui64 ACLEui64::RegistryEntry_("eui64");
#endif

#if USE_IDENT
ACL::Prototype ACLIdent::UserRegistryProtoype(&ACLIdent::UserRegistryEntry_, "ident");
ACLIdent ACLIdent::UserRegistryEntry_(new ACLUserData, "ident");
ACL::Prototype ACLIdent::RegexRegistryProtoype(&ACLIdent::RegexRegistryEntry_, "ident_regex" );
ACLIdent ACLIdent::RegexRegistryEntry_(new ACLRegexData, "ident_regex");
#endif

#if USE_AUTH
ACL::Prototype ACLProxyAuth::UserRegistryProtoype(&ACLProxyAuth::UserRegistryEntry_, "proxy_auth");
ACLProxyAuth ACLProxyAuth::UserRegistryEntry_(new ACLUserData, "proxy_auth");
ACL::Prototype ACLProxyAuth::RegexRegistryProtoype(&ACLProxyAuth::RegexRegistryEntry_, "proxy_auth_regex" );
ACLProxyAuth ACLProxyAuth::RegexRegistryEntry_(new ACLRegexData, "proxy_auth_regex");

ACL::Prototype ACLMaxUserIP::RegistryProtoype(&ACLMaxUserIP::RegistryEntry_, "max_user_ip");
ACLMaxUserIP ACLMaxUserIP::RegistryEntry_("max_user_ip");
#endif

ACL::Prototype ACLTag::RegistryProtoype(&ACLTag::RegistryEntry_, "tag");
ACLStrategised<const char *> ACLTag::RegistryEntry_(new ACLStringData, ACLTagStrategy::Instance(), "tag");

ACL::Prototype Acl::AnyOf::RegistryProtoype(&Acl::AnyOf::RegistryEntry_, "any-of");
Acl::AnyOf Acl::AnyOf::RegistryEntry_;

ACL::Prototype Acl::AllOf::RegistryProtoype(&Acl::AllOf::RegistryEntry_, "all-of");
Acl::AllOf Acl::AllOf::RegistryEntry_;

ACL::Prototype ACLNote::RegistryProtoype(&ACLNote::RegistryEntry_, "note");
ACLStrategised<HttpRequest *> ACLNote::RegistryEntry_(new ACLNoteData, ACLNoteStrategy::Instance(), "note");

#if USE_ADAPTATION
ACL::Prototype ACLAdaptationService::RegistryProtoype(&ACLAdaptationService::RegistryEntry_, "adaptation_service");
ACLStrategised<const char *> ACLAdaptationService::RegistryEntry_(new ACLAdaptationServiceData, ACLAdaptationServiceStrategy::Instance(), "adaptation_service");
#endif

