#include "squid.h"

/** This file exists to provide satic registration code to executables
    that need ACLs. We cannot place this code in acl/lib*.la because it
    does not get linked in, because nobody is using these classes by name.
*/

#include "acl/Acl.h"
#ifdef USE_ARP_ACL
#include "acl/Arp.h"
#endif
#include "acl/Asn.h"
#include "acl/Browser.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/DestinationAsn.h"
#include "acl/DestinationDomain.h"
#include "acl/DestinationIp.h"
#include "acl/DomainData.h"
#include "acl/ExtUser.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "acl/HttpHeaderData.h"
#include "acl/HttpRepHeader.h"
#include "acl/HttpReqHeader.h"
#include "acl/HttpStatus.h"
#include "acl/IntRange.h"
#include "acl/Ip.h"
#include "acl/MaxConnection.h"
#include "acl/MethodData.h"
#include "acl/Method.h"
#include "acl/MyIp.h"
#include "acl/MyPort.h"
#include "acl/MyPortName.h"
#include "acl/PeerName.h"
#include "acl/ProtocolData.h"
#include "acl/Protocol.h"
#include "acl/Referer.h"
#include "acl/RegexData.h"
#include "acl/ReplyHeaderStrategy.h"
#include "acl/ReplyMimeType.h"
#include "acl/RequestHeaderStrategy.h"
#include "acl/RequestMimeType.h"
#include "acl/SourceAsn.h"
#include "acl/SourceDomain.h"
#include "acl/SourceIp.h"
#ifdef USE_SSL
#include "acl/SslErrorData.h"
#include "acl/SslError.h"
#include "acl/CertificateData.h"
#include "acl/Certificate.h"
#endif
#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "acl/StringData.h"
#include "acl/Tag.h"
#include "acl/TimeData.h"
#include "acl/Time.h"
#include "acl/Url.h"
#include "acl/UrlPath.h"
#include "acl/UrlPort.h"
#include "acl/UserData.h"
#include "auth/AclProxyAuth.h"
#include "auth/AclMaxUserIp.h"
#if USE_IDENT
#include "ident/AclIdent.h"
#endif


ACL::Prototype ACLBrowser::RegistryProtoype(&ACLBrowser::RegistryEntry_, "browser");
ACLStrategised<char const *> ACLBrowser::RegistryEntry_(new ACLRegexData, ACLRequestHeaderStrategy<HDR_USER_AGENT>::Instance(), "browser");
ACL::Prototype ACLDestinationDomain::LiteralRegistryProtoype(&ACLDestinationDomain::LiteralRegistryEntry_, "dstdomain");
ACLStrategised<char const *> ACLDestinationDomain::LiteralRegistryEntry_(new ACLDomainData, ACLDestinationDomainStrategy::Instance(), "dstdomain");
ACL::Prototype ACLDestinationDomain::RegexRegistryProtoype(&ACLDestinationDomain::RegexRegistryEntry_, "dstdom_regex");
ACLStrategised<char const *> ACLDestinationDomain::RegexRegistryEntry_(new ACLRegexData,ACLDestinationDomainStrategy::Instance() ,"dstdom_regex");
ACL::Prototype ACLDestinationIP::RegistryProtoype(&ACLDestinationIP::RegistryEntry_, "dst");
ACLDestinationIP ACLDestinationIP::RegistryEntry_;
ACL::Prototype ACLExtUser::UserRegistryProtoype(&ACLExtUser::UserRegistryEntry_, "ext_user");
ACLExtUser ACLExtUser::UserRegistryEntry_(new ACLUserData, "ext_user");
ACL::Prototype ACLExtUser::RegexRegistryProtoype(&ACLExtUser::RegexRegistryEntry_, "ext_user_regex" );
ACLExtUser ACLExtUser::RegexRegistryEntry_(new ACLRegexData, "ext_user_regex");
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
ACL::Prototype ACLMyIP::RegistryProtoype(&ACLMyIP::RegistryEntry_, "myip");
ACLMyIP ACLMyIP::RegistryEntry_;
ACL::Prototype ACLMyPort::RegistryProtoype(&ACLMyPort::RegistryEntry_, "myport");
ACLStrategised<int> ACLMyPort::RegistryEntry_(new ACLIntRange, ACLMyPortStrategy::Instance(), "myport");
ACL::Prototype ACLMyPortName::RegistryProtoype(&ACLMyPortName::RegistryEntry_, "myportname");
ACLStrategised<const char *> ACLMyPortName::RegistryEntry_(new ACLStringData, ACLMyPortNameStrategy::Instance(), "myportname");
ACL::Prototype ACLPeerName::RegistryProtoype(&ACLPeerName::RegistryEntry_, "peername");
ACLStrategised<const char *> ACLPeerName::RegistryEntry_(new ACLStringData, ACLPeerNameStrategy::Instance(), "peername");
ACL::Prototype ACLProtocol::RegistryProtoype(&ACLProtocol::RegistryEntry_, "proto");
ACLStrategised<protocol_t> ACLProtocol::RegistryEntry_(new ACLProtocolData, ACLProtocolStrategy::Instance(), "proto");
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
ACL::Prototype ACLUrlPath::LegacyRegistryProtoype(&ACLUrlPath::RegistryEntry_, "pattern");
ACL::Prototype ACLUrlPath::RegistryProtoype(&ACLUrlPath::RegistryEntry_, "urlpath_regex");
ACLStrategised<char const *> ACLUrlPath::RegistryEntry_(new ACLRegexData, ACLUrlPathStrategy::Instance(), "urlpath_regex");
ACL::Prototype ACLUrlPort::RegistryProtoype(&ACLUrlPort::RegistryEntry_, "port");
ACLStrategised<int> ACLUrlPort::RegistryEntry_(new ACLIntRange, ACLUrlPortStrategy::Instance(), "port");

#ifdef USE_SSL
ACL::Prototype ACLSslError::RegistryProtoype(&ACLSslError::RegistryEntry_, "ssl_error");
ACLStrategised<int> ACLSslError::RegistryEntry_(new ACLSslErrorData, ACLSslErrorStrategy::Instance(), "ssl_error");
ACL::Prototype ACLCertificate::UserRegistryProtoype(&ACLCertificate::UserRegistryEntry_, "user_cert");
ACLStrategised<SSL *> ACLCertificate::UserRegistryEntry_(new ACLCertificateData (sslGetUserAttribute), ACLCertificateStrategy::Instance(), "user_cert");
ACL::Prototype ACLCertificate::CARegistryProtoype(&ACLCertificate::CARegistryEntry_, "ca_cert");
ACLStrategised<SSL *> ACLCertificate::CARegistryEntry_(new ACLCertificateData (sslGetCAAttribute), ACLCertificateStrategy::Instance(), "ca_cert");
#endif

#ifdef USE_ARP_ACL
ACL::Prototype ACLARP::RegistryProtoype(&ACLARP::RegistryEntry_, "arp");
ACLARP ACLARP::RegistryEntry_("arp");
#endif

#if USE_IDENT
ACL::Prototype ACLIdent::UserRegistryProtoype(&ACLIdent::UserRegistryEntry_, "ident");
ACLIdent ACLIdent::UserRegistryEntry_(new ACLUserData, "ident");
ACL::Prototype ACLIdent::RegexRegistryProtoype(&ACLIdent::RegexRegistryEntry_, "ident_regex" );
ACLIdent ACLIdent::RegexRegistryEntry_(new ACLRegexData, "ident_regex");
#endif


ACL::Prototype ACLProxyAuth::UserRegistryProtoype(&ACLProxyAuth::UserRegistryEntry_, "proxy_auth");
ACLProxyAuth ACLProxyAuth::UserRegistryEntry_(new ACLUserData, "proxy_auth");
ACL::Prototype ACLProxyAuth::RegexRegistryProtoype(&ACLProxyAuth::RegexRegistryEntry_, "proxy_auth_regex" );
ACLProxyAuth ACLProxyAuth::RegexRegistryEntry_(new ACLRegexData, "proxy_auth_regex");

ACL::Prototype ACLMaxUserIP::RegistryProtoype(&ACLMaxUserIP::RegistryEntry_, "max_user_ip");
ACLMaxUserIP ACLMaxUserIP::RegistryEntry_("max_user_ip");

ACL::Prototype ACLTag::RegistryProtoype(&ACLTag::RegistryEntry_, "tag");
ACLStrategised<const char *> ACLTag::RegistryEntry_(new ACLStringData, ACLTagStrategy::Instance(), "tag");
