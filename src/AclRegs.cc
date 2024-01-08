/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_ADAPTATION
#include "acl/AdaptationService.h"
#include "acl/AdaptationServiceData.h"
#endif
#include "acl/AllOf.h"
#include "acl/AnnotateClient.h"
#include "acl/AnnotateTransaction.h"
#include "acl/AnnotationData.h"
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
#include "acl/Checklist.h"
#include "acl/ConnectionsEncrypted.h"
#include "acl/Data.h"
#include "acl/DestinationAsn.h"
#include "acl/DestinationDomain.h"
#include "acl/DestinationIp.h"
#include "acl/DomainData.h"
#if USE_LIBNETFILTERCONNTRACK
#include "acl/ConnMark.h"
#endif
#if USE_AUTH
#include "acl/ExtUser.h"
#endif
#include "acl/FilledChecklist.h"
#include "acl/forward.h"
#include "acl/Gadgets.h"
#include "acl/HasComponent.h"
#include "acl/HasComponentData.h"
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
#include "acl/RegexData.h"
#include "acl/ReplyHeaderStrategy.h"
#include "acl/ReplyMimeType.h"
#include "acl/RequestHeaderStrategy.h"
#include "acl/RequestMimeType.h"
#include "acl/SourceAsn.h"
#include "acl/SourceDomain.h"
#include "acl/SourceIp.h"
#include "acl/SquidError.h"
#include "acl/SquidErrorData.h"
#if USE_OPENSSL
#include "acl/Certificate.h"
#include "acl/CertificateData.h"
#include "acl/ServerName.h"
#include "acl/SslError.h"
#include "acl/SslErrorData.h"
#endif
#include "acl/StringData.h"
#if USE_OPENSSL
#include "acl/ServerCertificate.h"
#endif
#include "acl/Tag.h"
#include "acl/Time.h"
#include "acl/TimeData.h"
#include "acl/TransactionInitiator.h"
#include "acl/Url.h"
#include "acl/UrlLogin.h"
#include "acl/UrlPath.h"
#include "acl/UrlPort.h"
#include "acl/UserData.h"
#if USE_AUTH
#include "auth/AclMaxUserIp.h"
#include "auth/AclProxyAuth.h"
#endif
#include "base/RegexPattern.h"
#include "ExternalACL.h"
#if USE_IDENT
#include "ident/AclIdent.h"
#endif
#if SQUID_SNMP
#include "snmp_core.h"
#endif
#include "sbuf/Stream.h"

namespace Acl
{

/// Constructs a ParameterizedNode-derived ACL (specified as a Parent class).
/// This template exists to avoid placing a variant of this ACL construction
/// code in each ParameterizedNode-derived ACL class just to pass through
/// TypeName and Parameters onto ParameterizedNode (and to add MEMPROXY_CLASS).
template <class Parent>
class FinalizedParameterizedNode: public Parent
{
    MEMPROXY_CLASS(Acl::FinalizedParameterizedNode<Parent>);

public:
    using Parameters = typename Parent::Parameters;
    using Parent::data;

    /// Replaces generic memory allocator label X set by our MEMPROXY_CLASS(X)
    /// with an admin-friendly label based on the given acltype-like name.
    /// Normally, our class constructor sets the right allocator label using the
    /// actlype name, but that algorithm results in unstable and misleading
    /// labels when the same instantiation of this template class is used for
    /// _multiple_ acltype names. Calling this method corrects that behavior.
    /// \prec this method must be called at most once
    /// \prec if called, this method must be called before the class constructor
    static void PreferAllocatorLabelPrefix(const char * const suffix)
    {
        assert(!PreferredAllocatorLabelSuffix); // must be called at most once
        assert(!FinalPoolLabel); // must be called before the class constructor
        assert(suffix);
        PreferredAllocatorLabelSuffix = suffix;
    }

    FinalizedParameterizedNode(TypeName typeName, Parameters * const params):
        typeName_(typeName)
    {
        Assure(!data); // base classes never set this data member
        data.reset(params);
        Assure(data); // ... but we always do

        FinalizePoolLabel(typeName);
    }

    ~FinalizedParameterizedNode() override = default;

    /* ACL API */
    const char *typeString() const override { return typeName_; }

private:
    /// A constructor helper function that replaces generic memory allocator
    /// label X set by our MEMPROXY_CLASS(X) with an admin-friendly label based
    /// on the acltype name from squid.conf. Meant to be called from the
    /// constructor so that no mgr:mem report lists this C++ template class
    /// statistics using label X. Repeated calls are allowed but have no effect.
    /// \sa PreferAllocatorLabelPrefix()
    static void FinalizePoolLabel(const TypeName typeName)
    {
        if (FinalPoolLabel)
            return; // the label has been finalized already

        assert(typeName);
        const auto label = ToSBuf("acltype=", PreferredAllocatorLabelSuffix ? PreferredAllocatorLabelSuffix : typeName);
        FinalPoolLabel = SBufToCstring(label);
        Pool().relabel(FinalPoolLabel);
    }

    /// if set, overrules FinalizePoolLabel() argument
    inline static const char *PreferredAllocatorLabelSuffix = nullptr;

    /// custom allocator label set by FinalizePoolLabel()
    inline static const char *FinalPoolLabel = nullptr;

    // TODO: Consider storing the spelling used by the admin instead.
    /// the "acltype" name in its canonical spelling
    TypeName typeName_;
};

} // namespace Acl

// Not in src/acl/ because some of the ACLs it registers are not in src/acl/.
void
Acl::Init()
{
    /* the registration order does not matter */

    // The explicit return type (AclNode*) for lambdas is needed because the type
    // of the return expression inside lambda is not AclNode* but AclFoo* while
    // Acl::Maker is defined to return AclNode*.

    RegisterMaker("all-of", [](TypeName)->AclNode* { return new Acl::AllOf; }); // XXX: Add name parameter to ctor
    RegisterMaker("any-of", [](TypeName)->AclNode* { return new Acl::AnyOf; }); // XXX: Add name parameter to ctor
    RegisterMaker("random", [](TypeName name)->AclNode* { return new ACLRandom(name); });
    RegisterMaker("time", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::CurrentTimeCheck>(name, new ACLTimeData); });
    RegisterMaker("src_as", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::SourceAsnCheck>(name, new ACLASN); });
    RegisterMaker("dst_as", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::DestinationAsnCheck>(name, new ACLASN); });
    RegisterMaker("browser", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::RequestHeaderCheck<Http::HdrType::USER_AGENT> >(name, new ACLRegexData); });

    RegisterMaker("dstdomain", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::DestinationDomainCheck>(name, new ACLDomainData); });
    RegisterMaker("dstdom_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::DestinationDomainCheck>(name, new ACLRegexData); });
    Acl::FinalizedParameterizedNode<Acl::DestinationDomainCheck>::PreferAllocatorLabelPrefix("dstdomain+");

    RegisterMaker("dst", [](TypeName)->AclNode* { return new ACLDestinationIP; }); // XXX: Add name parameter to ctor
    RegisterMaker("hier_code", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::HierCodeCheck>(name, new ACLHierCodeData); });
    RegisterMaker("rep_header", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::HttpRepHeaderCheck>(name, new ACLHTTPHeaderData); });
    RegisterMaker("req_header", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::HttpReqHeaderCheck>(name, new ACLHTTPHeaderData); });
    RegisterMaker("http_status", [](TypeName name)->AclNode* { return new ACLHTTPStatus(name); });
    RegisterMaker("maxconn", [](TypeName name)->AclNode* { return new ACLMaxConnection(name); });
    RegisterMaker("method", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::MethodCheck>(name, new ACLMethodData); });
    RegisterMaker("localip", [](TypeName)->AclNode* { return new ACLLocalIP; }); // XXX: Add name parameter to ctor
    RegisterMaker("localport", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::LocalPortCheck>(name, new ACLIntRange); });
    RegisterMaker("myportname", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::MyPortNameCheck>(name, new ACLStringData); });

    RegisterMaker("peername", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::PeerNameCheck>(name, new ACLStringData); });
    RegisterMaker("peername_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::PeerNameCheck>(name, new ACLRegexData); });
    Acl::FinalizedParameterizedNode<Acl::PeerNameCheck>::PreferAllocatorLabelPrefix("peername+");

    RegisterMaker("proto", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ProtocolCheck>(name, new ACLProtocolData); });
    RegisterMaker("referer_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::RequestHeaderCheck<Http::HdrType::REFERER> >(name, new ACLRegexData); });
    RegisterMaker("rep_mime_type", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ReplyHeaderCheck<Http::HdrType::CONTENT_TYPE> >(name, new ACLRegexData); });
    RegisterMaker("req_mime_type", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::RequestHeaderCheck<Http::HdrType::CONTENT_TYPE> >(name, new ACLRegexData); });

    RegisterMaker("srcdomain", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::SourceDomainCheck>(name, new ACLDomainData); });
    RegisterMaker("srcdom_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::SourceDomainCheck>(name, new ACLRegexData); });
    Acl::FinalizedParameterizedNode<Acl::SourceDomainCheck>::PreferAllocatorLabelPrefix("srcdomain+");

    RegisterMaker("src", [](TypeName)->AclNode* { return new ACLSourceIP; }); // XXX: Add name parameter to ctor
    RegisterMaker("url_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::UrlCheck>(name, new ACLRegexData); });
    RegisterMaker("urllogin", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::UrlLoginCheck>(name, new ACLRegexData); });
    RegisterMaker("urlpath_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::UrlPathCheck>(name, new ACLRegexData); });
    RegisterMaker("port", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::UrlPortCheck>(name, new ACLIntRange); });
    RegisterMaker("external", [](TypeName name)->AclNode* { return new ACLExternal(name); });
    RegisterMaker("squid_error", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::SquidErrorCheck>(name, new ACLSquidErrorData); });
    RegisterMaker("connections_encrypted", [](TypeName name)->AclNode* { return new Acl::ConnectionsEncrypted(name); });
    RegisterMaker("tag", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::TagCheck>(name, new ACLStringData); });
    RegisterMaker("note", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::NoteCheck>(name, new ACLNoteData); });
    RegisterMaker("annotate_client", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::AnnotateClientCheck>(name, new ACLAnnotationData); });
    RegisterMaker("annotate_transaction", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::AnnotateTransactionCheck>(name, new ACLAnnotationData); });
    RegisterMaker("has", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::HasComponentCheck>(name, new ACLHasComponentData); });
    RegisterMaker("transaction_initiator", [](TypeName name)->AclNode* {return new TransactionInitiator(name);});

#if USE_LIBNETFILTERCONNTRACK
    RegisterMaker("clientside_mark", [](TypeName)->AclNode* { return new Acl::ConnMark; }); // XXX: Add name parameter to ctor
    RegisterMaker("client_connection_mark", [](TypeName)->AclNode* { return new Acl::ConnMark; }); // XXX: Add name parameter to ctor
#endif

#if USE_OPENSSL
    RegisterMaker("ssl_error", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::CertificateErrorCheck>(name, new ACLSslErrorData); });

    RegisterMaker("user_cert", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ClientCertificateCheck>(name, new ACLCertificateData(Ssl::GetX509UserAttribute, "*")); });
    RegisterMaker("ca_cert", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ClientCertificateCheck>(name, new ACLCertificateData(Ssl::GetX509CAAttribute, "*")); });
    Acl::FinalizedParameterizedNode<Acl::ClientCertificateCheck>::PreferAllocatorLabelPrefix("user_cert+");

    RegisterMaker("server_cert_fingerprint", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ServerCertificateCheck>(name, new ACLCertificateData(Ssl::GetX509Fingerprint, nullptr, true)); });
    RegisterMaker("at_step", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::AtStepCheck>(name, new ACLAtStepData); });

    RegisterMaker("ssl::server_name", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ServerNameCheck>(name, new ACLServerNameData); });
    RegisterMaker("ssl::server_name_regex", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::ServerNameCheck>(name, new ACLRegexData); });
    Acl::FinalizedParameterizedNode<Acl::ServerNameCheck>::PreferAllocatorLabelPrefix("ssl::server_name+");
#endif

#if USE_SQUID_EUI
    RegisterMaker("arp", [](TypeName name)->AclNode* { return new ACLARP(name); });
    RegisterMaker("eui64", [](TypeName name)->AclNode* { return new ACLEui64(name); });
#endif

#if USE_IDENT
    RegisterMaker("ident", [](TypeName name)->AclNode* { return new ACLIdent(new ACLUserData, name); });
    RegisterMaker("ident_regex", [](TypeName name)->AclNode* { return new ACLIdent(new ACLRegexData, name); });
#endif

#if USE_AUTH
    RegisterMaker("ext_user", [](TypeName name)->AclNode* { return new ACLExtUser(new ACLUserData, name); });
    RegisterMaker("ext_user_regex", [](TypeName name)->AclNode* { return new ACLExtUser(new ACLRegexData, name); });
    RegisterMaker("proxy_auth", [](TypeName name)->AclNode* { return new ACLProxyAuth(new ACLUserData, name); });
    RegisterMaker("proxy_auth_regex", [](TypeName name)->AclNode* { return new ACLProxyAuth(new ACLRegexData, name); });
    RegisterMaker("max_user_ip", [](TypeName name)->AclNode* { return new ACLMaxUserIP(name); });
#endif

#if USE_ADAPTATION
    RegisterMaker("adaptation_service", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::AdaptationServiceCheck>(name, new ACLAdaptationServiceData); });
#endif

#if SQUID_SNMP
    RegisterMaker("snmp_community", [](TypeName name)->AclNode* { return new Acl::FinalizedParameterizedNode<Acl::SnmpCommunityCheck>(name, new ACLStringData); });
#endif
}

