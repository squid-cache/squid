/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLFILLED_CHECKLIST_H
#define SQUID_ACLFILLED_CHECKLIST_H

#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "acl/forward.h"
#include "base/CbcPointer.h"
#include "error/forward.h"
#include "http/forward.h"
#include "ip/Address.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#include "security/CertError.h"

class CachePeer;
class ConnStateData;

/** \ingroup ACLAPI
    ACLChecklist filled with specific data, representing Squid and transaction
    state for access checks along with some data-specific checking methods
 */
class ACLFilledChecklist: public ACLChecklist
{
    CBDATA_CLASS(ACLFilledChecklist);

public:
    ACLFilledChecklist();
    ACLFilledChecklist(const acl_access *, HttpRequest *, const char *ident = nullptr);
    ~ACLFilledChecklist();

    // The following checklist configuration functions may be called in any
    // order, repeatedly, and/or with nil arguments. They all extract new (as in
    // "previously not set") information but do not update changed (as in
    // "previously set to a different value") info.

    /// configure client request-related fields
    void setRequest(HttpRequest *);

    /// configure rfc931 user identity
    void setIdent(const char *userIdentity);

    /// configure cache_peer-related fields
    void setPeer(const CachePeer *);

    /// configure Squid-to-origin/cache_peer connection-related fields
    void setOutgoingConnection(const Comm::ConnectionPointer &);

    /// configure server response-related fields
    void setReply(const HttpReplyPointer &);

    /// configure Squid-generated error-related fields
    void setError(const ErrorState *);

public:
    /// The client connection manager
    ConnStateData * conn() const;

    /// The client side fd. It uses conn() if available
    int fd() const;

    /// set either conn
    void setConn(ConnStateData *);
    /// set the client side FD
    void fd(int aDescriptor);

    //int authenticated();

    bool destinationDomainChecked() const;
    void markDestinationDomainChecked();
    bool sourceDomainChecked() const;
    void markSourceDomainChecked();

    // ACLChecklist API
    virtual bool hasRequest() const { return request != nullptr; }
    virtual bool hasReply() const { return reply != nullptr; }
    virtual bool hasAle() const { return al != nullptr; }
    virtual void syncAle(HttpRequest *adaptedRequest, const char *logUri) const;
    virtual void verifyAle() const;

public:
    Ip::Address src_addr;
    Ip::Address dst_addr;
    Ip::Address my_addr;
    SBuf dst_peer_name;
    char *dst_rdns;

    HttpRequest *request;
    HttpReply *reply;

    char rfc931[USER_IDENT_SZ];
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request;
#endif
#if SQUID_SNMP
    char *snmp_community;
#endif

    /// TLS server [certificate validation] errors, in undefined order.
    /// The errors are accumulated as Squid goes through validation steps
    /// and server certificates. They are cleared on connection retries.
    /// For sslproxy_cert_error checks, contains just the current/last error.
    const Security::CertErrors *sslErrors;

    /// Peer certificate being checked by ssl_verify_cb() and by
    /// Security::PeerConnector class. In other contexts, the peer
    /// certificate is retrieved via ALE or ConnStateData::serverBump.
    Security::CertPointer serverCert;

    AccessLogEntry::Pointer al; ///< info for the future access.log, and external ACL

    ExternalACLEntryPointer extacl_entry;

    err_type requestErrorType;

private:
    ConnStateData * conn_;          /**< hack for ident and NTLM */
    int fd_;                        /**< may be available when conn_ is not */
    bool destinationDomainChecked_;
    bool sourceDomainChecked_;
    /// not implemented; will cause link failures if used
    ACLFilledChecklist(const ACLFilledChecklist &);
    /// not implemented; will cause link failures if used
    ACLFilledChecklist &operator=(const ACLFilledChecklist &);
};

/// convenience and safety wrapper for dynamic_cast<ACLFilledChecklist*>
inline
ACLFilledChecklist *Filled(ACLChecklist *checklist)
{
    // this should always be safe because ACLChecklist is an abstract class
    // and ACLFilledChecklist is its only [concrete] child
    return dynamic_cast<ACLFilledChecklist*>(checklist);
}

#endif /* SQUID_ACLFILLED_CHECKLIST_H */

