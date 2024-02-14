/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_FILLEDCHECKLIST_H
#define SQUID_SRC_ACL_FILLEDCHECKLIST_H

#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "acl/forward.h"
#include "base/CbcPointer.h"
#include "error/forward.h"
#include "ip/Address.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#include "security/CertError.h"

class CachePeer;
class ConnStateData;
class HttpRequest;
class HttpReply;

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
    ~ACLFilledChecklist() override;

    /// configure client request-related fields for the first time
    void setRequest(HttpRequest *);
    /// configure rfc931 user identity for the first time
    void setIdent(const char *userIdentity);

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
    bool hasRequest() const override { return request != nullptr; }
    bool hasReply() const override { return reply != nullptr; }
    bool hasAle() const override { return al != nullptr; }
    void syncAle(HttpRequest *adaptedRequest, const char *logUri) const override;
    void verifyAle() const override;

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

    // TODO: RefCount errors; do not ignore them because their "owner" is gone!
    /// TLS server [certificate validation] errors, in undefined order.
    /// The errors are accumulated as Squid goes through validation steps
    /// and server certificates. They are cleared on connection retries.
    /// For sslproxy_cert_error checks, contains just the current/last error.
    CbcPointer<Security::CertErrors> sslErrors;

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

#endif /* SQUID_SRC_ACL_FILLEDCHECKLIST_H */

