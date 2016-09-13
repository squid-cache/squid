/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "err_type.h"
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
    ACLFilledChecklist(const acl_access *, HttpRequest *, const char *ident);
    ~ACLFilledChecklist();

public:
    /// The client connection manager
    ConnStateData * conn() const;

    /// The client side fd. It uses conn() if available
    int fd() const;

    /// set either conn
    void conn(ConnStateData *);
    /// set the client side FD
    void fd(int aDescriptor);

    //int authenticated();

    bool destinationDomainChecked() const;
    void markDestinationDomainChecked();
    bool sourceDomainChecked() const;
    void markSourceDomainChecked();

    // ACLChecklist API
    virtual bool hasRequest() const { return request != NULL; }
    virtual bool hasReply() const { return reply != NULL; }
    virtual bool hasAle() const { return al != NULL; }
    virtual void syncAle() const;

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

    /// SSL [certificate validation] errors, in undefined order
    const Security::CertErrors *sslErrors;
    /// The peer certificate
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

