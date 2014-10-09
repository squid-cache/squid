#ifndef SQUID_ACLFILLED_CHECKLIST_H
#define SQUID_ACLFILLED_CHECKLIST_H

#include "acl/Checklist.h"
#include "acl/forward.h"
#include "base/CbcPointer.h"
#include "ip/Address.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_SSL
#include "ssl/support.h"
#endif

class CachePeer;
class ConnStateData;
class HttpRequest;
class HttpReply;

/** \ingroup ACLAPI
    ACLChecklist filled with specific data, representing Squid and transaction
    state for access checks along with some data-specific checking methods */
class ACLFilledChecklist: public ACLChecklist
{
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

public:
    Ip::Address src_addr;
    Ip::Address dst_addr;
    Ip::Address my_addr;
    CachePeer *dst_peer;
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

#if USE_SSL
    /// SSL [certificate validation] errors, in undefined order
    Ssl::CertErrors *sslErrors;
    /// The peer certificate
    Ssl::X509_Pointer serverCert;
#endif

    ExternalACLEntryPointer extacl_entry;

private:
    ConnStateData * conn_;          /**< hack for ident and NTLM */
    int fd_;                        /**< may be available when conn_ is not */
    bool destinationDomainChecked_;
    bool sourceDomainChecked_;
    /// not implemented; will cause link failures if used
    ACLFilledChecklist(const ACLFilledChecklist &);
    /// not implemented; will cause link failures if used
    ACLFilledChecklist &operator=(const ACLFilledChecklist &);

    CBDATA_CLASS2(ACLFilledChecklist);
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
