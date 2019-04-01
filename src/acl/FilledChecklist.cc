/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/forward.h"
#include "ExternalACLEntry.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#if USE_AUTH
#include "auth/AclProxyAuth.h"
#include "auth/UserRequest.h"
#endif

CBDATA_CLASS_INIT(ACLFilledChecklist);

ACLFilledChecklist::ACLFilledChecklist() :
    dst_rdns(NULL),
    request (NULL),
    reply (NULL),
#if USE_AUTH
    auth_user_request (NULL),
#endif
#if SQUID_SNMP
    snmp_community(NULL),
#endif
#if USE_OPENSSL
    sslErrors(NULL),
#endif
    requestErrorType(ERR_MAX),
    conn_(NULL),
    fd_(-1),
    destinationDomainChecked_(false),
    sourceDomainChecked_(false)
{
    my_addr.setEmpty();
    src_addr.setEmpty();
    dst_addr.setEmpty();
    rfc931[0] = '\0';
}

ACLFilledChecklist::~ACLFilledChecklist()
{
    assert (!asyncInProgress());

    safe_free(dst_rdns); // created by xstrdup().

    HTTPMSGUNLOCK(request);

    HTTPMSGUNLOCK(reply);

    cbdataReferenceDone(conn_);

#if USE_OPENSSL
    cbdataReferenceDone(sslErrors);
#endif

    debugs(28, 4, HERE << "ACLFilledChecklist destroyed " << this);
}

static void
showDebugWarning(const char *msg)
{
    static uint16_t count = 0;
    if (count > 10)
        return;

    ++count;
    debugs(28, DBG_IMPORTANT, "ALE missing " << msg);
}

void
ACLFilledChecklist::verifyAle() const
{
    // make sure the ALE fields used by Format::assemble to
    // fill the old external_acl_type codes are set if any
    // data on them exists in the Checklist

    if (!al->cache.port && conn()) {
        showDebugWarning("listening port");
        al->cache.port = conn()->port;
    }

    if (request) {
        if (!al->request) {
            showDebugWarning("HttpRequest object");
            // XXX: al->request should be original,
            // but the request may be already adapted
            al->request = request;
            HTTPMSGLOCK(al->request);
        }

        if (!al->adapted_request) {
            showDebugWarning("adapted HttpRequest object");
            al->adapted_request = request;
            HTTPMSGLOCK(al->adapted_request);
        }

        if (al->url.isEmpty()) {
            showDebugWarning("URL");
            // XXX: al->url should be the request URL from client,
            // but request->url may be different (e.g.,redirected)
            al->url = request->effectiveRequestUri();
        }
    }

    if (reply && !al->reply) {
        showDebugWarning("HttpReply object");
        al->reply = reply;
        HTTPMSGLOCK(al->reply);
    }

#if USE_IDENT
    if (*rfc931 && !al->cache.rfc931) {
        showDebugWarning("IDENT");
        al->cache.rfc931 = xstrdup(rfc931);
    }
#endif
}

void
ACLFilledChecklist::syncAle(HttpRequest *adaptedRequest, const char *logUri) const
{
    if (!al)
        return;
    if (adaptedRequest && !al->adapted_request) {
        al->adapted_request = adaptedRequest;
        HTTPMSGLOCK(al->adapted_request);
    }
    if (logUri && al->url.isEmpty())
        al->url = logUri;
}

ConnStateData *
ACLFilledChecklist::conn() const
{
    return cbdataReferenceValid(conn_) ? conn_ : nullptr;
}

void
ACLFilledChecklist::conn(ConnStateData *aConn)
{
    if (conn() == aConn)
        return;
    assert (conn() == NULL);
    conn_ = cbdataReference(aConn);
}

int
ACLFilledChecklist::fd() const
{
    const auto c = conn();
    return (c && c->clientConnection) ? c->clientConnection->fd : fd_;
}

void
ACLFilledChecklist::fd(int aDescriptor)
{
    const auto c = conn();
    assert(!c || !c->clientConnection || c->clientConnection->fd == aDescriptor);
    fd_ = aDescriptor;
}

bool
ACLFilledChecklist::destinationDomainChecked() const
{
    return destinationDomainChecked_;
}

void
ACLFilledChecklist::markDestinationDomainChecked()
{
    assert (!finished() && !destinationDomainChecked());
    destinationDomainChecked_ = true;
}

bool
ACLFilledChecklist::sourceDomainChecked() const
{
    return sourceDomainChecked_;
}

void
ACLFilledChecklist::markSourceDomainChecked()
{
    assert (!finished() && !sourceDomainChecked());
    sourceDomainChecked_ = true;
}

/*
 * There are two common ACLFilledChecklist lifecycles paths:
 *
 * A) Using aclCheckFast(): The caller creates an ACLFilledChecklist object
 *    on stack and calls aclCheckFast().
 *
 * B) Using aclNBCheck() and callbacks: The caller allocates an
 *    ACLFilledChecklist object (via operator new) and passes it to
 *    aclNBCheck(). Control eventually passes to ACLChecklist::checkCallback(),
 *    which will invoke the callback function as requested by the
 *    original caller of aclNBCheck().  This callback function must
 *    *not* delete the list.  After the callback function returns,
 *    checkCallback() will delete the list (i.e., self).
 */
ACLFilledChecklist::ACLFilledChecklist(const acl_access *A, HttpRequest *http_request, const char *ident):
    dst_rdns(NULL),
    request(NULL),
    reply(NULL),
#if USE_AUTH
    auth_user_request(NULL),
#endif
#if SQUID_SNMP
    snmp_community(NULL),
#endif
#if USE_OPENSSL
    sslErrors(NULL),
#endif
    requestErrorType(ERR_MAX),
    conn_(NULL),
    fd_(-1),
    destinationDomainChecked_(false),
    sourceDomainChecked_(false)
{
    my_addr.setEmpty();
    src_addr.setEmpty();
    dst_addr.setEmpty();
    rfc931[0] = '\0';

    changeAcl(A);
    setRequest(http_request);
    setIdent(ident);
}

void ACLFilledChecklist::setRequest(HttpRequest *httpRequest)
{
    assert(!request);
    if (httpRequest) {
        request = httpRequest;
        HTTPMSGLOCK(request);
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.acl_uses_indirect_client)
            src_addr = request->indirect_client_addr;
        else
#endif /* FOLLOW_X_FORWARDED_FOR */
            src_addr = request->client_addr;
        my_addr = request->my_addr;

        if (request->clientConnectionManager.valid())
            conn(request->clientConnectionManager.get());
    }
}

void
ACLFilledChecklist::setIdent(const char *ident)
{
#if USE_IDENT
    assert(!rfc931[0]);
    if (ident)
        xstrncpy(rfc931, ident, USER_IDENT_SZ);
#endif
}

