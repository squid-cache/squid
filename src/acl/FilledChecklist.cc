/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "debug/Messages.h"
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
    dst_rdns(nullptr),
#if USE_AUTH
    auth_user_request (nullptr),
#endif
#if SQUID_SNMP
    snmp_community(nullptr),
#endif
    requestErrorType(ERR_MAX),
    conn_(nullptr),
    fd_(-1),
    destinationDomainChecked_(false),
    sourceDomainChecked_(false)
{
    my_addr.setEmpty();
    src_addr.setEmpty();
    dst_addr.setEmpty();
}

ACLFilledChecklist::~ACLFilledChecklist()
{
    assert (!asyncInProgress());

    safe_free(dst_rdns); // created by xstrdup().

    cbdataReferenceDone(conn_);

    debugs(28, 4, "ACLFilledChecklist destroyed " << this);
}

static void
showDebugWarning(const char *msg)
{
    static uint16_t count = 0;
    if (count > 10)
        return;

    ++count;
    debugs(28, Important(58), "ERROR: ALE missing " << msg);
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
            al->request = request.getRaw();
            HTTPMSGLOCK(al->request);
        }

        if (!al->adapted_request) {
            showDebugWarning("adapted HttpRequest object");
            al->adapted_request = request.getRaw();
            HTTPMSGLOCK(al->adapted_request);
        }

        if (al->url.isEmpty()) {
            showDebugWarning("URL");
            // XXX: al->url should be the request URL from client,
            // but request->url may be different (e.g.,redirected)
            al->url = request->effectiveRequestUri();
        }
    }

    if (hasReply() && !al->reply) {
        showDebugWarning("HttpReply object");
        al->reply = reply_;
    }
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
ACLFilledChecklist::setConn(ConnStateData *aConn)
{
    if (conn_ == aConn)
        return; // no new information

    // no conn_ replacement/removal to reduce inconsistent fill concerns
    assert(!conn_);
    assert(aConn);

    // To reduce inconsistent fill concerns, we should be the only ones calling
    // fillConnectionLevelDetails(). Set conn_ first so that the filling method
    // can detect (some) direct calls from others.
    conn_ = cbdataReference(aConn);
    aConn->fillConnectionLevelDetails(*this);
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
 * "Fast" (always synchronous or "blocking"): The user constructs an
 *    ACLFilledChecklist object on stack, configures it as needed, and calls one
 *    or both of its fastCheck() methods.
 *
 * "Slow" (usually asynchronous or "non-blocking"): The user allocates an
 *    ACLFilledChecklist object on heap (via Make()), configures it as needed,
 *    and passes it to NonBlockingCheck() while specifying the callback function
 *    to call with check results. NonBlockingCheck() calls the callback function
 *    (if the corresponding cbdata is still valid), either immediately/directly
 *    (XXX) or eventually/asynchronously. After this callback obligations are
 *    fulfilled, checkCallback() deletes the checklist object (i.e. "this").
 */
ACLFilledChecklist::ACLFilledChecklist(const acl_access *A, HttpRequest *http_request):
    dst_rdns(nullptr),
#if USE_AUTH
    auth_user_request(nullptr),
#endif
#if SQUID_SNMP
    snmp_community(nullptr),
#endif
    requestErrorType(ERR_MAX),
    conn_(nullptr),
    fd_(-1),
    destinationDomainChecked_(false),
    sourceDomainChecked_(false)
{
    my_addr.setEmpty();
    src_addr.setEmpty();
    dst_addr.setEmpty();

    changeAcl(A);
    setRequest(http_request);
}

void ACLFilledChecklist::setRequest(HttpRequest *httpRequest)
{
    assert(!request);
    if (httpRequest) {
        request = httpRequest;
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.acl_uses_indirect_client)
            src_addr = request->indirect_client_addr;
        else
#endif /* FOLLOW_X_FORWARDED_FOR */
            src_addr = request->client_addr;
        my_addr = request->my_addr;

        if (const auto cmgr = request->clientConnectionManager.get())
            setConn(cmgr);
    }
}

void
ACLFilledChecklist::updateAle(const AccessLogEntry::Pointer &a)
{
    if (!a)
        return;

    al = a; // could have been set already (to a different value)
    if (!request)
        setRequest(a->request);
    updateReply(a->reply);
}

void
ACLFilledChecklist::updateReply(const HttpReply::Pointer &r)
{
    if (r)
        reply_ = r; // may already be set, including to r
}

