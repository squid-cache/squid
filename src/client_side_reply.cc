/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 88    Client-side Reply Routines */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "anyp/PortCfg.h"
#include "client_side_reply.h"
#include "errorpage.h"
#include "ETag.h"
#include "fd.h"
#include "fde.h"
#include "format/Token.h"
#include "FwdState.h"
#include "globals.h"
#include "http/Stream.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ip/QosConfig.h"
#include "ipcache.h"
#include "log/access_log.h"
#include "MemObject.h"
#include "mime_header.h"
#include "neighbors.h"
#include "refresh.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "StrList.h"
#include "tools.h"
#include "URL.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif
#if USE_SQUID_ESI
#include "esi/Esi.h"
#endif

#include <memory>

CBDATA_CLASS_INIT(clientReplyContext);

/* Local functions */
extern "C" CSS clientReplyStatus;
ErrorState *clientBuildError(err_type, Http::StatusCode, char const *, Ip::Address &, HttpRequest *);

/* privates */

clientReplyContext::~clientReplyContext()
{
    deleting = true;
    /* This may trigger a callback back into SendMoreData as the cbdata
     * is still valid
     */
    removeClientStoreReference(&sc, http);
    /* old_entry might still be set if we didn't yet get the reply
     * code in HandleIMSReply() */
    removeStoreReference(&old_sc, &old_entry);
    safe_free(tempBuffer.data);
    cbdataReferenceDone(http);
    HTTPMSGUNLOCK(reply);
}

clientReplyContext::clientReplyContext(ClientHttpRequest *clientContext) :
    purgeStatus(Http::scNone),
    lookingforstore(0),
    http(cbdataReference(clientContext)),
    headers_sz(0),
    sc(NULL),
    old_reqsize(0),
    reqsize(0),
    reqofs(0),
#if USE_CACHE_DIGESTS
    lookup_type(NULL),
#endif
    ourNode(NULL),
    reply(NULL),
    old_entry(NULL),
    old_sc(NULL),
    old_lastmod(-1),
    deleting(false),
    collapsedRevalidation(crNone)
{
    *tempbuf = 0;
}

/** Create an error in the store awaiting the client side to read it.
 *
 * This may be better placed in the clientStream logic, but it has not been
 * relocated there yet
 */
void
clientReplyContext::setReplyToError(
    err_type err, Http::StatusCode status, const HttpRequestMethod& method, char const *uri,
    Ip::Address &addr, HttpRequest * failedrequest, const char *unparsedrequest,
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request
#else
    void*
#endif
)
{
    ErrorState *errstate = clientBuildError(err, status, uri, addr, failedrequest);

    if (unparsedrequest)
        errstate->request_hdrs = xstrdup(unparsedrequest);

#if USE_AUTH
    errstate->auth_user_request = auth_user_request;
#endif
    setReplyToError(method, errstate);
}

void clientReplyContext::setReplyToError(const HttpRequestMethod& method, ErrorState *errstate)
{
    if (errstate->httpStatus == Http::scNotImplemented && http->request)
        /* prevent confusion over whether we default to persistent or not */
        http->request->flags.proxyKeepalive = false;

    http->al->http.code = errstate->httpStatus;

    if (http->request)
        http->request->ignoreRange("responding with a Squid-generated error");

    createStoreEntry(method, RequestFlags());
    assert(errstate->callback_data == NULL);
    errorAppendEntry(http->storeEntry(), errstate);
    /* Now the caller reads to get this */
}

void
clientReplyContext::setReplyToReply(HttpReply *futureReply)
{
    Must(futureReply);
    http->al->http.code = futureReply->sline.status();

    HttpRequestMethod method;
    if (http->request) { // nil on responses to unparsable requests
        http->request->ignoreRange("responding with a Squid-generated reply");
        method = http->request->method;
    }

    createStoreEntry(method, RequestFlags());

    http->storeEntry()->storeErrorResponse(futureReply);
    /* Now the caller reads to get futureReply */
}

// Assumes that the entry contains an error response without Content-Range.
// To use with regular entries, make HTTP Range header removal conditional.
void clientReplyContext::setReplyToStoreEntry(StoreEntry *entry, const char *reason)
{
    entry->lock("clientReplyContext::setReplyToStoreEntry"); // removeClientStoreReference() unlocks
    sc = storeClientListAdd(entry, this);
#if USE_DELAY_POOLS
    sc->setDelayId(DelayId::DelayClient(http));
#endif
    reqofs = 0;
    reqsize = 0;
    if (http->request)
        http->request->ignoreRange(reason);
    flags.storelogiccomplete = 1;
    http->storeEntry(entry);
}

void
clientReplyContext::removeStoreReference(store_client ** scp,
        StoreEntry ** ep)
{
    StoreEntry *e;
    store_client *sc_tmp = *scp;

    if ((e = *ep) != NULL) {
        *ep = NULL;
        storeUnregister(sc_tmp, e, this);
        *scp = NULL;
        e->unlock("clientReplyContext::removeStoreReference");
    }
}

void
clientReplyContext::removeClientStoreReference(store_client **scp, ClientHttpRequest *aHttpRequest)
{
    StoreEntry *reference = aHttpRequest->storeEntry();
    removeStoreReference(scp, &reference);
    aHttpRequest->storeEntry(reference);
}

void
clientReplyContext::saveState()
{
    assert(old_sc == NULL);
    debugs(88, 3, "clientReplyContext::saveState: saving store context");
    old_entry = http->storeEntry();
    old_sc = sc;
    old_lastmod = http->request->lastmod;
    old_etag = http->request->etag;
    old_reqsize = reqsize;
    tempBuffer.offset = reqofs;
    /* Prevent accessing the now saved entries */
    http->storeEntry(NULL);
    sc = NULL;
    reqsize = 0;
    reqofs = 0;
}

void
clientReplyContext::restoreState()
{
    assert(old_sc != NULL);
    debugs(88, 3, "clientReplyContext::restoreState: Restoring store context");
    removeClientStoreReference(&sc, http);
    http->storeEntry(old_entry);
    sc = old_sc;
    reqsize = old_reqsize;
    reqofs = tempBuffer.offset;
    http->request->lastmod = old_lastmod;
    http->request->etag = old_etag;
    /* Prevent accessed the old saved entries */
    old_entry = NULL;
    old_sc = NULL;
    old_lastmod = -1;
    old_etag.clean();
    old_reqsize = 0;
    tempBuffer.offset = 0;
}

void
clientReplyContext::startError(ErrorState * err)
{
    createStoreEntry(http->request->method, RequestFlags());
    triggerInitialStoreRead();
    errorAppendEntry(http->storeEntry(), err);
}

clientStreamNode *
clientReplyContext::getNextNode() const
{
    return (clientStreamNode *)ourNode->node.next->data;
}

/* This function is wrong - the client parameters don't include the
 * header offset
 */
void
clientReplyContext::triggerInitialStoreRead()
{
    /* when confident, 0 becomes reqofs, and then this factors into
     * startSendProcess
     */
    assert(reqofs == 0);
    StoreIOBuffer localTempBuffer (next()->readBuffer.length, 0, next()->readBuffer.data);
    storeClientCopy(sc, http->storeEntry(), localTempBuffer, SendMoreData, this);
}

/* there is an expired entry in the store.
 * setup a temporary buffer area and perform an IMS to the origin
 */
void
clientReplyContext::processExpired()
{
    const char *url = storeId();
    debugs(88, 3, "clientReplyContext::processExpired: '" << http->uri << "'");
    const time_t lastmod = http->storeEntry()->lastModified();
    assert(lastmod >= 0);
    /*
     * check if we are allowed to contact other servers
     * @?@: Instead of a 504 (Gateway Timeout) reply, we may want to return
     *      a stale entry *if* it matches client requirements
     */

    if (http->onlyIfCached()) {
        processOnlyIfCachedMiss();
        return;
    }

    http->logType = LOG_TCP_REFRESH;
    http->request->flags.refresh = true;
#if STORE_CLIENT_LIST_DEBUG
    /* Prevent a race with the store client memory free routines
     */
    assert(storeClientIsThisAClient(sc, this));
#endif
    /* Prepare to make a new temporary request */
    saveState();

    // TODO: support collapsed revalidation for Vary-controlled entries
    const bool collapsingAllowed = Config.onoff.collapsed_forwarding &&
                                   !Store::Root().smpAware() &&
                                   http->request->vary_headers.isEmpty();

    StoreEntry *entry = nullptr;
    if (collapsingAllowed) {
        if ((entry = storeGetPublicByRequest(http->request, ksRevalidation)))
            entry->lock("clientReplyContext::processExpired#alreadyRevalidating");
    }

    if (entry) {
        entry->ensureMemObject(url, http->log_uri, http->request->method);
        debugs(88, 5, "collapsed on existing revalidation entry: " << *entry);
        collapsedRevalidation = crSlave;
    } else {
        entry = storeCreateEntry(url,
                                 http->log_uri, http->request->flags, http->request->method);
        /* NOTE, don't call StoreEntry->lock(), storeCreateEntry() does it */

        if (collapsingAllowed && Store::Root().allowCollapsing(entry, http->request->flags, http->request->method)) {
            debugs(88, 5, "allow other revalidation requests to collapse on " << *entry);
            collapsedRevalidation = crInitiator;
        } else {
            collapsedRevalidation = crNone;
        }
    }

    sc = storeClientListAdd(entry, this);
#if USE_DELAY_POOLS
    /* delay_id is already set on original store client */
    sc->setDelayId(DelayId::DelayClient(http));
#endif

    http->request->lastmod = lastmod;

    if (!http->request->header.has(Http::HdrType::IF_NONE_MATCH)) {
        ETag etag = {NULL, -1}; // TODO: make that a default ETag constructor
        if (old_entry->hasEtag(etag) && !etag.weak)
            http->request->etag = etag.str;
    }

    debugs(88, 5, "lastmod " << entry->lastModified());
    http->storeEntry(entry);
    assert(http->out.offset == 0);
    assert(http->request->clientConnectionManager == http->getConn());

    if (collapsedRevalidation != crSlave) {
        /*
         * A refcounted pointer so that FwdState stays around as long as
         * this clientReplyContext does
         */
        Comm::ConnectionPointer conn = http->getConn() != NULL ? http->getConn()->clientConnection : NULL;
        FwdState::Start(conn, http->storeEntry(), http->request, http->al);
    }
    /* Register with storage manager to receive updates when data comes in. */

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
        debugs(88, DBG_CRITICAL, "clientReplyContext::processExpired: Found ENTRY_ABORTED object");

    {
        /* start counting the length from 0 */
        StoreIOBuffer localTempBuffer(HTTP_REQBUF_SZ, 0, tempbuf);
        storeClientCopy(sc, entry, localTempBuffer, HandleIMSReply, this);
    }
}

void
clientReplyContext::sendClientUpstreamResponse()
{
    StoreIOBuffer tempresult;
    removeStoreReference(&old_sc, &old_entry);
    /* here the data to send is the data we just received */
    tempBuffer.offset = 0;
    old_reqsize = 0;
    /* sendMoreData tracks the offset as well.
     * Force it back to zero */
    reqofs = 0;
    assert(!EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED));
    /* TODO: provide sendMoreData with the ready parsed reply */
    tempresult.length = reqsize;
    tempresult.data = tempbuf;
    sendMoreData(tempresult);
}

void
clientReplyContext::HandleIMSReply(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = (clientReplyContext *)data;
    context->handleIMSReply(result);
}

void
clientReplyContext::sendClientOldEntry()
{
    /* Get the old request back */
    restoreState();
    /* here the data to send is in the next nodes buffers already */
    assert(!EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED));
    /* sendMoreData tracks the offset as well.
     * Force it back to zero */
    reqofs = 0;
    StoreIOBuffer tempresult (reqsize, reqofs, next()->readBuffer.data);
    sendMoreData(tempresult);
}

/* This is the workhorse of the HandleIMSReply callback.
 *
 * It is called when we've got data back from the origin following our
 * IMS request to revalidate a stale entry.
 */
void
clientReplyContext::handleIMSReply(StoreIOBuffer result)
{
    if (deleting)
        return;

    debugs(88, 3, http->storeEntry()->url() << ", " << (long unsigned) result.length << " bytes");

    if (http->storeEntry() == NULL)
        return;

    if (result.flags.error && !EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED))
        return;

    if (collapsedRevalidation == crSlave && !http->storeEntry()->mayStartHitting()) {
        debugs(88, 3, "CF slave hit private non-shareable " << *http->storeEntry() << ". MISS");
        // restore context to meet processMiss() expectations
        restoreState();
        http->logType = LOG_TCP_MISS;
        processMiss();
        return;
    }

    /* update size of the request */
    reqsize = result.length + reqofs;

    const Http::StatusCode status = http->storeEntry()->getReply()->sline.status();

    // request to origin was aborted
    if (EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED)) {
        debugs(88, 3, "request to origin aborted '" << http->storeEntry()->url() << "', sending old entry to client");
        http->logType = LOG_TCP_REFRESH_FAIL_OLD;
        sendClientOldEntry();
    }

    const HttpReply *old_rep = old_entry->getReply();

    // origin replied 304
    if (status == Http::scNotModified) {
        http->logType = LOG_TCP_REFRESH_UNMODIFIED;
        http->request->flags.staleIfHit = false; // old_entry is no longer stale

        // update headers on existing entry
        Store::Root().updateOnNotModified(old_entry, *http->storeEntry());

        // if client sent IMS

        if (http->request->flags.ims && !old_entry->modifiedSince(http->request->ims, http->request->imslen)) {
            // forward the 304 from origin
            debugs(88, 3, "origin replied 304, revalidating existing entry and forwarding 304 to client");
            sendClientUpstreamResponse();
        } else {
            // send existing entry, it's still valid
            debugs(88, 3, "origin replied 304, revalidating existing entry and sending " <<
                   old_rep->sline.status() << " to client");
            sendClientOldEntry();
        }
    }

    // origin replied with a non-error code
    else if (status > Http::scNone && status < Http::scInternalServerError) {
        const HttpReply *new_rep = http->storeEntry()->getReply();
        // RFC 7234 section 4: a cache MUST use the most recent response
        // (as determined by the Date header field)
        if (new_rep->olderThan(old_rep)) {
            http->logType.err.ignored = true;
            debugs(88, 3, "origin replied " << status <<
                   " but with an older date header, sending old entry (" <<
                   old_rep->sline.status() << ") to client");
            sendClientOldEntry();
        } else {
            http->logType = LOG_TCP_REFRESH_MODIFIED;
            debugs(88, 3, "origin replied " << status <<
                   ", replacing existing entry and forwarding to client");

            if (collapsedRevalidation)
                http->storeEntry()->clearPublicKeyScope();

            sendClientUpstreamResponse();
        }
    }

    // origin replied with an error
    else if (http->request->flags.failOnValidationError) {
        http->logType = LOG_TCP_REFRESH_FAIL_ERR;
        debugs(88, 3, "origin replied with error " << status <<
               ", forwarding to client due to fail_on_validation_err");
        sendClientUpstreamResponse();
    } else {
        // ignore and let client have old entry
        http->logType = LOG_TCP_REFRESH_FAIL_OLD;
        debugs(88, 3, "origin replied with error " <<
               status << ", sending old entry (" << old_rep->sline.status() << ") to client");
        sendClientOldEntry();
    }
}

SQUIDCEXTERN CSR clientGetMoreData;
SQUIDCEXTERN CSD clientReplyDetach;

/**
 * clientReplyContext::cacheHit Should only be called until the HTTP reply headers
 * have been parsed.  Normally this should be a single call, but
 * it might take more than one.  As soon as we have the headers,
 * we hand off to clientSendMoreData, processExpired, or
 * processMiss.
 */
void
clientReplyContext::CacheHit(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = (clientReplyContext *)data;
    context->cacheHit(result);
}

/**
 * Process a possible cache HIT.
 */
void
clientReplyContext::cacheHit(StoreIOBuffer result)
{
    /** Ignore if the HIT object is being deleted. */
    if (deleting) {
        debugs(88, 3, "HIT object being deleted. Ignore the HIT.");
        return;
    }

    StoreEntry *e = http->storeEntry();

    HttpRequest *r = http->request;

    debugs(88, 3, "clientCacheHit: " << http->uri << ", " << result.length << " bytes");

    if (http->storeEntry() == NULL) {
        debugs(88, 3, "clientCacheHit: request aborted");
        return;
    } else if (result.flags.error) {
        /* swap in failure */
        debugs(88, 3, "clientCacheHit: swapin failure for " << http->uri);
        http->logType = LOG_TCP_SWAPFAIL_MISS;
        removeClientStoreReference(&sc, http);
        processMiss();
        return;
    }

    // The previously identified hit suddenly became unsharable!
    // This is common for collapsed forwarding slaves but might also
    // happen to regular hits because we are called asynchronously.
    if (!e->mayStartHitting()) {
        debugs(88, 3, "unsharable " << *e << ". MISS");
        http->logType = LOG_TCP_MISS;
        processMiss();
        return;
    }

    if (result.length == 0) {
        debugs(88, 5, "store IO buffer has no content. MISS");
        /* the store couldn't get enough data from the file for us to id the
         * object
         */
        /* treat as a miss */
        http->logType = LOG_TCP_MISS;
        processMiss();
        return;
    }

    assert(!EBIT_TEST(e->flags, ENTRY_ABORTED));
    /* update size of the request */
    reqsize = result.length + reqofs;

    /*
     * Got the headers, now grok them
     */
    assert(http->logType.oldType == LOG_TCP_HIT);

    if (http->request->storeId().cmp(e->mem_obj->storeId()) != 0) {
        debugs(33, DBG_IMPORTANT, "clientProcessHit: URL mismatch, '" << e->mem_obj->storeId() << "' != '" << http->request->storeId() << "'");
        http->logType = LOG_TCP_MISS; // we lack a more precise LOG_*_MISS code
        processMiss();
        return;
    }

    switch (varyEvaluateMatch(e, r)) {

    case VARY_NONE:
        /* No variance detected. Continue as normal */
        break;

    case VARY_MATCH:
        /* This is the correct entity for this request. Continue */
        debugs(88, 2, "clientProcessHit: Vary MATCH!");
        break;

    case VARY_OTHER:
        /* This is not the correct entity for this request. We need
         * to requery the cache.
         */
        removeClientStoreReference(&sc, http);
        e = NULL;
        /* Note: varyEvalyateMatch updates the request with vary information
         * so we only get here once. (it also takes care of cancelling loops)
         */
        debugs(88, 2, "clientProcessHit: Vary detected!");
        clientGetMoreData(ourNode, http);
        return;

    case VARY_CANCEL:
        /* varyEvaluateMatch found a object loop. Process as miss */
        debugs(88, DBG_IMPORTANT, "clientProcessHit: Vary object loop!");
        http->logType = LOG_TCP_MISS; // we lack a more precise LOG_*_MISS code
        processMiss();
        return;
    }

    if (r->method == Http::METHOD_PURGE) {
        debugs(88, 5, "PURGE gets a HIT");
        removeClientStoreReference(&sc, http);
        e = NULL;
        purgeRequest();
        return;
    }

    if (e->checkNegativeHit() && !r->flags.noCacheHack()) {
        debugs(88, 5, "negative-HIT");
        http->logType = LOG_TCP_NEGATIVE_HIT;
        sendMoreData(result);
        return;
    } else if (blockedHit()) {
        debugs(88, 5, "send_hit forces a MISS");
        http->logType = LOG_TCP_MISS;
        processMiss();
        return;
    } else if (!http->flags.internal && refreshCheckHTTP(e, r)) {
        debugs(88, 5, "clientCacheHit: in refreshCheck() block");
        /*
         * We hold a stale copy; it needs to be validated
         */
        /*
         * The 'needValidation' flag is used to prevent forwarding
         * loops between siblings.  If our copy of the object is stale,
         * then we should probably only use parents for the validation
         * request.  Otherwise two siblings could generate a loop if
         * both have a stale version of the object.
         */
        r->flags.needValidation = true;

        if (e->lastModified() < 0) {
            debugs(88, 3, "validate HIT object? NO. Can't calculate entry modification time. Do MISS.");
            /*
             * We cannot revalidate entries without knowing their
             * modification time.
             * XXX: BUG 1890 objects without Date do not get one added.
             */
            http->logType = LOG_TCP_MISS;
            processMiss();
        } else if (r->flags.noCache) {
            debugs(88, 3, "validate HIT object? NO. Client sent CC:no-cache. Do CLIENT_REFRESH_MISS");
            /*
             * This did not match a refresh pattern that overrides no-cache
             * we should honour the client no-cache header.
             */
            http->logType = LOG_TCP_CLIENT_REFRESH_MISS;
            processMiss();
        } else if (r->url.getScheme() == AnyP::PROTO_HTTP || r->url.getScheme() == AnyP::PROTO_HTTPS) {
            debugs(88, 3, "validate HIT object? YES.");
            /*
             * Object needs to be revalidated
             * XXX This could apply to FTP as well, if Last-Modified is known.
             */
            processExpired();
        } else {
            debugs(88, 3, "validate HIT object? NO. Client protocol non-HTTP. Do MISS.");
            /*
             * We don't know how to re-validate other protocols. Handle
             * them as if the object has expired.
             */
            http->logType = LOG_TCP_MISS;
            processMiss();
        }
        return;
    } else if (r->conditional()) {
        debugs(88, 5, "conditional HIT");
        if (processConditional(result))
            return;
    }

    /*
     * plain ol' cache hit
     */
    debugs(88, 5, "plain old HIT");

#if USE_DELAY_POOLS
    if (e->store_status != STORE_OK)
        http->logType = LOG_TCP_MISS;
    else
#endif
        if (e->mem_status == IN_MEMORY)
            http->logType = LOG_TCP_MEM_HIT;
        else if (Config.onoff.offline)
            http->logType = LOG_TCP_OFFLINE_HIT;

    sendMoreData(result);
}

/**
 * Prepare to fetch the object as it's a cache miss of some kind.
 */
void
clientReplyContext::processMiss()
{
    char *url = http->uri;
    HttpRequest *r = http->request;
    ErrorState *err = NULL;
    debugs(88, 4, r->method << ' ' << url);

    /**
     * We might have a left-over StoreEntry from a failed cache hit
     * or IMS request.
     */
    if (http->storeEntry()) {
        if (EBIT_TEST(http->storeEntry()->flags, ENTRY_SPECIAL)) {
            debugs(88, DBG_CRITICAL, "clientProcessMiss: miss on a special object (" << url << ").");
            debugs(88, DBG_CRITICAL, "\tlog_type = " << http->logType.c_str());
            http->storeEntry()->dump(1);
        }

        removeClientStoreReference(&sc, http);
    }

    /** Check if its a PURGE request to be actioned. */
    if (r->method == Http::METHOD_PURGE) {
        purgeRequest();
        return;
    }

    /** Check if its an 'OTHER' request. Purge all cached entries if so and continue. */
    if (r->method == Http::METHOD_OTHER) {
        purgeAllCached();
    }

    /** Check if 'only-if-cached' flag is set. Action if so. */
    if (http->onlyIfCached()) {
        processOnlyIfCachedMiss();
        return;
    }

    Comm::ConnectionPointer conn = http->getConn() != nullptr ? http->getConn()->clientConnection : nullptr;
    /// Deny loops
    if (r->flags.loopDetected) {
        http->al->http.code = Http::scForbidden;
        Ip::Address tmp_noaddr;
        tmp_noaddr.setNoAddr();
        err = clientBuildError(ERR_ACCESS_DENIED, Http::scForbidden, nullptr, conn ? conn->remote : tmp_noaddr, http->request);
        createStoreEntry(r->method, RequestFlags());
        errorAppendEntry(http->storeEntry(), err);
        triggerInitialStoreRead();
        return;
    } else {
        assert(http->out.offset == 0);
        createStoreEntry(r->method, r->flags);
        triggerInitialStoreRead();

        if (http->redirect.status) {
            HttpReply *rep = new HttpReply;
            http->logType = LOG_TCP_REDIRECT;
            http->storeEntry()->releaseRequest();
            rep->redirect(http->redirect.status, http->redirect.location);
            http->storeEntry()->replaceHttpReply(rep);
            http->storeEntry()->complete();
            return;
        }

        assert(r->clientConnectionManager == http->getConn());

        /** Start forwarding to get the new object from network */
        FwdState::Start(conn, http->storeEntry(), r, http->al);
    }
}

/**
 * client issued a request with an only-if-cached cache-control directive;
 * we did not find a cached object that can be returned without
 *     contacting other servers;
 * respond with a 504 (Gateway Timeout) as suggested in [RFC 2068]
 */
void
clientReplyContext::processOnlyIfCachedMiss()
{
    debugs(88, 4, http->request->method << ' ' << http->uri);
    http->al->http.code = Http::scGatewayTimeout;
    Ip::Address tmp_noaddr;
    tmp_noaddr.setNoAddr();
    ErrorState *err = clientBuildError(ERR_ONLY_IF_CACHED_MISS, Http::scGatewayTimeout, NULL,
                                       http->getConn() ? http->getConn()->clientConnection->remote : tmp_noaddr,
                                       http->request);
    removeClientStoreReference(&sc, http);
    startError(err);
}

/// process conditional request from client
bool
clientReplyContext::processConditional(StoreIOBuffer &result)
{
    StoreEntry *const e = http->storeEntry();

    if (e->getReply()->sline.status() != Http::scOkay) {
        debugs(88, 4, "Reply code " << e->getReply()->sline.status() << " != 200");
        http->logType = LOG_TCP_MISS;
        processMiss();
        return true;
    }

    HttpRequest &r = *http->request;

    if (r.header.has(Http::HdrType::IF_MATCH) && !e->hasIfMatchEtag(r)) {
        // RFC 2616: reply with 412 Precondition Failed if If-Match did not match
        sendPreconditionFailedError();
        return true;
    }

    if (r.header.has(Http::HdrType::IF_NONE_MATCH)) {
        // RFC 7232: If-None-Match recipient MUST ignore IMS
        r.flags.ims = false;
        r.ims = -1;
        r.imslen = 0;
        r.header.delById(Http::HdrType::IF_MODIFIED_SINCE);

        if (e->hasIfNoneMatchEtag(r)) {
            sendNotModifiedOrPreconditionFailedError();
            return true;
        }

        // None-Match is true (no ETag matched); treat as an unconditional hit
        return false;
    }

    if (r.flags.ims) {
        // handle If-Modified-Since requests from the client
        if (e->modifiedSince(r.ims, r.imslen)) {
            // Modified-Since is true; treat as an unconditional hit
            return false;

        } else {
            // otherwise reply with 304 Not Modified
            sendNotModified();
        }
        return true;
    }

    return false;
}

/// whether squid.conf send_hit prevents us from serving this hit
bool
clientReplyContext::blockedHit() const
{
    if (!Config.accessList.sendHit)
        return false; // hits are not blocked by default

    if (http->flags.internal)
        return false; // internal content "hits" cannot be blocked

    if (const HttpReply *rep = http->storeEntry()->getReply()) {
        std::unique_ptr<ACLFilledChecklist> chl(clientAclChecklistCreate(Config.accessList.sendHit, http));
        chl->reply = const_cast<HttpReply*>(rep); // ACLChecklist API bug
        HTTPMSGLOCK(chl->reply);
        return !chl->fastCheck().allowed(); // when in doubt, block
    }

    // This does not happen, I hope, because we are called from CacheHit, which
    // is called via a storeClientCopy() callback, and store should initialize
    // the reply before calling that callback.
    debugs(88, 3, "Missing reply!");
    return false;
}

void
clientReplyContext::purgeRequestFindObjectToPurge()
{
    /* Try to find a base entry */
    http->flags.purging = true;
    lookingforstore = 1;

    // TODO: can we use purgeAllCached() here instead of doing the
    // getPublicByRequestMethod() dance?
    StoreEntry::getPublicByRequestMethod(this, http->request, Http::METHOD_GET);
}

// Purges all entries with a given url
// TODO: move to SideAgent parent, when we have one
/*
 * We probably cannot purge Vary-affected responses because their MD5
 * keys depend on vary headers.
 */
void
purgeEntriesByUrl(HttpRequest * req, const char *url)
{
    for (HttpRequestMethod m(Http::METHOD_NONE); m != Http::METHOD_ENUM_END; ++m) {
        if (m.respMaybeCacheable()) {
            const cache_key *key = storeKeyPublic(url, m);
            debugs(88, 5, m << ' ' << url << ' ' << storeKeyText(key));
#if USE_HTCP
            neighborsHtcpClear(nullptr, url, req, m, HTCP_CLR_INVALIDATION);
#endif
            Store::Root().evictIfFound(key);
        }
    }
}

void
clientReplyContext::purgeAllCached()
{
    // XXX: performance regression, c_str() reallocates
    SBuf url(http->request->effectiveRequestUri());
    purgeEntriesByUrl(http->request, url.c_str());
}

void
clientReplyContext::created(StoreEntry *newEntry)
{
    if (lookingforstore == 1)
        purgeFoundGet(newEntry);
    else if (lookingforstore == 2)
        purgeFoundHead(newEntry);
    else if (lookingforstore == 3)
        purgeDoPurgeGet(newEntry);
    else if (lookingforstore == 4)
        purgeDoPurgeHead(newEntry);
    else if (lookingforstore == 5)
        identifyFoundObject(newEntry);
}

void
clientReplyContext::purgeFoundGet(StoreEntry *newEntry)
{
    if (newEntry->isNull()) {
        lookingforstore = 2;
        StoreEntry::getPublicByRequestMethod(this, http->request, Http::METHOD_HEAD);
    } else
        purgeFoundObject (newEntry);
}

void
clientReplyContext::purgeFoundHead(StoreEntry *newEntry)
{
    if (newEntry->isNull())
        purgeDoMissPurge();
    else
        purgeFoundObject (newEntry);
}

void
clientReplyContext::purgeFoundObject(StoreEntry *entry)
{
    assert (entry && !entry->isNull());

    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL)) {
        http->logType = LOG_TCP_DENIED;
        Ip::Address tmp_noaddr;
        tmp_noaddr.setNoAddr(); // TODO: make a global const
        ErrorState *err = clientBuildError(ERR_ACCESS_DENIED, Http::scForbidden, NULL,
                                           http->getConn() ? http->getConn()->clientConnection->remote : tmp_noaddr,
                                           http->request);
        startError(err);
        return; // XXX: leaking unused entry if some store does not keep it
    }

    StoreIOBuffer localTempBuffer;
    /* Swap in the metadata */
    http->storeEntry(entry);

    http->storeEntry()->lock("clientReplyContext::purgeFoundObject");
    http->storeEntry()->ensureMemObject(storeId(), http->log_uri,
                                        http->request->method);

    sc = storeClientListAdd(http->storeEntry(), this);

    http->logType = LOG_TCP_HIT;

    reqofs = 0;

    localTempBuffer.offset = http->out.offset;

    localTempBuffer.length = next()->readBuffer.length;

    localTempBuffer.data = next()->readBuffer.data;

    storeClientCopy(sc, http->storeEntry(),
                    localTempBuffer, CacheHit, this);
}

void
clientReplyContext::purgeRequest()
{
    debugs(88, 3, "Config2.onoff.enable_purge = " <<
           Config2.onoff.enable_purge);

    if (!Config2.onoff.enable_purge) {
        http->logType = LOG_TCP_DENIED;
        Ip::Address tmp_noaddr;
        tmp_noaddr.setNoAddr();
        ErrorState *err = clientBuildError(ERR_ACCESS_DENIED, Http::scForbidden, NULL,
                                           http->getConn() ? http->getConn()->clientConnection->remote : tmp_noaddr, http->request);
        startError(err);
        return;
    }

    /* Release both IP cache */
    ipcacheInvalidate(http->request->url.host());

    if (!http->flags.purging)
        purgeRequestFindObjectToPurge();
    else
        purgeDoMissPurge();
}

void
clientReplyContext::purgeDoMissPurge()
{
    http->logType = LOG_TCP_MISS;
    lookingforstore = 3;
    StoreEntry::getPublicByRequestMethod(this,http->request, Http::METHOD_GET);
}

void
clientReplyContext::purgeDoPurgeGet(StoreEntry *newEntry)
{
    assert (newEntry);
    /* Move to new() when that is created */
    purgeStatus = Http::scNotFound;

    if (!newEntry->isNull()) {
        /* Release the cached URI */
        debugs(88, 4, "clientPurgeRequest: GET '" << newEntry->url() << "'" );
#if USE_HTCP
        neighborsHtcpClear(newEntry, NULL, http->request, HttpRequestMethod(Http::METHOD_GET), HTCP_CLR_PURGE);
#endif
        newEntry->release(true);
        purgeStatus = Http::scOkay;
    }

    lookingforstore = 4;
    StoreEntry::getPublicByRequestMethod(this, http->request, Http::METHOD_HEAD);
}

void
clientReplyContext::purgeDoPurgeHead(StoreEntry *newEntry)
{
    if (newEntry && !newEntry->isNull()) {
        debugs(88, 4, "HEAD " << newEntry->url());
#if USE_HTCP
        neighborsHtcpClear(newEntry, NULL, http->request, HttpRequestMethod(Http::METHOD_HEAD), HTCP_CLR_PURGE);
#endif
        newEntry->release(true);
        purgeStatus = Http::scOkay;
    }

    /* And for Vary, release the base URI if none of the headers was included in the request */
    if (!http->request->vary_headers.isEmpty()
            && http->request->vary_headers.find('=') != SBuf::npos) {
        // XXX: performance regression, c_str() reallocates
        SBuf tmp(http->request->effectiveRequestUri());
        StoreEntry *entry = storeGetPublic(tmp.c_str(), Http::METHOD_GET);

        if (entry) {
            debugs(88, 4, "Vary GET " << entry->url());
#if USE_HTCP
            neighborsHtcpClear(entry, NULL, http->request, HttpRequestMethod(Http::METHOD_GET), HTCP_CLR_PURGE);
#endif
            entry->release(true);
            purgeStatus = Http::scOkay;
        }

        entry = storeGetPublic(tmp.c_str(), Http::METHOD_HEAD);

        if (entry) {
            debugs(88, 4, "Vary HEAD " << entry->url());
#if USE_HTCP
            neighborsHtcpClear(entry, NULL, http->request, HttpRequestMethod(Http::METHOD_HEAD), HTCP_CLR_PURGE);
#endif
            entry->release(true);
            purgeStatus = Http::scOkay;
        }
    }

    /*
     * Make a new entry to hold the reply to be written
     * to the client.
     */
    /* FIXME: This doesn't need to go through the store. Simply
     * push down the client chain
     */
    createStoreEntry(http->request->method, RequestFlags());

    triggerInitialStoreRead();

    HttpReply *rep = new HttpReply;
    rep->setHeaders(purgeStatus, NULL, NULL, 0, 0, -1);
    http->storeEntry()->replaceHttpReply(rep);
    http->storeEntry()->complete();
}

void
clientReplyContext::traceReply(clientStreamNode * node)
{
    clientStreamNode *nextNode = (clientStreamNode *)node->node.next->data;
    StoreIOBuffer localTempBuffer;
    createStoreEntry(http->request->method, RequestFlags());
    localTempBuffer.offset = nextNode->readBuffer.offset + headers_sz;
    localTempBuffer.length = nextNode->readBuffer.length;
    localTempBuffer.data = nextNode->readBuffer.data;
    storeClientCopy(sc, http->storeEntry(),
                    localTempBuffer, SendMoreData, this);
    http->storeEntry()->releaseRequest();
    http->storeEntry()->buffer();
    HttpReply *rep = new HttpReply;
    rep->setHeaders(Http::scOkay, NULL, "text/plain", http->request->prefixLen(), 0, squid_curtime);
    http->storeEntry()->replaceHttpReply(rep);
    http->request->swapOut(http->storeEntry());
    http->storeEntry()->complete();
}

#define SENDING_BODY 0
#define SENDING_HDRSONLY 1
int
clientReplyContext::checkTransferDone()
{
    StoreEntry *entry = http->storeEntry();

    if (entry == NULL)
        return 0;

    /*
     * For now, 'done_copying' is used for special cases like
     * Range and HEAD requests.
     */
    if (http->flags.done_copying)
        return 1;

    if (http->request->flags.chunkedReply && !flags.complete) {
        // last-chunk was not sent
        return 0;
    }

    /*
     * Handle STORE_OK objects.
     * objectLen(entry) will be set proprely.
     * RC: Does objectLen(entry) include the Headers?
     * RC: Yes.
     */
    if (entry->store_status == STORE_OK) {
        return storeOKTransferDone();
    } else {
        return storeNotOKTransferDone();
    }
}

int
clientReplyContext::storeOKTransferDone() const
{
    assert(http->storeEntry()->objectLen() >= 0);
    assert(http->storeEntry()->objectLen() >= headers_sz);
    if (http->out.offset >= http->storeEntry()->objectLen() - headers_sz) {
        debugs(88,3,HERE << "storeOKTransferDone " <<
               " out.offset=" << http->out.offset <<
               " objectLen()=" << http->storeEntry()->objectLen() <<
               " headers_sz=" << headers_sz);
        return 1;
    }

    return 0;
}

int
clientReplyContext::storeNotOKTransferDone() const
{
    /*
     * Now, handle STORE_PENDING objects
     */
    MemObject *mem = http->storeEntry()->mem_obj;
    assert(mem != NULL);
    assert(http->request != NULL);
    /* mem->reply was wrong because it uses the UPSTREAM header length!!! */
    HttpReply const *curReply = mem->getReply();

    if (headers_sz == 0)
        /* haven't found end of headers yet */
        return 0;

    /*
     * Figure out how much data we are supposed to send.
     * If we are sending a body and we don't have a content-length,
     * then we must wait for the object to become STORE_OK.
     */
    if (curReply->content_length < 0)
        return 0;

    uint64_t expectedLength = curReply->content_length + http->out.headers_sz;

    if (http->out.size < expectedLength)
        return 0;
    else {
        debugs(88,3,HERE << "storeNotOKTransferDone " <<
               " out.size=" << http->out.size <<
               " expectedLength=" << expectedLength);
        return 1;
    }
}

/* A write has completed, what is the next status based on the
 * canonical request data?
 * 1 something is wrong
 * 0 nothing is wrong.
 *
 */
int
clientHttpRequestStatus(int fd, ClientHttpRequest const *http)
{
#if SIZEOF_INT64_T == 4
    if (http->out.size > 0x7FFF0000) {
        debugs(88, DBG_IMPORTANT, "WARNING: closing FD " << fd << " to prevent out.size counter overflow");
        if (http->getConn())
            debugs(88, DBG_IMPORTANT, "\tclient " << http->getConn()->peer);
        debugs(88, DBG_IMPORTANT, "\treceived " << http->out.size << " bytes");
        debugs(88, DBG_IMPORTANT, "\tURI " << http->log_uri);
        return 1;
    }

    if (http->out.offset > 0x7FFF0000) {
        debugs(88, DBG_IMPORTANT, "WARNING: closing FD " << fd < " to prevent out.offset counter overflow");
        if (http->getConn())
            debugs(88, DBG_IMPORTANT, "\tclient " << http->getConn()->peer);
        debugs(88, DBG_IMPORTANT, "\treceived " << http->out.size << " bytes, offset " << http->out.offset);
        debugs(88, DBG_IMPORTANT, "\tURI " << http->log_uri);
        return 1;
    }

#endif
    return 0;
}

/* Preconditions:
 * *http is a valid structure.
 * fd is either -1, or an open fd.
 *
 * TODO: enumify this
 *
 * This function is used by any http request sink, to determine the status
 * of the object.
 */
clientStream_status_t
clientReplyStatus(clientStreamNode * aNode, ClientHttpRequest * http)
{
    clientReplyContext *context = dynamic_cast<clientReplyContext *>(aNode->data.getRaw());
    assert (context);
    assert (context->http == http);
    return context->replyStatus();
}

clientStream_status_t
clientReplyContext::replyStatus()
{
    int done;
    /* Here because lower nodes don't need it */

    if (http->storeEntry() == NULL) {
        debugs(88, 5, "clientReplyStatus: no storeEntry");
        return STREAM_FAILED;   /* yuck, but what can we do? */
    }

    if (EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED)) {
        /* TODO: Could upstream read errors (result.flags.error) be
         * lost, and result in undersize requests being considered
         * complete. Should we tcp reset such connections ?
         */
        debugs(88, 5, "clientReplyStatus: aborted storeEntry");
        return STREAM_FAILED;
    }

    if ((done = checkTransferDone()) != 0 || flags.complete) {
        debugs(88, 5, "clientReplyStatus: transfer is DONE: " << done << flags.complete);
        /* Ok we're finished, but how? */

        if (EBIT_TEST(http->storeEntry()->flags, ENTRY_BAD_LENGTH)) {
            debugs(88, 5, "clientReplyStatus: truncated response body");
            return STREAM_UNPLANNED_COMPLETE;
        }

        if (!done) {
            debugs(88, 5, "clientReplyStatus: closing, !done, but read 0 bytes");
            return STREAM_FAILED;
        }

        const int64_t expectedBodySize =
            http->storeEntry()->getReply()->bodySize(http->request->method);
        if (expectedBodySize >= 0 && !http->gotEnough()) {
            debugs(88, 5, "clientReplyStatus: client didn't get all it expected");
            return STREAM_UNPLANNED_COMPLETE;
        }

        debugs(88, 5, "clientReplyStatus: stream complete; keepalive=" <<
               http->request->flags.proxyKeepalive);
        return STREAM_COMPLETE;
    }

    // XXX: Should this be checked earlier? We could return above w/o checking.
    if (reply->receivedBodyTooLarge(*http->request, http->out.offset - 4096)) {
        /* 4096 is a margin for the HTTP headers included in out.offset */
        debugs(88, 5, "clientReplyStatus: client reply body is too large");
        return STREAM_FAILED;
    }

    return STREAM_NONE;
}

/* Responses with no body will not have a content-type header,
 * which breaks the rep_mime_type acl, which
 * coincidentally, is the most common acl for reply access lists.
 * A better long term fix for this is to allow acl matchs on the various
 * status codes, and then supply a default ruleset that puts these
 * codes before any user defines access entries. That way the user
 * can choose to block these responses where appropriate, but won't get
 * mysterious breakages.
 */
bool
clientReplyContext::alwaysAllowResponse(Http::StatusCode sline) const
{
    bool result;

    switch (sline) {

    case Http::scContinue:

    case Http::scSwitchingProtocols:

    case Http::scProcessing:

    case Http::scNoContent:

    case Http::scNotModified:
        result = true;
        break;

    default:
        result = false;
    }

    return result;
}

/**
 * Generate the reply headers sent to client.
 *
 * Filters out unwanted entries and hop-by-hop from original reply header
 * then adds extra entries if we have more info than origin server
 * then adds Squid specific entries
 */
void
clientReplyContext::buildReplyHeader()
{
    HttpHeader *hdr = &reply->header;
    const bool is_hit = http->logType.isTcpHit();
    HttpRequest *request = http->request;
#if DONT_FILTER_THESE
    /* but you might want to if you run Squid as an HTTP accelerator */
    /* hdr->delById(HDR_ACCEPT_RANGES); */
    hdr->delById(HDR_ETAG);
#endif

    if (is_hit || collapsedRevalidation == crSlave)
        hdr->delById(Http::HdrType::SET_COOKIE);
    // TODO: RFC 2965 : Must honour Cache-Control: no-cache="set-cookie2" and remove header.

    // if there is not configured a peer proxy with login=PASS or login=PASSTHRU option enabled
    // remove the Proxy-Authenticate header
    if ( !request->peer_login || (strcmp(request->peer_login,"PASS") != 0 && strcmp(request->peer_login,"PASSTHRU") != 0)) {
#if USE_ADAPTATION
        // but allow adaptation services to authenticate clients
        // via request satisfaction
        if (!http->requestSatisfactionMode())
#endif
            reply->header.delById(Http::HdrType::PROXY_AUTHENTICATE);
    }

    reply->header.removeHopByHopEntries();

    //    if (request->range)
    //      clientBuildRangeHeader(http, reply);

    /*
     * Add a estimated Age header on cache hits.
     */
    if (is_hit) {
        /*
         * Remove any existing Age header sent by upstream caches
         * (note that the existing header is passed along unmodified
         * on cache misses)
         */
        hdr->delById(Http::HdrType::AGE);
        /*
         * This adds the calculated object age. Note that the details of the
         * age calculation is performed by adjusting the timestamp in
         * StoreEntry::timestampsSet(), not here.
         */
        if (EBIT_TEST(http->storeEntry()->flags, ENTRY_SPECIAL)) {
            hdr->delById(Http::HdrType::DATE);
            hdr->putTime(Http::HdrType::DATE, squid_curtime);
        } else if (http->getConn() && http->getConn()->port->actAsOrigin) {
            // Swap the Date: header to current time if we are simulating an origin
            HttpHeaderEntry *h = hdr->findEntry(Http::HdrType::DATE);
            if (h)
                hdr->putExt("X-Origin-Date", h->value.termedBuf());
            hdr->delById(Http::HdrType::DATE);
            hdr->putTime(Http::HdrType::DATE, squid_curtime);
            h = hdr->findEntry(Http::HdrType::EXPIRES);
            if (h && http->storeEntry()->expires >= 0) {
                hdr->putExt("X-Origin-Expires", h->value.termedBuf());
                hdr->delById(Http::HdrType::EXPIRES);
                hdr->putTime(Http::HdrType::EXPIRES, squid_curtime + http->storeEntry()->expires - http->storeEntry()->timestamp);
            }
            if (http->storeEntry()->timestamp <= squid_curtime) {
                // put X-Cache-Age: instead of Age:
                char age[64];
                snprintf(age, sizeof(age), "%" PRId64, static_cast<int64_t>(squid_curtime - http->storeEntry()->timestamp));
                hdr->putExt("X-Cache-Age", age);
            }
        } else if (http->storeEntry()->timestamp <= squid_curtime) {
            hdr->putInt(Http::HdrType::AGE,
                        squid_curtime - http->storeEntry()->timestamp);
            /* Signal old objects.  NB: rfc 2616 is not clear,
             * by implication, on whether we should do this to all
             * responses, or only cache hits.
             * 14.46 states it ONLY applys for heuristically caclulated
             * freshness values, 13.2.4 doesn't specify the same limitation.
             * We interpret RFC 2616 under the combination.
             */
            /* TODO: if maxage or s-maxage is present, don't do this */

            if (squid_curtime - http->storeEntry()->timestamp >= 86400) {
                char tbuf[512];
                snprintf (tbuf, sizeof(tbuf), "%s %s %s",
                          "113", ThisCache,
                          "This cache hit is still fresh and more than 1 day old");
                hdr->putStr(Http::HdrType::WARNING, tbuf);
            }
        }
    }

    /* RFC 2616: Section 14.18
     *
     * Add a Date: header if missing.
     * We have access to a clock therefore are required to amend any shortcoming in servers.
     *
     * NP: done after Age: to prevent ENTRY_SPECIAL double-handling this header.
     */
    if ( !hdr->has(Http::HdrType::DATE) ) {
        if (!http->storeEntry())
            hdr->putTime(Http::HdrType::DATE, squid_curtime);
        else if (http->storeEntry()->timestamp > 0)
            hdr->putTime(Http::HdrType::DATE, http->storeEntry()->timestamp);
        else {
            debugs(88,DBG_IMPORTANT,"BUG 3279: HTTP reply without Date:");
            /* dump something useful about the problem */
            http->storeEntry()->dump(DBG_IMPORTANT);
        }
    }

    // add Warnings required by RFC 2616 if serving a stale hit
    if (http->request->flags.staleIfHit && http->logType.isTcpHit()) {
        hdr->putWarning(110, "Response is stale");
        if (http->request->flags.needValidation)
            hdr->putWarning(111, "Revalidation failed");
    }

    /* Filter unproxyable authentication types */
    if (http->logType.oldType != LOG_TCP_DENIED &&
            hdr->has(Http::HdrType::WWW_AUTHENTICATE)) {
        HttpHeaderPos pos = HttpHeaderInitPos;
        HttpHeaderEntry *e;

        int connection_auth_blocked = 0;
        while ((e = hdr->getEntry(&pos))) {
            if (e->id == Http::HdrType::WWW_AUTHENTICATE) {
                const char *value = e->value.rawBuf();

                if ((strncasecmp(value, "NTLM", 4) == 0 &&
                        (value[4] == '\0' || value[4] == ' '))
                        ||
                        (strncasecmp(value, "Negotiate", 9) == 0 &&
                         (value[9] == '\0' || value[9] == ' '))
                        ||
                        (strncasecmp(value, "Kerberos", 8) == 0 &&
                         (value[8] == '\0' || value[8] == ' '))) {
                    if (request->flags.connectionAuthDisabled) {
                        hdr->delAt(pos, connection_auth_blocked);
                        continue;
                    }
                    request->flags.mustKeepalive = true;
                    if (!request->flags.accelerated && !request->flags.intercepted) {
                        httpHeaderPutStrf(hdr, Http::HdrType::PROXY_SUPPORT, "Session-Based-Authentication");
                        /*
                          We send "Connection: Proxy-Support" header to mark
                          Proxy-Support as a hop-by-hop header for intermediaries that do not
                          understand the semantics of this header. The RFC should have included
                          this recommendation.
                        */
                        httpHeaderPutStrf(hdr, Http::HdrType::CONNECTION, "Proxy-support");
                    }
                    break;
                }
            }
        }

        if (connection_auth_blocked)
            hdr->refreshMask();
    }

#if USE_AUTH
    /* Handle authentication headers */
    if (http->logType.oldType == LOG_TCP_DENIED &&
            ( reply->sline.status() == Http::scProxyAuthenticationRequired ||
              reply->sline.status() == Http::scUnauthorized)
       ) {
        /* Add authentication header */
        /*! \todo alter errorstate to be accel on|off aware. The 0 on the next line
         * depends on authenticate behaviour: all schemes to date send no extra
         * data on 407/401 responses, and do not check the accel state on 401/407
         * responses
         */
        authenticateFixHeader(reply, request->auth_user_request, request, 0, 1);
    } else if (request->auth_user_request != NULL)
        authenticateFixHeader(reply, request->auth_user_request, request, http->flags.accel, 0);
#endif

    /* Append X-Cache */
    httpHeaderPutStrf(hdr, Http::HdrType::X_CACHE, "%s from %s",
                      is_hit ? "HIT" : "MISS", getMyHostname());

#if USE_CACHE_DIGESTS
    /* Append X-Cache-Lookup: -- temporary hack, to be removed @?@ @?@ */
    httpHeaderPutStrf(hdr, Http::HdrType::X_CACHE_LOOKUP, "%s from %s:%d",
                      lookup_type ? lookup_type : "NONE",
                      getMyHostname(), getMyPort());

#endif

    const bool maySendChunkedReply = !request->multipartRangeRequest() &&
                                     reply->sline.protocol == AnyP::PROTO_HTTP && // response is HTTP
                                     (request->http_ver >= Http::ProtocolVersion(1,1));

    /* Check whether we should send keep-alive */
    if (!Config.onoff.error_pconns && reply->sline.status() >= 400 && !request->flags.mustKeepalive) {
        debugs(33, 3, "clientBuildReplyHeader: Error, don't keep-alive");
        request->flags.proxyKeepalive = false;
    } else if (!Config.onoff.client_pconns && !request->flags.mustKeepalive) {
        debugs(33, 2, "clientBuildReplyHeader: Connection Keep-Alive not requested by admin or client");
        request->flags.proxyKeepalive = false;
    } else if (request->flags.proxyKeepalive && shutting_down) {
        debugs(88, 3, "clientBuildReplyHeader: Shutting down, don't keep-alive.");
        request->flags.proxyKeepalive = false;
    } else if (request->flags.connectionAuth && !reply->keep_alive) {
        debugs(33, 2, "clientBuildReplyHeader: Connection oriented auth but server side non-persistent");
        request->flags.proxyKeepalive = false;
    } else if (reply->bodySize(request->method) < 0 && !maySendChunkedReply) {
        debugs(88, 3, "clientBuildReplyHeader: can't keep-alive, unknown body size" );
        request->flags.proxyKeepalive = false;
    } else if (fdUsageHigh()&& !request->flags.mustKeepalive) {
        debugs(88, 3, "clientBuildReplyHeader: Not many unused FDs, can't keep-alive");
        request->flags.proxyKeepalive = false;
    } else if (request->flags.sslBumped && !reply->persistent()) {
        // We do not really have to close, but we pretend we are a tunnel.
        debugs(88, 3, "clientBuildReplyHeader: bumped reply forces close");
        request->flags.proxyKeepalive = false;
    } else if (request->pinnedConnection() && !reply->persistent()) {
        // The peer wants to close the pinned connection
        debugs(88, 3, "pinned reply forces close");
        request->flags.proxyKeepalive = false;
    } else if (http->getConn()) {
        ConnStateData * conn = http->getConn();
        if (!Comm::IsConnOpen(conn->port->listenConn)) {
            // The listening port closed because of a reconfigure
            debugs(88, 3, "listening port closed");
            request->flags.proxyKeepalive = false;
        }
    }

    // Decide if we send chunked reply
    if (maySendChunkedReply && reply->bodySize(request->method) < 0) {
        debugs(88, 3, "clientBuildReplyHeader: chunked reply");
        request->flags.chunkedReply = true;
        hdr->putStr(Http::HdrType::TRANSFER_ENCODING, "chunked");
    }

    hdr->addVia(reply->sline.version);

    /* Signal keep-alive or close explicitly */
    hdr->putStr(Http::HdrType::CONNECTION, request->flags.proxyKeepalive ? "keep-alive" : "close");

#if ADD_X_REQUEST_URI
    /*
     * Knowing the URI of the request is useful when debugging persistent
     * connections in a client; we cannot guarantee the order of http headers,
     * but X-Request-URI is likely to be the very last header to ease use from a
     * debugger [hdr->entries.count-1].
     */
    hdr->putStr(Http::HdrType::X_REQUEST_URI,
                http->memOjbect()->url ? http->memObject()->url : http->uri);

#endif

    /* Surrogate-Control requires Surrogate-Capability from upstream to pass on */
    if ( hdr->has(Http::HdrType::SURROGATE_CONTROL) ) {
        if (!request->header.has(Http::HdrType::SURROGATE_CAPABILITY)) {
            hdr->delById(Http::HdrType::SURROGATE_CONTROL);
        }
        /* TODO: else case: drop any controls intended specifically for our surrogate ID */
    }

    httpHdrMangleList(hdr, request, http->al, ROR_REPLY);
}

void
clientReplyContext::cloneReply()
{
    assert(reply == NULL);

    reply = http->storeEntry()->getReply()->clone();
    HTTPMSGLOCK(reply);

    if (reply->sline.protocol == AnyP::PROTO_HTTP) {
        /* RFC 2616 requires us to advertise our version (but only on real HTTP traffic) */
        reply->sline.version = Http::ProtocolVersion();
    }

    /* do header conversions */
    buildReplyHeader();
}

/// Safely disposes of an entry pointing to a cache hit that we do not want.
/// We cannot just ignore the entry because it may be locking or otherwise
/// holding an associated cache resource of some sort.
void
clientReplyContext::forgetHit()
{
    StoreEntry *e = http->storeEntry();
    assert(e); // or we are not dealing with a hit
    // We probably have not locked the entry earlier, unfortunately. We lock it
    // now so that we can unlock two lines later (and trigger cleanup).
    // Ideally, ClientHttpRequest::storeEntry() should lock/unlock, but it is
    // used so inconsistently that simply adding locking there leads to bugs.
    e->lock("clientReplyContext::forgetHit");
    http->storeEntry(NULL);
    e->unlock("clientReplyContext::forgetHit"); // may delete e
}

void
clientReplyContext::identifyStoreObject()
{
    HttpRequest *r = http->request;

    // client sent CC:no-cache or some other condition has been
    // encountered which prevents delivering a public/cached object.
    if (!r->flags.noCache || r->flags.internal) {
        lookingforstore = 5;
        StoreEntry::getPublicByRequest (this, r);
    } else {
        identifyFoundObject (NullStoreEntry::getInstance());
    }
}

/**
 * Check state of the current StoreEntry object.
 * to see if we can determine the final status of the request.
 */
void
clientReplyContext::identifyFoundObject(StoreEntry *newEntry)
{
    StoreEntry *e = newEntry;
    HttpRequest *r = http->request;

    /** \li If the entry received isNull() then we ignore it. */
    if (e->isNull()) {
        http->storeEntry(NULL);
    } else {
        http->storeEntry(e);
    }

    e = http->storeEntry();

    /* Release IP-cache entries on reload */
    /** \li If the request has no-cache flag set or some no_cache HACK in operation we
      * 'invalidate' the cached IP entries for this request ???
      */
    if (r->flags.noCache || r->flags.noCacheHack())
        ipcacheInvalidateNegative(r->url.host());

#if USE_CACHE_DIGESTS
    lookup_type = http->storeEntry() ? "HIT" : "MISS";
#endif

    if (NULL == http->storeEntry()) {
        /** \li If no StoreEntry object is current assume this object isn't in the cache set MISS*/
        debugs(85, 3, "StoreEntry is NULL -  MISS");
        http->logType = LOG_TCP_MISS;
        doGetMoreData();
        return;
    }

    if (Config.onoff.offline) {
        /** \li If we are running in offline mode set to HIT */
        debugs(85, 3, "offline HIT " << *e);
        http->logType = LOG_TCP_HIT;
        doGetMoreData();
        return;
    }

    if (http->redirect.status) {
        /** \li If redirection status is True force this to be a MISS */
        debugs(85, 3, "REDIRECT status forced StoreEntry to NULL (no body on 3XX responses) " << *e);
        forgetHit();
        http->logType = LOG_TCP_REDIRECT;
        doGetMoreData();
        return;
    }

    if (!e->validToSend()) {
        debugs(85, 3, "!storeEntryValidToSend MISS " << *e);
        forgetHit();
        http->logType = LOG_TCP_MISS;
        doGetMoreData();
        return;
    }

    if (EBIT_TEST(e->flags, ENTRY_SPECIAL)) {
        /* \li Special entries are always hits, no matter what the client says */
        debugs(85, 3, "ENTRY_SPECIAL HIT " << *e);
        http->logType = LOG_TCP_HIT;
        doGetMoreData();
        return;
    }

    if (r->flags.noCache) {
        debugs(85, 3, "no-cache REFRESH MISS " << *e);
        forgetHit();
        http->logType = LOG_TCP_CLIENT_REFRESH_MISS;
        doGetMoreData();
        return;
    }

    debugs(85, 3, "default HIT " << *e);
    http->logType = LOG_TCP_HIT;
    doGetMoreData();
}

/**
 * Request more data from the store for the client Stream
 * This is *the* entry point to this module.
 *
 * Preconditions:
 *  - This is the head of the list.
 *  - There is at least one more node.
 *  - Data context is not null
 */
void
clientGetMoreData(clientStreamNode * aNode, ClientHttpRequest * http)
{
    /* Test preconditions */
    assert(aNode != NULL);
    assert(cbdataReferenceValid(aNode));
    assert(aNode->node.prev == NULL);
    assert(aNode->node.next != NULL);
    clientReplyContext *context = dynamic_cast<clientReplyContext *>(aNode->data.getRaw());
    assert (context);
    assert(context->http == http);

    clientStreamNode *next = ( clientStreamNode *)aNode->node.next->data;

    if (!context->ourNode)
        context->ourNode = aNode;

    /* no cbdatareference, this is only used once, and safely */
    if (context->flags.storelogiccomplete) {
        StoreIOBuffer tempBuffer;
        tempBuffer.offset = next->readBuffer.offset + context->headers_sz;
        tempBuffer.length = next->readBuffer.length;
        tempBuffer.data = next->readBuffer.data;

        storeClientCopy(context->sc, http->storeEntry(),
                        tempBuffer, clientReplyContext::SendMoreData, context);
        return;
    }

    if (context->http->request->method == Http::METHOD_PURGE) {
        context->purgeRequest();
        return;
    }

    // OPTIONS with Max-Forwards:0 handled in clientProcessRequest()

    if (context->http->request->method == Http::METHOD_TRACE) {
        if (context->http->request->header.getInt64(Http::HdrType::MAX_FORWARDS) == 0) {
            context->traceReply(aNode);
            return;
        }

        /* continue forwarding, not finished yet. */
        http->logType = LOG_TCP_MISS;

        context->doGetMoreData();
    } else
        context->identifyStoreObject();
}

void
clientReplyContext::doGetMoreData()
{
    /* We still have to do store logic processing - vary, cache hit etc */
    if (http->storeEntry() != NULL) {
        /* someone found the object in the cache for us */
        StoreIOBuffer localTempBuffer;

        http->storeEntry()->lock("clientReplyContext::doGetMoreData");

        http->storeEntry()->ensureMemObject(storeId(), http->log_uri, http->request->method);

        sc = storeClientListAdd(http->storeEntry(), this);
#if USE_DELAY_POOLS
        sc->setDelayId(DelayId::DelayClient(http));
#endif

        assert(http->logType.oldType == LOG_TCP_HIT);
        reqofs = 0;
        /* guarantee nothing has been sent yet! */
        assert(http->out.size == 0);
        assert(http->out.offset == 0);

        if (ConnStateData *conn = http->getConn()) {
            if (Ip::Qos::TheConfig.isHitTosActive()) {
                Ip::Qos::doTosLocalHit(conn->clientConnection);
            }

            if (Ip::Qos::TheConfig.isHitNfmarkActive()) {
                Ip::Qos::doNfmarkLocalHit(conn->clientConnection);
            }
        }

        localTempBuffer.offset = reqofs;
        localTempBuffer.length = getNextNode()->readBuffer.length;
        localTempBuffer.data = getNextNode()->readBuffer.data;
        storeClientCopy(sc, http->storeEntry(), localTempBuffer, CacheHit, this);
    } else {
        /* MISS CASE, http->logType is already set! */
        processMiss();
    }
}

/** The next node has removed itself from the stream. */
void
clientReplyDetach(clientStreamNode * node, ClientHttpRequest * http)
{
    /** detach from the stream */
    clientStreamDetach(node, http);
}

/**
 * Accepts chunk of a http message in buf, parses prefix, filters headers and
 * such, writes processed message to the message recipient
 */
void
clientReplyContext::SendMoreData(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = static_cast<clientReplyContext *>(data);
    context->sendMoreData (result);
}

void
clientReplyContext::makeThisHead()
{
    /* At least, I think thats what this does */
    dlinkDelete(&http->active, &ClientActiveRequests);
    dlinkAdd(http, &http->active, &ClientActiveRequests);
}

bool
clientReplyContext::errorInStream(StoreIOBuffer const &result, size_t const &sizeToProcess)const
{
    return /* aborted request */
        (http->storeEntry() && EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED)) ||
        /* Upstream read error */ (result.flags.error) ||
        /* Upstream EOF */ (sizeToProcess == 0);
}

void
clientReplyContext::sendStreamError(StoreIOBuffer const &result)
{
    /** call clientWriteComplete so the client socket gets closed
     *
     * We call into the stream, because we don't know that there is a
     * client socket!
     */
    debugs(88, 5, "clientReplyContext::sendStreamError: A stream error has occured, marking as complete and sending no data.");
    StoreIOBuffer localTempBuffer;
    flags.complete = 1;
    http->request->flags.streamError = true;
    localTempBuffer.flags.error = result.flags.error;
    clientStreamCallback((clientStreamNode*)http->client_stream.head->data, http, NULL,
                         localTempBuffer);
}

void
clientReplyContext::pushStreamData(StoreIOBuffer const &result, char *source)
{
    StoreIOBuffer localTempBuffer;

    if (result.length == 0) {
        debugs(88, 5, "clientReplyContext::pushStreamData: marking request as complete due to 0 length store result");
        flags.complete = 1;
    }

    assert(result.offset - headers_sz == next()->readBuffer.offset);
    localTempBuffer.offset = result.offset - headers_sz;
    localTempBuffer.length = result.length;

    if (localTempBuffer.length)
        localTempBuffer.data = source;

    clientStreamCallback((clientStreamNode*)http->client_stream.head->data, http, NULL,
                         localTempBuffer);
}

clientStreamNode *
clientReplyContext::next() const
{
    assert ( (clientStreamNode*)http->client_stream.head->next->data == getNextNode());
    return getNextNode();
}

void
clientReplyContext::sendBodyTooLargeError()
{
    Ip::Address tmp_noaddr;
    tmp_noaddr.setNoAddr(); // TODO: make a global const
    http->logType = LOG_TCP_DENIED_REPLY;
    ErrorState *err = clientBuildError(ERR_TOO_BIG, Http::scForbidden, NULL,
                                       http->getConn() != NULL ? http->getConn()->clientConnection->remote : tmp_noaddr,
                                       http->request);
    removeClientStoreReference(&(sc), http);
    HTTPMSGUNLOCK(reply);
    startError(err);

}

/// send 412 (Precondition Failed) to client
void
clientReplyContext::sendPreconditionFailedError()
{
    http->logType = LOG_TCP_HIT;
    Ip::Address tmp_noaddr;
    tmp_noaddr.setNoAddr();
    ErrorState *const err =
        clientBuildError(ERR_PRECONDITION_FAILED, Http::scPreconditionFailed,
                         NULL, http->getConn() ? http->getConn()->clientConnection->remote : tmp_noaddr, http->request);
    removeClientStoreReference(&sc, http);
    HTTPMSGUNLOCK(reply);
    startError(err);
}

/// send 304 (Not Modified) to client
void
clientReplyContext::sendNotModified()
{
    StoreEntry *e = http->storeEntry();
    const time_t timestamp = e->timestamp;
    HttpReply *const temprep = e->getReply()->make304();
    // log as TCP_INM_HIT if code 304 generated for
    // If-None-Match request
    if (!http->request->flags.ims)
        http->logType = LOG_TCP_INM_HIT;
    else
        http->logType = LOG_TCP_IMS_HIT;
    removeClientStoreReference(&sc, http);
    createStoreEntry(http->request->method, RequestFlags());
    e = http->storeEntry();
    // Copy timestamp from the original entry so the 304
    // reply has a meaningful Age: header.
    e->timestampsSet();
    e->timestamp = timestamp;
    e->replaceHttpReply(temprep);
    e->complete();
    /*
     * TODO: why put this in the store and then serialise it and
     * then parse it again. Simply mark the request complete in
     * our context and write the reply struct to the client side.
     */
    triggerInitialStoreRead();
}

/// send 304 (Not Modified) or 412 (Precondition Failed) to client
/// depending on request method
void
clientReplyContext::sendNotModifiedOrPreconditionFailedError()
{
    if (http->request->method == Http::METHOD_GET ||
            http->request->method == Http::METHOD_HEAD)
        sendNotModified();
    else
        sendPreconditionFailedError();
}

void
clientReplyContext::processReplyAccess ()
{
    /* NP: this should probably soft-fail to a zero-sized-reply error ?? */
    assert(reply);

    /** Don't block our own responses or HTTP status messages */
    if (http->logType.oldType == LOG_TCP_DENIED ||
            http->logType.oldType == LOG_TCP_DENIED_REPLY ||
            alwaysAllowResponse(reply->sline.status())) {
        headers_sz = reply->hdr_sz;
        processReplyAccessResult(ACCESS_ALLOWED);
        return;
    }

    /** Check for reply to big error */
    if (reply->expectedBodyTooLarge(*http->request)) {
        sendBodyTooLargeError();
        return;
    }

    headers_sz = reply->hdr_sz;

    /** check for absent access controls (permit by default) */
    if (!Config.accessList.reply) {
        processReplyAccessResult(ACCESS_ALLOWED);
        return;
    }

    /** Process http_reply_access lists */
    ACLFilledChecklist *replyChecklist =
        clientAclChecklistCreate(Config.accessList.reply, http);
    replyChecklist->reply = reply;
    HTTPMSGLOCK(replyChecklist->reply);
    replyChecklist->nonBlockingCheck(ProcessReplyAccessResult, this);
}

void
clientReplyContext::ProcessReplyAccessResult(allow_t rv, void *voidMe)
{
    clientReplyContext *me = static_cast<clientReplyContext *>(voidMe);
    me->processReplyAccessResult(rv);
}

void
clientReplyContext::processReplyAccessResult(const allow_t &accessAllowed)
{
    debugs(88, 2, "The reply for " << http->request->method
           << ' ' << http->uri << " is " << accessAllowed << ", because it matched "
           << (AclMatchedName ? AclMatchedName : "NO ACL's"));

    if (!accessAllowed.allowed()) {
        ErrorState *err;
        err_type page_id;
        page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName, 1);

        http->logType = LOG_TCP_DENIED_REPLY;

        if (page_id == ERR_NONE)
            page_id = ERR_ACCESS_DENIED;

        Ip::Address tmp_noaddr;
        tmp_noaddr.setNoAddr();
        err = clientBuildError(page_id, Http::scForbidden, NULL,
                               http->getConn() != NULL ? http->getConn()->clientConnection->remote : tmp_noaddr,
                               http->request);

        removeClientStoreReference(&sc, http);

        HTTPMSGUNLOCK(reply);

        startError(err);

        return;
    }

    /* Ok, the reply is allowed, */
    http->loggingEntry(http->storeEntry());

    ssize_t body_size = reqofs - reply->hdr_sz;
    if (body_size < 0) {
        reqofs = reply->hdr_sz;
        body_size = 0;
    }

    debugs(88, 3, "clientReplyContext::sendMoreData: Appending " <<
           (int) body_size << " bytes after " << reply->hdr_sz <<
           " bytes of headers");

#if USE_SQUID_ESI

    if (http->flags.accel && reply->sline.status() != Http::scForbidden &&
            !alwaysAllowResponse(reply->sline.status()) &&
            esiEnableProcessing(reply)) {
        debugs(88, 2, "Enabling ESI processing for " << http->uri);
        clientStreamInsertHead(&http->client_stream, esiStreamRead,
                               esiProcessStream, esiStreamDetach, esiStreamStatus, NULL);
    }

#endif

    if (http->request->method == Http::METHOD_HEAD) {
        /* do not forward body for HEAD replies */
        body_size = 0;
        http->flags.done_copying = true;
        flags.complete = 1;
    }

    assert (!flags.headersSent);
    flags.headersSent = true;

    StoreIOBuffer localTempBuffer;
    char *buf = next()->readBuffer.data;
    char *body_buf = buf + reply->hdr_sz;

    //Server side may disable ranges under some circumstances.

    if ((!http->request->range))
        next()->readBuffer.offset = 0;

    body_buf -= next()->readBuffer.offset;

    if (next()->readBuffer.offset != 0) {
        if (next()->readBuffer.offset > body_size) {
            /* Can't use any of the body we received. send nothing */
            localTempBuffer.length = 0;
            localTempBuffer.data = NULL;
        } else {
            localTempBuffer.length = body_size - next()->readBuffer.offset;
            localTempBuffer.data = body_buf + next()->readBuffer.offset;
        }
    } else {
        localTempBuffer.length = body_size;
        localTempBuffer.data = body_buf;
    }

    /* TODO??: move the data in the buffer back by the request header size */
    clientStreamCallback((clientStreamNode *)http->client_stream.head->data,
                         http, reply, localTempBuffer);

    return;
}

void
clientReplyContext::sendMoreData (StoreIOBuffer result)
{
    if (deleting)
        return;

    StoreEntry *entry = http->storeEntry();

    if (ConnStateData * conn = http->getConn()) {
        if (!conn->isOpen()) {
            debugs(33,3, "not sending more data to closing connection " << conn->clientConnection);
            return;
        }
        if (conn->pinning.zeroReply) {
            debugs(33,3, "not sending more data after a pinned zero reply " << conn->clientConnection);
            return;
        }

        if (reqofs==0 && !http->logType.isTcpHit()) {
            if (Ip::Qos::TheConfig.isHitTosActive()) {
                Ip::Qos::doTosLocalMiss(conn->clientConnection, http->request->hier.code);
            }
            if (Ip::Qos::TheConfig.isHitNfmarkActive()) {
                Ip::Qos::doNfmarkLocalMiss(conn->clientConnection, http->request->hier.code);
            }
        }

        debugs(88, 5, conn->clientConnection <<
               " '" << entry->url() << "'" <<
               " out.offset=" << http->out.offset);
    }

    char *buf = next()->readBuffer.data;

    if (buf != result.data) {
        /* we've got to copy some data */
        assert(result.length <= next()->readBuffer.length);
        memcpy(buf, result.data, result.length);
    }

    /* We've got the final data to start pushing... */
    flags.storelogiccomplete = 1;

    reqofs += result.length;

    assert(reqofs <= HTTP_REQBUF_SZ || flags.headersSent);

    assert(http->request != NULL);

    /* ESI TODO: remove this assert once everything is stable */
    assert(http->client_stream.head->data
           && cbdataReferenceValid(http->client_stream.head->data));

    makeThisHead();

    debugs(88, 5, "clientReplyContext::sendMoreData: " << http->uri << ", " <<
           reqofs << " bytes (" << result.length <<
           " new bytes)");

    /* update size of the request */
    reqsize = reqofs;

    if (errorInStream(result, reqofs)) {
        sendStreamError(result);
        return;
    }

    if (flags.headersSent) {
        pushStreamData (result, buf);
        return;
    }

    cloneReply();

#if USE_DELAY_POOLS
    if (sc)
        sc->setDelayId(DelayId::DelayClient(http,reply));
#endif

    /* handle headers */

    if (Config.onoff.log_mime_hdrs) {
        size_t k;

        if ((k = headersEnd(buf, reqofs))) {
            safe_free(http->al->headers.reply);
            http->al->headers.reply = (char *)xcalloc(k + 1, 1);
            xstrncpy(http->al->headers.reply, buf, k);
        }
    }

    holdingBuffer = result;
    processReplyAccess();
    return;
}

/* Using this breaks the client layering just a little!
 */
void
clientReplyContext::createStoreEntry(const HttpRequestMethod& m, RequestFlags reqFlags)
{
    assert(http != NULL);
    /*
     * For erroneous requests, we might not have a h->request,
     * so make a fake one.
     */

    if (http->request == NULL) {
        const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initClient);
        http->request = new HttpRequest(m, AnyP::PROTO_NONE, "http", null_string, mx);
        HTTPMSGLOCK(http->request);
    }

    StoreEntry *e = storeCreateEntry(storeId(), http->log_uri, reqFlags, m);

    // Make entry collapsable ASAP, to increase collapsing chances for others,
    // TODO: every must-revalidate and similar request MUST reach the origin,
    // but do we have to prohibit others from collapsing on that request?
    if (Config.onoff.collapsed_forwarding && reqFlags.cachable &&
            !reqFlags.needValidation &&
            (m == Http::METHOD_GET || m == Http::METHOD_HEAD)) {
        // make the entry available for future requests now
        (void)Store::Root().allowCollapsing(e, reqFlags, m);
    }

    sc = storeClientListAdd(e, this);

#if USE_DELAY_POOLS
    sc->setDelayId(DelayId::DelayClient(http));
#endif

    reqofs = 0;

    reqsize = 0;

    /* I don't think this is actually needed! -- adrian */
    /* http->reqbuf = http->norm_reqbuf; */
    //    assert(http->reqbuf == http->norm_reqbuf);
    /* The next line is illegal because we don't know if the client stream
     * buffers have been set up
     */
    //    storeClientCopy(http->sc, e, 0, HTTP_REQBUF_SZ, http->reqbuf,
    //        SendMoreData, this);
    /* So, we mark the store logic as complete */
    flags.storelogiccomplete = 1;

    /* and get the caller to request a read, from whereever they are */
    /* NOTE: after ANY data flows down the pipe, even one step,
     * this function CAN NOT be used to manage errors
     */
    http->storeEntry(e);
}

ErrorState *
clientBuildError(err_type page_id, Http::StatusCode status, char const *url,
                 Ip::Address &src_addr, HttpRequest * request)
{
    ErrorState *err = new ErrorState(page_id, status, request);
    err->src_addr = src_addr;

    if (url)
        err->url = xstrdup(url);

    return err;
}

