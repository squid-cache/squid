
/*
 * $Id: client_side_reply.cc,v 1.62 2003/07/23 11:21:37 robertc Exp $
 *
 * DEBUG: section 88    Client-side Reply Routines
 * AUTHOR: Robert Collins (Originally Duane Wessels in client_side.c)
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "client_side_reply.h"
#include "StoreClient.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"

#include "clientStream.h"
#include "authenticate.h"
#if ESI
#include "ESI.h"
#endif
#include "MemObject.h"
#include "ACLChecklist.h"
#include "ACL.h"
#if DELAY_POOLS
#include "DelayPools.h"
#endif
#include "client_side.h"

CBDATA_CLASS_INIT(clientReplyContext);

/* Local functions */
extern "C" CSS clientReplyStatus;
extern ErrorState *clientBuildError(err_type, http_status, char const *,

                                        struct in_addr *, request_t *);

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
}

clientReplyContext::clientReplyContext(clientHttpRequest *clientContext) : http (cbdataReference(clientContext)), old_entry (NULL), old_sc(NULL), deleting(false)
{}

/* create an error in the store awaiting the client side to read it. */
/* This may be better placed in the clientStream logic, but it has not been
 * relocated there yet
 */
void
clientReplyContext::setReplyToError(
    err_type err, http_status status, method_t method, char const *uri,

    struct in_addr *addr, request_t * failedrequest, char *unparsedrequest,
    auth_user_request_t * auth_user_request)
{
    ErrorState *errstate =
        clientBuildError(err, status, uri, addr, failedrequest);

    if (unparsedrequest)
        errstate->request_hdrs = xstrdup(unparsedrequest);

    if (status == HTTP_NOT_IMPLEMENTED && http->request)
        /* prevent confusion over whether we default to persistent or not */
        http->request->flags.proxy_keepalive = 0;

    http->al.http.code = errstate->httpStatus;

    createStoreEntry(method, request_flags());

    if (auth_user_request)
    {
        errstate->auth_user_request = auth_user_request;
        authenticateAuthUserRequestLock(errstate->auth_user_request);
    }

    assert(errstate->callback_data == NULL);
    errorAppendEntry(http->storeEntry(), errstate);
    /* Now the caller reads to get this */
}

void
clientReplyContext::removeStoreReference(store_client ** scp,
        StoreEntry ** ep)
{
    StoreEntry *e;
    store_client *sc = *scp;

    if ((e = *ep) != NULL) {
        *ep = NULL;
        storeUnregister(sc, e, this);
        *scp = NULL;
        storeUnlockObject(e);
    }
}

void
clientReplyContext::removeClientStoreReference(store_client **scp, ClientHttpRequest *http)
{
    StoreEntry *reference = http->storeEntry();
    removeStoreReference(scp, &reference);
    http->storeEntry(reference);
}

void *
clientReplyContext::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (clientReplyContext));
    CBDATA_INIT_TYPE(clientReplyContext);
    return cbdataAlloc(clientReplyContext);
}

void
clientReplyContext::operator delete (void *address)
{
    clientReplyContext * tmp = (clientReplyContext *)address;
    cbdataFree (tmp);
}

void
clientReplyContext::deleteSelf() const
{
    delete this;
}

void
clientReplyContext::saveState()
{
    assert(old_sc == NULL);
    debug(88, 3)("clientReplyContext::saveState: saving store context\n");
    old_entry = http->storeEntry();
    old_sc = sc;
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
    debug(88, 3)("clientReplyContext::restoreState: Restoring store context\n");
    removeClientStoreReference(&sc, http);
    http->storeEntry(old_entry);
    sc = old_sc;
    reqsize = old_reqsize;
    reqofs = tempBuffer.offset;
    /* Prevent accessed the old saved entries */
    old_entry = NULL;
    old_sc = NULL;
    old_reqsize = 0;
    tempBuffer.offset = 0;
}

void
clientReplyContext::startError(ErrorState * err)
{
    createStoreEntry(http->request->method, request_flags());
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
    StoreIOBuffer tempBuffer;
    /* when confident, 0 becomes reqofs, and then this factors into
     * startSendProcess 
     */
    assert(reqofs == 0);
    tempBuffer.offset = 0;
    tempBuffer.length = next()->readBuffer.length;
    tempBuffer.data = next()->readBuffer.data;
    storeClientCopy(sc, http->storeEntry(), tempBuffer, SendMoreData, this);
}

/* there is an expired entry in the store.
 * setup a temporary buffer area and perform an IMS to the origin
 */
void
clientReplyContext::processExpired()
{
    char *url = http->uri;
    StoreEntry *entry = NULL;
    debug(88, 3)("clientReplyContext::processExpired: '%s'", http->uri);
    assert(http->storeEntry()->lastmod >= 0);
    /*
     * check if we are allowed to contact other servers
     * @?@: Instead of a 504 (Gateway Timeout) reply, we may want to return 
     *      a stale entry *if* it matches client requirements
     */

    if (http->onlyIfCached()) {
        processOnlyIfCachedMiss();
        return;
    }

    http->request->flags.refresh = 1;
#if STORE_CLIENT_LIST_DEBUG
    /* Prevent a race with the store client memory free routines
     */
    assert(storeClientIsThisAClient(sc, this));
#endif
    /* Prepare to make a new temporary request */
    saveState();
    entry = storeCreateEntry(url,
                             http->log_uri, http->request->flags, http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    sc = storeClientListAdd(entry, this);
#if DELAY_POOLS
    /* delay_id is already set on original store client */
    sc->setDelayId(DelayId::DelayClient(http));
#endif

    http->request->lastmod = old_entry->lastmod;
    debug(88, 5)("clientReplyContext::processExpired : lastmod %ld",
                 (long int) entry->lastmod);
    http->storeEntry(entry);
    assert(http->out.offset == 0);
    fwdStart(http->getConn().getRaw() != NULL ? http->getConn()->fd : -1, http->storeEntry(), http->request);
    /* Register with storage manager to receive updates when data comes in. */

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
        debug(88, 0) ("clientReplyContext::processExpired: Found ENTRY_ABORTED object");

    {
        /* start counting the length from 0 */
        StoreIOBuffer tempBuffer(HTTP_REQBUF_SZ, 0, tempbuf);
        storeClientCopy(sc, entry, tempBuffer, HandleIMSReply, this);
    }
}

bool
clientReplyContext::clientGetsOldEntry()const
{
    const http_status status = http->storeEntry()->getReply()->sline.status;

    if (0 == status) {
        debug(88, 5) ("clientGetsOldEntry: YES, broken HTTP reply\n");
        return true;
    }

    /* If the reply is a failure then send the old object as a last
     * resort */
    if (status >= 500 && status < 600) {
        debug(88, 3) ("clientGetsOldEntry: YES, failure reply=%d\n", status);
        return true;
    }

    /* If the reply is anything but "Not Modified" then
     * we must forward it to the client */
    if (HTTP_NOT_MODIFIED != status) {
        debug(88, 5) ("clientGetsOldEntry: NO, reply=%d\n", status);
        return false;
    }

    /* If the client did not send IMS in the request, then it
     * must get the old object, not this "Not Modified" reply 
     * REGARDLESS of validation */
    if (!http->request->flags.ims) {
        debug(88, 5) ("clientGetsOldEntry: YES, no client IMS\n");
        return true;
    }

    /* If key metadata in the reply are not consistent with the
     * old entry, we must use the new reply.
     * Note: this means that the server is sending garbage replies 
     * in that it has sent an IMS that is incompatible with our request!?
     */
    /* This is a duplicate call through the HandleIMS code path.
     * Can we guarantee we don't need it elsewhere?
     */
    if (!httpReplyValidatorsMatch(http->storeEntry()->getReply(),
                                  old_entry->getReply())) {
        debug(88, 5) ("clientGetsOldEntry: NO, Old object has been invalidated"
                      "by the new one\n");
        return false;
    }

    /* If the client IMS time is prior to the entry LASTMOD time we
     * need to send the old object */
    if (old_entry->modifiedSince(http->request)) {
        debug(88, 5) ("clientGetsOldEntry: YES, modified since %ld\n",
                      (long int) http->request->ims);
        return true;
    }

    debug(88, 5) ("clientGetsOldEntry: NO, new one is fine\n");
    return false;
}

void
clientReplyContext::sendClientUpstreamResponse()
{
    StoreIOBuffer tempresult;
    http->logType = LOG_TCP_REFRESH_MISS;
    removeStoreReference(&old_sc, &old_entry);
    /* here the data to send is the data we just recieved */
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

void
clientReplyContext::cleanUpAfterIMSCheck()
{
    debug(88, 3) ("clientHandleIMSReply: ABORTED '%s'\n", storeUrl(http->storeEntry()));
    /* We have an existing entry, but failed to validate it */
    /* Its okay to send the old one anyway */
    http->logType = LOG_TCP_REFRESH_FAIL_HIT;
    sendClientOldEntry();
}

void
clientReplyContext::handlePartialIMSHeaders()
{
    /* more headers needed to decide */
    debug(88, 3) ("clientHandleIMSReply: Incomplete headers for '%s'\n",
                  storeUrl(http->storeEntry()));

    if (reqsize >= HTTP_REQBUF_SZ) {
        /* will not get any bigger than that */
        debug(88, 3)
        ("clientHandleIMSReply: Reply is too large '%s', using old entry\n",
         storeUrl(http->storeEntry()));
        /* use old entry, this repeats the code above */
        http->logType = LOG_TCP_REFRESH_FAIL_HIT;
        sendClientOldEntry();
    } else {
        reqofs = reqsize;
        waitForMoreData();
    }
}

void
clientReplyContext::handleIMSGiveClientUpdatedOldEntry()
{
    /* We initiated the IMS request and the IMS is compatible with
     * our object. As the client is not expecting
     * 304, so put the good one back.  First, make sure the old entry
     * headers have been loaded from disk. */
    http->logType = LOG_TCP_REFRESH_HIT;

    if (httpReplyValidatorsMatch(http->storeEntry()->getReply(),
                                 old_entry->getReply())) {
        int unlink_request = 0;

        if (old_entry->mem_obj->request == NULL) {
            old_entry->mem_obj->request = requestLink(http->memObject()->request);
            unlink_request = 1;
        }

        /* Don't memcpy() the whole reply structure here.  For example,
         * www.thegist.com (Netscape/1.13) returns a content-length for
         * 304's which seems to be the length of the 304 HEADERS!!! and
         * not the body they refer to.  */
        httpReplyUpdateOnNotModified((HttpReply *)old_entry->getReply(), http->storeEntry()->getReply());

        storeTimestampsSet(old_entry);

        old_entry->timestamp = squid_curtime;

        if (unlink_request) {
            requestUnlink(old_entry->mem_obj->request);
            old_entry->mem_obj->request = NULL;
        }
    }

    sendClientOldEntry();
}

void
clientReplyContext::handleIMSGiveClientNewEntry()
{
    /* The client gets the new entry,
     * either as a 304 (they initiated the IMS) or
     * as a full request from the upstream
     * The new entry is *not* a 304 reply, or
     * is a 304 that is incompatible with our cached entities.
     */

    if (http->request->flags.ims) {
        /* The client asked for a IMS, and can deal
         * with any reply
         * XXX TODO: invalidate our object if it's not valid any more.
         * Send the IMS reply to the client.
         */
        sendClientUpstreamResponse();
    } else if (httpReplyValidatorsMatch (http->storeEntry()->getReply(),
                                         old_entry->getReply())) {
        /* Our object is usable once updated */
        /* the client did not ask for IMS, send the whole object
         */
        /* the client needs to get this reply */
        StoreIOBuffer tempresult;
        http->logType = LOG_TCP_REFRESH_MISS;

        if (HTTP_NOT_MODIFIED == http->storeEntry()->getReply()->sline.status) {
            httpReplyUpdateOnNotModified((HttpReply *)old_entry->getReply(),
                                         http->storeEntry()->getReply());
            storeTimestampsSet(old_entry);
            http->logType = LOG_TCP_REFRESH_HIT;
        }

        removeStoreReference(&old_sc, &old_entry);
        /* here the data to send is the data we just recieved */
        tempBuffer.offset = 0;
        old_reqsize = 0;
        /* clientSendMoreData tracks the offset as well.
         * Force it back to zero */
        reqofs = 0;
        assert(!EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED));
        /* TODO: provide SendMoreData with the ready parsed reply */
        tempresult.length = reqsize;
        tempresult.data = tempbuf;
        sendMoreData(tempresult);
    } else {
        /* the client asked for the whole object, and
         * 1) our object was stale
         * 2) our internally generated IMS failed to validate
         * 3) the server sent incompatible headers in it's reply
         */
        http->logType = LOG_TCP_REFRESH_MISS;
        processMiss();
        /* We start over for everything except IMS because:
         * 1) HEAD requests will go straight through now
         * 2) GET requests will go straight through now
         * 3) IMS requests are a corner case. If the server
         * decided to give us different data, we should give
         * that to the client, which means returning our IMS request.
         */
    }
}

void
clientReplyContext::handleIMSReply(StoreIOBuffer result)
{
    if (deleting)
        return;

    debug(88, 3) ("clientHandleIMSReply: %s, %lu bytes\n",
                  storeUrl(http->storeEntry()),
                  (long unsigned) result.length);

    if (http->storeEntry() == NULL)
        return;

    if (result.flags.error && !EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED))
        return;

    /* update size of the request */
    reqsize = result.length + reqofs;

    http_status status = http->storeEntry()->getReply()->sline.status;

    if (EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED))
        cleanUpAfterIMSCheck();
    else if (STORE_PENDING == http->storeEntry()->store_status && 0 == status)
        handlePartialIMSHeaders();
    else if (clientGetsOldEntry())
        handleIMSGiveClientUpdatedOldEntry();
    else
        handleIMSGiveClientNewEntry();
}

extern "C" CSR clientGetMoreData;
extern "C" CSD clientReplyDetach;

/*
 * clientCacheHit should only be called until the HTTP reply headers
 * have been parsed.  Normally this should be a single call, but
 * it might take more than one.  As soon as we have the headers,
 * we hand off to clientSendMoreData, processExpired, or
 * processMiss.
 */
void
clientReplyContext::CacheHit(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = (clientReplyContext *)data;
    context->cacheHit (result);
}

void
clientReplyContext::cacheHit(StoreIOBuffer result)
{
    if (deleting)
        return;

    StoreEntry *e = http->storeEntry();

    request_t *r = http->request;

    debug(88, 3) ("clientCacheHit: %s, %ud bytes\n", http->uri, (unsigned int)result.length);

    if (http->storeEntry() == NULL) {
        debug(88, 3) ("clientCacheHit: request aborted\n");
        return;
    } else if (result.flags.error) {
        /* swap in failure */
        debug(88, 3) ("clientCacheHit: swapin failure for %s\n", http->uri);
        http->logType = LOG_TCP_SWAPFAIL_MISS;
        removeClientStoreReference(&sc, http);
        processMiss();
        return;
    }

    if (result.length == 0) {
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

    if (e->getReply()->sline.status == 0) {
        /*
         * we don't have full reply headers yet; either wait for more or
         * punt to clientProcessMiss.
         */

        if (e->mem_status == IN_MEMORY || e->store_status == STORE_OK) {
            processMiss();
        } else if (result.length + reqofs >= HTTP_REQBUF_SZ
                   && http->out.offset == 0) {
            processMiss();
        } else {
            debug(88, 3) ("clientCacheHit: waiting for HTTP reply headers\n");
            reqofs += result.length;
            assert(reqofs <= HTTP_REQBUF_SZ);
            /* get the next users' buffer */
            StoreIOBuffer tempBuffer;
            tempBuffer.offset = http->out.offset + reqofs;
            tempBuffer.length = next()->readBuffer.length - reqofs;
            tempBuffer.data = next()->readBuffer.data + reqofs;
            storeClientCopy(sc, e,
                            tempBuffer, CacheHit, this);
        }

        return;
    }

    /*
     * Got the headers, now grok them
     */
    assert(http->logType == LOG_TCP_HIT);

    switch (varyEvaluateMatch(e, r)) {

    case VARY_NONE:
        /* No variance detected. Continue as normal */
        break;

    case VARY_MATCH:
        /* This is the correct entity for this request. Continue */
        debug(88, 2) ("clientProcessHit: Vary MATCH!\n");
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
        debug(88, 2) ("clientProcessHit: Vary detected!\n");
        clientGetMoreData(ourNode, http);
        return;

    case VARY_CANCEL:
        /* varyEvaluateMatch found a object loop. Process as miss */
        debug(88, 1) ("clientProcessHit: Vary object loop!\n");
        processMiss();
        return;
    }

    if (r->method == METHOD_PURGE) {
        removeClientStoreReference(&sc, http);
        e = NULL;
        purgeRequest();
        return;
    }

    if (storeCheckNegativeHit(e)) {
        http->logType = LOG_TCP_NEGATIVE_HIT;
        sendMoreData(result);
    } else if (!Config.onoff.offline && refreshCheckHTTP(e, r) && !http->flags.internal) {
        debug(88, 5) ("clientCacheHit: in refreshCheck() block\n");
        /*
         * We hold a stale copy; it needs to be validated
         */
        /*
         * The 'need_validation' flag is used to prevent forwarding
         * loops between siblings.  If our copy of the object is stale,
         * then we should probably only use parents for the validation
         * request.  Otherwise two siblings could generate a loop if
         * both have a stale version of the object.
         */
        r->flags.need_validation = 1;

        if (e->lastmod < 0) {
            /*
             * Previous reply didn't have a Last-Modified header,
             * we cannot revalidate it.
             */
            http->logType = LOG_TCP_MISS;
            processMiss();
        } else if (r->flags.nocache) {
            /*
             * This did not match a refresh pattern that overrides no-cache
             * we should honour the client no-cache header.
             */
            http->logType = LOG_TCP_CLIENT_REFRESH_MISS;
            processMiss();
        } else if (r->protocol == PROTO_HTTP) {
            /*
             * Object needs to be revalidated
             * XXX This could apply to FTP as well, if Last-Modified is known.
             */
            http->logType = LOG_TCP_REFRESH_MISS;
            processExpired();
        } else {
            /*
             * We don't know how to re-validate other protocols. Handle
             * them as if the object has expired.
             */
            http->logType = LOG_TCP_MISS;
            processMiss();
        }
    } else if (r->flags.ims) {
        /*
         * Handle If-Modified-Since requests from the client
         */

        if (e->getReply()->sline.status != HTTP_OK) {
            debug(88, 4) ("clientCacheHit: Reply code %d != 200\n",
                          e->getReply()->sline.status);
            http->logType = LOG_TCP_MISS;
            processMiss();
        } else if (e->modifiedSince(http->request)) {
            http->logType = LOG_TCP_IMS_HIT;
            sendMoreData(result);
        } else {
            time_t const timestamp = e->timestamp;
            HttpReply *temprep = httpReplyMake304 (e->getReply());
            http->logType = LOG_TCP_IMS_HIT;
            removeClientStoreReference(&sc, http);
            createStoreEntry(http->request->method,
                             request_flags());
            e = http->storeEntry();
            /*
             * Copy timestamp from the original entry so the 304
             * reply has a meaningful Age: header.
             */
            e->timestamp = timestamp;
            httpReplySwapOut (temprep, e);
            e->complete();
            /* TODO: why put this in the store and then serialise it and then parse it again.
             * Simply mark the request complete in our context and
             * write the reply struct to the client side
             */
            triggerInitialStoreRead();
        }
    } else {
        /*
         * plain ol' cache hit
         */

        if (e->mem_status == IN_MEMORY)
            http->logType = LOG_TCP_MEM_HIT;
        else if (Config.onoff.offline)
            http->logType = LOG_TCP_OFFLINE_HIT;

        sendMoreData(result);
    }
}

/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 */
void
clientReplyContext::processMiss()
{
    char *url = http->uri;
    request_t *r = http->request;
    ErrorState *err = NULL;
    debug(88, 4) ("clientProcessMiss: '%s %s'\n",
                  RequestMethodStr[r->method], url);
    /*
     * We might have a left-over StoreEntry from a failed cache hit
     * or IMS request.
     */

    if (http->storeEntry()) {
        if (EBIT_TEST(http->storeEntry()->flags, ENTRY_SPECIAL)) {
            debug(88, 0) ("clientProcessMiss: miss on a special object (%s).\n",
                          url);
            debug(88, 0) ("\tlog_type = %s\n", log_tags[http->logType]);
            storeEntryDump(http->storeEntry(), 1);
        }

        removeClientStoreReference(&sc, http);
    }

    if (r->method == METHOD_PURGE) {
        purgeRequest();
        return;
    }

    if (http->onlyIfCached()) {
        processOnlyIfCachedMiss();
        return;
    }

    /*
     * Deny loops when running in accelerator/transproxy mode.
     */
    if (http->flags.accel && r->flags.loopdetect) {
        http->al.http.code = HTTP_FORBIDDEN;
        err =
            clientBuildError(ERR_ACCESS_DENIED, HTTP_FORBIDDEN, NULL,
                             &http->getConn()->peer.sin_addr, http->request);
        createStoreEntry(r->method, request_flags());
        errorAppendEntry(http->storeEntry(), err);
        triggerInitialStoreRead();
        return;
    } else {
        assert(http->out.offset == 0);
        createStoreEntry(r->method, r->flags);
        triggerInitialStoreRead();

        if (http->redirect.status) {
            HttpReply *rep = httpReplyCreate();
#if LOG_TCP_REDIRECTS

            http->logType = LOG_TCP_REDIRECT;
#endif

            storeReleaseRequest(http->storeEntry());
            httpRedirectReply(rep, http->redirect.status,
                              http->redirect.location);
            httpReplySwapOut(rep, http->storeEntry());
            http->storeEntry()->complete();
            return;
        }

        if (http->flags.internal)
            r->protocol = PROTO_INTERNAL;

        fwdStart(http->getConn().getRaw() != NULL ? http->getConn()->fd : -1, http->storeEntry(), r);
    }
}

/*
 * client issued a request with an only-if-cached cache-control directive;
 * we did not find a cached object that can be returned without
 *     contacting other servers;
 * respond with a 504 (Gateway Timeout) as suggested in [RFC 2068]
 */
void
clientReplyContext::processOnlyIfCachedMiss()
{
    ErrorState *err = NULL;
    debug(88, 4) ("clientProcessOnlyIfCachedMiss: '%s %s'\n",
                  RequestMethodStr[http->request->method], http->uri);
    http->al.http.code = HTTP_GATEWAY_TIMEOUT;
    err = clientBuildError(ERR_ONLY_IF_CACHED_MISS, HTTP_GATEWAY_TIMEOUT, NULL,
                           &http->getConn()->peer.sin_addr, http->request);
    removeClientStoreReference(&sc, http);
    startError(err);
}

void
clientReplyContext::purgeRequestFindObjectToPurge()
{
    /* Try to find a base entry */
    http->flags.purging = 1;
    lookingforstore = 1;
    StoreEntry::getPublicByRequestMethod(this, http->request, METHOD_GET);
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
        StoreEntry::getPublicByRequestMethod(this, http->request, METHOD_HEAD);
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
    StoreIOBuffer tempBuffer;
    /* Swap in the metadata */
    http->storeEntry(entry);
    storeLockObject(http->storeEntry());
    storeCreateMemObject(http->storeEntry(), http->uri, http->log_uri);
    http->storeEntry()->mem_obj->method = http->request->method;
    sc = storeClientListAdd(http->storeEntry(), this);
    http->logType = LOG_TCP_HIT;
    reqofs = 0;
    tempBuffer.offset = http->out.offset;
    tempBuffer.length = next()->readBuffer.length;
    tempBuffer.data = next()->readBuffer.data;
    storeClientCopy(sc, http->storeEntry(),
                    tempBuffer, CacheHit, this);
}

void
clientReplyContext::purgeRequest()
{
    debug(88, 3) ("Config2.onoff.enable_purge = %d\n",
                  Config2.onoff.enable_purge);

    if (!Config2.onoff.enable_purge) {
        http->logType = LOG_TCP_DENIED;
        ErrorState *err =
            clientBuildError(ERR_ACCESS_DENIED, HTTP_FORBIDDEN, NULL,
                             &http->getConn()->peer.sin_addr, http->request);
        startError(err);
        return;
    }

    /* Release both IP cache */
    ipcacheInvalidate(http->request->host);

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
    StoreEntry::getPublicByRequestMethod(this,http->request, METHOD_GET);
}

void
clientReplyContext::purgeDoPurgeGet(StoreEntry *newEntry)
{
    assert (newEntry);
    /* Move to new() when that is created */
    purgeStatus = HTTP_NOT_FOUND;

    if (!newEntry->isNull()) {
        /* Release the cached URI */
        debug(88, 4) ("clientPurgeRequest: GET '%s'\n", storeUrl(newEntry));
        storeRelease(newEntry);
        purgeStatus = HTTP_OK;
    }

    lookingforstore = 4;
    StoreEntry::getPublicByRequestMethod(this, http->request, METHOD_HEAD);
}

void
clientReplyContext::purgeDoPurgeHead(StoreEntry *newEntry)
{
    if (newEntry && !newEntry->isNull()) {
        debug(88, 4) ("clientPurgeRequest: HEAD '%s'\n", storeUrl(newEntry));
        storeRelease(newEntry);
        purgeStatus = HTTP_OK;
    }

    HttpReply *r;
    http_version_t version;

    /* And for Vary, release the base URI if none of the headers was included in the request */

    if (http->request->vary_headers
            && !strstr(http->request->vary_headers, "=")) {
        StoreEntry *entry = storeGetPublic(urlCanonical(http->request), METHOD_GET);

        if (entry) {
            debug(88, 4) ("clientPurgeRequest: Vary GET '%s'\n",
                          storeUrl(entry));
            storeRelease(entry);
            purgeStatus = HTTP_OK;
        }

        entry = storeGetPublic(urlCanonical(http->request), METHOD_HEAD);

        if (entry) {
            debug(88, 4) ("clientPurgeRequest: Vary HEAD '%s'\n",
                          storeUrl(entry));
            storeRelease(entry);
            purgeStatus = HTTP_OK;
        }
    }

    /*
     * Make a new entry to hold the reply to be written
     * to the client.
     */
    /* FIXME: This doesn't need to go through the store. Simply
     * push down the client chain
     */
    createStoreEntry(http->request->method, request_flags());

    triggerInitialStoreRead();

    r = httpReplyCreate();

    httpBuildVersion(&version, 1, 0);

    httpReplySetHeaders(r, version, purgeStatus, NULL, NULL, 0, 0, -1);

    httpReplySwapOut(r, http->storeEntry());

    http->storeEntry()->complete();
}

void
clientReplyContext::traceReply(clientStreamNode * node)
{
    HttpReply *rep;
    http_version_t version;
    clientStreamNode *next = (clientStreamNode *)node->node.next->data;
    StoreIOBuffer tempBuffer;
    assert(http->request->max_forwards == 0);
    createStoreEntry(http->request->method, request_flags());
    tempBuffer.offset = next->readBuffer.offset + headers_sz;
    tempBuffer.length = next->readBuffer.length;
    tempBuffer.data = next->readBuffer.data;
    storeClientCopy(sc, http->storeEntry(),
                    tempBuffer, SendMoreData, this);
    storeReleaseRequest(http->storeEntry());
    storeBuffer(http->storeEntry());
    rep = httpReplyCreate();
    httpBuildVersion(&version, 1, 0);
    httpReplySetHeaders(rep, version, HTTP_OK, NULL, "text/plain",
                        httpRequestPrefixLen(http->request), 0, squid_curtime);
    httpReplySwapOut(rep, http->storeEntry());
    httpRequestSwapOut(http->request, http->storeEntry());
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
    if (http->out.offset >= objectLen(http->storeEntry()) - headers_sz)
        return 1;

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
    HttpReply const *reply = mem->getReply();

    if (headers_sz == 0)
        /* haven't found end of headers yet */
        return 0;

    int sending = SENDING_BODY;

    if (reply->sline.status == HTTP_NO_CONTENT ||
            reply->sline.status == HTTP_NOT_MODIFIED ||
            reply->sline.status < HTTP_OK ||
            http->request->method == METHOD_HEAD)
        sending = SENDING_HDRSONLY;

    /*
     * Figure out how much data we are supposed to send.
     * If we are sending a body and we don't have a content-length,
     * then we must wait for the object to become STORE_OK.
     */
    if (reply->content_length < 0)
        return 0;

    size_t expectedLength = http->out.headers_sz + reply->content_length;

    if (http->out.size < expectedLength)
        return 0;
    else
        return 1;
}


/* A write has completed, what is the next status based on the
 * canonical request data?
 * 1 something is wrong
 * 0 nothing is wrong.
 *
 */
int
clientHttpRequestStatus(int fd, clientHttpRequest const *http)
{
#if SIZEOF_SIZE_T == 4

    if (http->out.size > 0x7FFF0000) {
        debug(88, 1) ("WARNING: closing FD %d to prevent counter overflow\n",
                      fd);
        debug(88, 1) ("\tclient %s\n",
                      inet_ntoa(http->getConn().getRaw() != NULL ? http->getConn()->peer.sin_addr : no_addr));
        debug(88, 1) ("\treceived %d bytes\n", (int) http->out.size);
        debug(88, 1) ("\tURI %s\n", http->log_uri);
        return 1;
    }

#endif
#if SIZEOF_OFF_T == 4
    if (http->out.offset > 0x7FFF0000) {
        debug(88, 1) ("WARNING: closing FD %d to prevent counter overflow\n",
                      fd);
        debug(88, 1) ("\tclient %s\n",
                      inet_ntoa(http->getConn().getRaw() != NULL ? http->getConn()->peer.sin_addr : no_addr));
        debug(88, 1) ("\treceived %d bytes (offset %d)\n", (int) http->out.size,
                      (int) http->out.offset);
        debug(88, 1) ("\tURI %s\n", http->log_uri);
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
clientReplyStatus(clientStreamNode * aNode, clientHttpRequest * http)
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

    if (http->storeEntry() == NULL)
        return STREAM_FAILED;	/* yuck, but what can we do? */

    if (EBIT_TEST(http->storeEntry()->flags, ENTRY_ABORTED))
        /* TODO: Could upstream read errors (result.flags.error) be
         * lost, and result in undersize requests being considered
         * complete. Should we tcp reset such connections ?
         */
        return STREAM_FAILED;

    if ((done = checkTransferDone()) != 0 || flags.complete) {
        debug(88, 5) ("clientReplyStatus: transfer is DONE\n");
        /* Ok we're finished, but how? */

        if (httpReplyBodySize(http->request->method,
                              http->storeEntry()->getReply()) < 0) {
            debug(88, 5) ("clientReplyStatus: closing, content_length < 0\n");
            return STREAM_FAILED;
        }

        if (!done) {
            debug(88, 5) ("clientReplyStatus: closing, !done, but read 0 bytes\n");
            return STREAM_FAILED;
        }

        if (!http->gotEnough()) {
            debug(88, 5) ("clientReplyStatus: client didn't get all it expected\n");
            return STREAM_UNPLANNED_COMPLETE;
        }

        if (http->request->flags.proxy_keepalive) {
            debug(88, 5) ("clientReplyStatus: stream complete and can keepalive\n");
            return STREAM_COMPLETE;
        }

        debug(88, 5) ("clientReplyStatus: stream was not expected to complete!\n");
        return STREAM_UNPLANNED_COMPLETE;
    }

    if (http->isReplyBodyTooLarge(http->out.offset - 4096)) {
        /* 4096 is a margin for the HTTP headers included in out.offset */
        debug(88, 5) ("clientReplyStatus: client reply body is too large\n");
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
clientReplyContext::alwaysAllowResponse(http_status sline) const
{
    switch (sline) {

    case HTTP_CONTINUE:

    case HTTP_SWITCHING_PROTOCOLS:

    case HTTP_PROCESSING:

    case HTTP_NO_CONTENT:

    case HTTP_NOT_MODIFIED:
        return true;
        /* unreached */
        break;

    default:
        return false;
    }
}

void
clientReplyContext::obeyConnectionHeader()
{
    HttpHeader *hdr = &holdingReply->header;
    hdr->removeConnectionHeaderEntries();
}

/*
 * filters out unwanted entries from original reply header
 * adds extra entries if we have more info than origin server
 * adds Squid specific entries
 */
void
clientReplyContext::buildReplyHeader()
{
    HttpHeader *hdr = &holdingReply->header;
    int is_hit = logTypeIsATcpHit(http->logType);
    request_t *request = http->request;
#if DONT_FILTER_THESE
    /* but you might want to if you run Squid as an HTTP accelerator */
    /* httpHeaderDelById(hdr, HDR_ACCEPT_RANGES); */
    httpHeaderDelById(hdr, HDR_ETAG);
#endif

    httpHeaderDelById(hdr, HDR_PROXY_CONNECTION);
    /* here: Keep-Alive is a field-name, not a connection directive! */
    httpHeaderDelByName(hdr, "Keep-Alive");
    /* remove Set-Cookie if a hit */

    if (is_hit)
        httpHeaderDelById(hdr, HDR_SET_COOKIE);

    obeyConnectionHeader();

    //    if (request->range)
    //      clientBuildRangeHeader(http, holdingReply);
    /*
     * Add a estimated Age header on cache hits.
     */
    if (is_hit) {
        /*
         * Remove any existing Age header sent by upstream caches
         * (note that the existing header is passed along unmodified
         * on cache misses)
         */
        httpHeaderDelById(hdr, HDR_AGE);
        /*
         * This adds the calculated object age. Note that the details of the
         * age calculation is performed by adjusting the timestamp in
         * storeTimestampsSet(), not here.
         *
         * BROWSER WORKAROUND: IE sometimes hangs when receiving a 0 Age
         * header, so don't use it unless there is a age to report. Please
         * note that Age is only used to make a conservative estimation of
         * the objects age, so a Age: 0 header does not add any useful
         * information to the reply in any case.
         */

        if (NULL == http->storeEntry())
            (void) 0;
        else if (http->storeEntry()->timestamp < 0)
            (void) 0;
        else if (http->storeEntry()->timestamp < squid_curtime) {
            httpHeaderPutInt(hdr, HDR_AGE,
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
                char tempbuf[512];
                snprintf (tempbuf, sizeof(tempbuf), "%s %s %s",
                          "113", ThisCache,
                          "This cache hit is still fresh and more than 1 day old");
                httpHeaderPutStr(hdr, HDR_WARNING, tempbuf);
            }
        }

    }

    /* Filter unproxyable authentication types */
    if (http->logType != LOG_TCP_DENIED &&
            (httpHeaderHas(hdr, HDR_WWW_AUTHENTICATE) || httpHeaderHas(hdr, HDR_PROXY_AUTHENTICATE))) {
        HttpHeaderPos pos = HttpHeaderInitPos;
        HttpHeaderEntry *e;

        while ((e = httpHeaderGetEntry(hdr, &pos))) {
            if (e->id == HDR_WWW_AUTHENTICATE || e->id == HDR_PROXY_AUTHENTICATE) {
                const char *value = e->value.buf();

                if ((strncasecmp(value, "NTLM", 4) == 0 &&
                        (value[4] == '\0' || value[4] == ' '))
                        ||
                        (strncasecmp(value, "Negotiate", 9) == 0 &&
                         (value[9] == '\0' || value[9] == ' ')))
                    httpHeaderDelAt(hdr, pos);
            }
        }
    }

    /* Handle authentication headers */
    if (request->auth_user_request)
        authenticateFixHeader(holdingReply, request->auth_user_request, request,
                              http->flags.accel, 0);

    /* Append X-Cache */
    httpHeaderPutStrf(hdr, HDR_X_CACHE, "%s from %s",
                      is_hit ? "HIT" : "MISS", getMyHostname());

#if USE_CACHE_DIGESTS
    /* Append X-Cache-Lookup: -- temporary hack, to be removed @?@ @?@ */
    httpHeaderPutStrf(hdr, HDR_X_CACHE_LOOKUP, "%s from %s:%d",
                      lookup_type ? lookup_type : "NONE",
                      getMyHostname(), getMyPort());

#endif

    if (httpReplyBodySize(request->method, holdingReply) < 0) {
        debug(88,
              3)
        ("clientBuildReplyHeader: can't keep-alive, unknown body size\n");
        request->flags.proxy_keepalive = 0;
    }

    /* Append VIA */
    {
        LOCAL_ARRAY(char, bbuf, MAX_URL + 32);
        String strVia = httpHeaderGetList(hdr, HDR_VIA);
        snprintf(bbuf, sizeof(bbuf), "%d.%d %s",
                 holdingReply->sline.version.major,
                 holdingReply->sline.version.minor,
                 ThisCache);
        strListAdd(&strVia, bbuf, ',');
        httpHeaderDelById(hdr, HDR_VIA);
        httpHeaderPutStr(hdr, HDR_VIA, strVia.buf());
        strVia.clean();
    }
    /* Signal keep-alive if needed */
    httpHeaderPutStr(hdr,
                     http->flags.accel ? HDR_CONNECTION : HDR_PROXY_CONNECTION,
                     request->flags.proxy_keepalive ? "keep-alive" : "close");

#if ADD_X_REQUEST_URI
    /*
     * Knowing the URI of the request is useful when debugging persistent
     * connections in a client; we cannot guarantee the order of http headers,
     * but X-Request-URI is likely to be the very last header to ease use from a
     * debugger [hdr->entries.count-1].
     */
    httpHeaderPutStr(hdr, HDR_X_REQUEST_URI,
                     http->memOjbect()->url ? http->memObject()->url : http->uri);

#endif

    httpHdrMangleList(hdr, request);
}


void
clientReplyContext::buildReply(const char *buf, size_t size)
{
    size_t k = headersEnd(buf, size);

    if (!k)
        return;

    holdReply(httpReplyCreate());

    if (!httpReplyParse(holdingReply, buf, k)) {
        /* parsing failure, get rid of the invalid reply */
        httpReplyDestroy(holdingReply);
        holdReply (NULL);
        /* This is wrong. httpReplyDestroy should to the rep
         * for us, and we can destroy our own range info
         */

        if (http->request->range) {
            /* this will fail and destroy request->range */
            //          clientBuildRangeHeader(http, holdingReply);
        }

    }

    /* enforce 1.0 reply version */
    httpBuildVersion(&holdingReply->sline.version, 1, 0);

    /* do header conversions */
    buildReplyHeader();
}

void
clientReplyContext::identifyStoreObject()
{
    request_t *r = http->request;

    if (r->flags.cachable || r->flags.internal) {
        lookingforstore = 5;
        StoreEntry::getPublicByRequest (this, r);
    } else
        identifyFoundObject (NullStoreEntry::getInstance());
}

void
clientReplyContext::identifyFoundObject(StoreEntry *newEntry)
{
    StoreEntry *e = newEntry;
    request_t *r = http->request;

    if (e->isNull()) {
        http->storeEntry(NULL);
    } else {
        http->storeEntry(e);
    }

    e = http->storeEntry();
    /* Release negatively cached IP-cache entries on reload */

    if (r->flags.nocache)
        ipcacheInvalidate(r->host);

#if HTTP_VIOLATIONS

    else if (r->flags.nocache_hack)
        ipcacheInvalidate(r->host);

#endif
#if USE_CACHE_DIGESTS

    lookup_type = http->storeEntry() ? "HIT" : "MISS";

#endif

    if (NULL == http->storeEntry()) {
        /* this object isn't in the cache */
        debug(85, 3) ("clientProcessRequest2: storeGet() MISS\n");
        http->logType = LOG_TCP_MISS;
        doGetMoreData();
        return;
    }

    if (Config.onoff.offline) {
        debug(85, 3) ("clientProcessRequest2: offline HIT\n");
        http->logType = LOG_TCP_HIT;
        doGetMoreData();
        return;
    }

    if (http->redirect.status) {
        /* force this to be a miss */
        http->storeEntry(NULL);
        http->logType = LOG_TCP_MISS;
        doGetMoreData();
        return;
    }

    if (!storeEntryValidToSend(e)) {
        debug(85, 3) ("clientProcessRequest2: !storeEntryValidToSend MISS\n");
        http->storeEntry(NULL);
        http->logType = LOG_TCP_MISS;
        doGetMoreData();
        return;
    }

    if (EBIT_TEST(e->flags, ENTRY_SPECIAL)) {
        /* Special entries are always hits, no matter what the client says */
        debug(85, 3) ("clientProcessRequest2: ENTRY_SPECIAL HIT\n");
        http->logType = LOG_TCP_HIT;
        doGetMoreData();
        return;
    }

#if HTTP_VIOLATIONS
    if (http->storeEntry()->store_status == STORE_PENDING) {
        if (r->flags.nocache || r->flags.nocache_hack) {
            debug(85, 3) ("Clearing no-cache for STORE_PENDING request\n\t%s\n",
                          storeUrl(http->storeEntry()));
            r->flags.nocache = 0;
            r->flags.nocache_hack = 0;
        }
    }

#endif
    if (r->flags.nocache) {
        debug(85, 3) ("clientProcessRequest2: no-cache REFRESH MISS\n");
        http->storeEntry(NULL);
        http->logType = LOG_TCP_CLIENT_REFRESH_MISS;
        doGetMoreData();
        return;
    }

    /* We don't cache any range requests (for now!) -- adrian */
    /* RBC - and we won't until the store supports sparse objects.
     * I suspec this test is incorrect though, as we can extract ranges from
     * a fully cached object
     */
    if (r->flags.range) {
        /* XXX: test to see if we can satisfy the range with the cached object */
        debug(85, 3) ("clientProcessRequest2: force MISS due to range presence\n");
        http->storeEntry(NULL);
        http->logType = LOG_TCP_MISS;
        doGetMoreData();
        return;
    }

    debug(85, 3) ("clientProcessRequest2: default HIT\n");
    http->logType = LOG_TCP_HIT;
    doGetMoreData();
}

/* Request more data from the store for the client Stream
 * This is *the* entry point to this module.
 *
 * Preconditions:
 * This is the head of the list.
 * There is at least one more node.
 * data context is not null
 */
void
clientGetMoreData(clientStreamNode * aNode, clientHttpRequest * http)
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

    if (context->http->request->method == METHOD_PURGE) {
        context->purgeRequest();
        return;
    }

    if (context->http->request->method == METHOD_TRACE) {
        if (context->http->request->max_forwards == 0) {
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
        StoreIOBuffer tempBuffer;
        storeLockObject(http->storeEntry());

        if (http->storeEntry()->mem_obj == NULL) {
            /*
             * This if-block exists because we don't want to clobber
             * a preexiting mem_obj->method value if the mem_obj
             * already exists.  For example, when a HEAD request
             * is a cache hit for a GET response, we want to keep
             * the method as GET.
             */
            storeCreateMemObject(http->storeEntry(), http->uri,
                                 http->log_uri);
            http->storeEntry()->mem_obj->method =
                http->request->method;
        }

        sc = storeClientListAdd(http->storeEntry(), this);
#if DELAY_POOLS

        sc->setDelayId(DelayId::DelayClient(http));
#endif

        assert(http->logType == LOG_TCP_HIT);
        reqofs = 0;
        /* guarantee nothing has been sent yet! */
        assert(http->out.size == 0);
        assert(http->out.offset == 0);
        tempBuffer.offset = reqofs;
        tempBuffer.length = getNextNode()->readBuffer.length;
        tempBuffer.data = getNextNode()->readBuffer.data;
        storeClientCopy(sc, http->storeEntry(),
                        tempBuffer, CacheHit, this);
    } else {
        /* MISS CASE, http->logType is already set! */
        processMiss();
    }
}

/* the next node has removed itself from the stream. */
void
clientReplyDetach(clientStreamNode * node, clientHttpRequest * http)
{
    /* detach from the stream */
    clientStreamDetach(node, http);
}

/*
 * accepts chunk of a http message in buf, parses prefix, filters headers and
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
    /* call clientWriteComplete so the client socket gets closed */
    /* We call into the stream, because we don't know that there is a
     * client socket!
     */
    debug(88,5)("clientReplyContext::sendStreamError: A stream error has occured, marking as complete and sending no data.\n");
    StoreIOBuffer tempBuffer;
    flags.complete = 1;
    tempBuffer.flags.error = result.flags.error;
    clientStreamCallback((clientStreamNode*)http->client_stream.head->data, http, NULL,
                         tempBuffer);
}

void
clientReplyContext::pushStreamData(StoreIOBuffer const &result, char *source)
{
    StoreIOBuffer tempBuffer;

    if (result.length == 0) {
        debug (88,5)("clientReplyContext::pushStreamData: marking request as complete due to 0 length store result\n");
        flags.complete = 1;
    }

    assert(result.offset - headers_sz == next()->readBuffer.offset);
    tempBuffer.offset = result.offset - headers_sz;
    tempBuffer.length = result.length;

    if (tempBuffer.length)
        tempBuffer.data = source;

    clientStreamCallback((clientStreamNode*)http->client_stream.head->data, http, NULL,
                         tempBuffer);
}

clientStreamNode *
clientReplyContext::next() const
{
    assert ( (clientStreamNode*)http->client_stream.head->next->data == getNextNode());
    return getNextNode();
}

void
clientReplyContext::waitForMoreData ()
{
    debug(88,5)("clientReplyContext::waitForMoreData: Waiting for more data to parse reply headers in client side.\n");
    /* We don't have enough to parse the metadata yet */
    /* TODO: the store should give us out of band metadata and
     * obsolete this routine 
     */
    /* wait for more to arrive */
    startSendProcess();
}

void
clientReplyContext::startSendProcess()
{
    debug(88,5)("clientReplyContext::startSendProcess: triggering store read to SendMoreData\n");
    assert(reqofs <= HTTP_REQBUF_SZ);
    /* TODO: copy into the supplied buffer */
    StoreIOBuffer tempBuffer;
    tempBuffer.offset = reqofs;
    tempBuffer.length = next()->readBuffer.length - reqofs;
    tempBuffer.data = next()->readBuffer.data + reqofs;
    storeClientCopy(sc, http->storeEntry(),
                    tempBuffer, SendMoreData, this);
}

void
clientReplyContext::holdReply(HttpReply *aReply)
{
    assert (!holdingReply || !aReply);
    holdingReply = aReply;
}

/*
 * Calculates the maximum size allowed for an HTTP response
 */
void
clientReplyContext::buildMaxBodySize(HttpReply * reply)
{
    acl_size_t *l = Config.ReplyBodySize;
    ACLChecklist *ch;

    ch = clientAclChecklistCreate(NULL, http);
    ch->reply = reply;

    for (l = Config.ReplyBodySize; l; l = l -> next) {
        if (ch->matchAclListFast(l->aclList)) {
            if (l->size != static_cast<size_t>(-1)) {
                debug(58, 3) ("clientReplyContext: Setting maxBodySize to %ld\n", (long int) l->size);
                http->maxReplyBodySize(l->size);
            }

            break;
        }
    }

    delete ch;
}

void
clientReplyContext::processReplyAccess ()
{
    HttpReply *rep = holdingReply;
    holdReply(NULL);
    buildMaxBodySize(rep);

    if (http->isReplyBodyTooLarge(rep->content_length)) {
        ErrorState *err =
            clientBuildError(ERR_TOO_BIG, HTTP_FORBIDDEN, NULL,
                             http->getConn().getRaw() != NULL ? &http->getConn()->peer.sin_addr : &no_addr,
                             http->request);
        removeClientStoreReference(&sc, http);
        startError(err);
        httpReplyDestroy(rep);
        return;
    }

    headers_sz = rep->hdr_sz;
    ACLChecklist *replyChecklist;
    replyChecklist = clientAclChecklistCreate(Config.accessList.reply, http);
    replyChecklist->reply = rep;
    holdReply (rep);
    replyChecklist->nonBlockingCheck(ProcessReplyAccessResult, this);
}

void
clientReplyContext::ProcessReplyAccessResult (int rv, void *voidMe)
{
    clientReplyContext *me = static_cast<clientReplyContext *>(voidMe);
    me->processReplyAccessResult(rv);
}

void
clientReplyContext::processReplyAccessResult(bool accessAllowed)
{
    debug(88, 2) ("The reply for %s %s is %s, because it matched '%s'\n",
                  RequestMethodStr[http->request->method], http->uri,
                  accessAllowed ? "ALLOWED" : "DENIED",
                  AclMatchedName ? AclMatchedName : "NO ACL's");
    HttpReply *rep = holdingReply;
    holdReply (NULL);

    if (!accessAllowed && rep->sline.status != HTTP_FORBIDDEN
            && !alwaysAllowResponse(rep->sline.status)) {
        /* the if above is slightly broken, but there is no way
         * to tell if this is a squid generated error page, or one from
         *  upstream at this point. */
        ErrorState *err;
        err =
            clientBuildError(ERR_ACCESS_DENIED, HTTP_FORBIDDEN, NULL,
                             http->getConn().getRaw() != NULL ? &http->getConn()->peer.sin_addr : &no_addr,
                             http->request);
        removeClientStoreReference(&sc, http);
        startError(err);
        httpReplyDestroy(rep);
        http->logType = LOG_TCP_DENIED_REPLY;
        return;
    }

    ssize_t body_size = reqofs - rep->hdr_sz;
    assert(body_size >= 0);
    debug(88,3)
    ("clientReplyContext::sendMoreData: Appending %d bytes after %d bytes of headers\n",
     (int) body_size, rep->hdr_sz);
#if ESI

    if (http->flags.accel && rep->sline.status != HTTP_FORBIDDEN &&
            !alwaysAllowResponse(rep->sline.status) &&
            esiEnableProcessing(rep)) {
        debug(88, 2) ("Enabling ESI processing for %s\n", http->uri);
        clientStreamInsertHead(&http->client_stream, esiStreamRead,
                               esiProcessStream, esiStreamDetach, esiStreamStatus, NULL);
    }

#endif
    if (http->request->method == METHOD_HEAD) {
        /* do not forward body for HEAD replies */
        body_size = 0;
        http->flags.done_copying = 1;
        flags.complete = 1;
    }

    assert (!flags.headersSent);
    flags.headersSent = true;

    StoreIOBuffer tempBuffer;
    char *buf = next()->readBuffer.data;
    char *body_buf = buf + rep->hdr_sz;

    //Server side may disable ranges under some circumstances.

    if ((!http->request->range))
        next()->readBuffer.offset = 0;

    if (next()->readBuffer.offset != 0) {
        if (next()->readBuffer.offset > body_size) {
            /* Can't use any of the body we recieved. send nothing */
            tempBuffer.length = 0;
            tempBuffer.data = NULL;
        } else {
            tempBuffer.length = body_size - next()->readBuffer.offset;
            tempBuffer.data = body_buf + next()->readBuffer.offset;
        }
    } else {
        tempBuffer.length = body_size;
        tempBuffer.data = body_buf;
    }

    /* TODO??: move the data in the buffer back by the request header size */
    clientStreamCallback((clientStreamNode *)http->client_stream.head->data,
                         http, rep, tempBuffer);

    return;
}

void
clientReplyContext::sendMoreData (StoreIOBuffer result)
{
    if (deleting)
        return;

    StoreEntry *entry = http->storeEntry();

    ConnStateData::Pointer conn = http->getConn();

    int fd = conn.getRaw() != NULL ? conn->fd : -1;

    char *buf = next()->readBuffer.data;

    char *body_buf = buf;

    /* This is always valid until we get the headers as metadata from
     * storeClientCopy. 
     * Then it becomes reqofs == next->readBuffer.offset()
     */
    assert(reqofs == 0 || flags.storelogiccomplete);

    if (flags.headersSent && buf != result.data) {
        /* we've got to copy some data */
        assert(result.length <= next()->readBuffer.length);
        xmemcpy(buf, result.data, result.length);
        body_buf = buf;
    } else if (!flags.headersSent &&
               buf + reqofs !=result.data) {
        /* we've got to copy some data */
        assert(result.length + reqofs <= next()->readBuffer.length);
        xmemcpy(buf + reqofs, result.data, result.length);
        body_buf = buf;
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

    debug(88, 5) ("clientReplyContext::sendMoreData: %s, %d bytes (%u new bytes)\n",
                  http->uri, (int) reqofs, (unsigned int)result.length);

    debug(88, 5) ("clientReplyContext::sendMoreData: FD %d '%s', out.offset=%ld \n",
                  fd, storeUrl(entry), (long int) http->out.offset);

    /* update size of the request */
    reqsize = reqofs;

    if (http->request->flags.resetTCP()) {
        /* yuck. FIXME: move to client_side.c */

        if (fd != -1)
            comm_reset_close(fd);

        return;
    }

    if (errorInStream(result, reqofs)) {
        sendStreamError(result);
        return;
    }

    if (flags.headersSent) {
        pushStreamData (result, buf);
        return;
    }

    /* handle headers */
    if (Config.onoff.log_mime_hdrs) {
        size_t k;

        if ((k = headersEnd(buf, reqofs))) {
            safe_free(http->al.headers.reply);
            http->al.headers.reply = (char *)xcalloc(k + 1, 1);
            xstrncpy(http->al.headers.reply, buf, k);
        }
    }

    buildReply(buf, reqofs);
    ssize_t body_size = reqofs;

    if (holdingReply) {
        holdingBuffer = result;
        processReplyAccess ();
        return;

    } else if (reqofs < HTTP_REQBUF_SZ && entry->store_status == STORE_PENDING) {
        waitForMoreData();
        return;
    } else if (http->request->method == METHOD_HEAD) {
        /*
         * If we are here, then store_status == STORE_OK and it
         * seems we have a HEAD repsponse which is missing the
         * empty end-of-headers line (home.mira.net, phttpd/0.99.72
         * does this).  Because buildReply() fails we just
         * call this reply a body, set the done_copying flag and
         * continue...
         */
        /* RBC: Note that this is seriously broken, as we *need* the
         * metadata to allow further client modules to work. As such 
         * webservers are seriously broken, this is probably not 
         * going to get fixed.. perhapos we should remove it?
         */
        debug (88,0)("Broken head response - probably phttpd/0.99.72\n");
        http->flags.done_copying = 1;
        flags.complete = 1;
        /*
         * And as this is a malformed HTTP reply we cannot keep
         * the connection persistent
         */
        http->request->flags.proxy_keepalive = 0;

        assert(body_buf && body_size);
        StoreIOBuffer tempBuffer (body_size, 0 ,body_buf);
        clientStreamCallback((clientStreamNode *)http->client_stream.head->data,
                             http, NULL, tempBuffer);
    } else {
        debug (88,0)("clientReplyContext::sendMoreData: Unable to parse reply headers within a single HTTP_REQBUF_SZ length buffer\n");
        StoreIOBuffer tempBuffer;
        tempBuffer.flags.error = 1;
        /* XXX FIXME: make an html error page here */
        sendStreamError(tempBuffer);
        return;
    }

    fatal ("clientReplyContext::sendMoreData: Unreachable code reached \n");
}



/* Using this breaks the client layering just a little!
 */
void
clientReplyContext::createStoreEntry(method_t m, request_flags flags)
{
    assert(http != NULL);
    /*
     * For erroneous requests, we might not have a h->request,
     * so make a fake one.
     */

    if (http->request == NULL)
        http->request = requestLink(requestCreate(m, PROTO_NONE, null_string));

    StoreEntry *e = storeCreateEntry(http->uri, http->log_uri, flags, m);

    sc = storeClientListAdd(e, this);

#if DELAY_POOLS

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
    this->flags.storelogiccomplete = 1;

    /* and get the caller to request a read, from whereever they are */
    /* NOTE: after ANY data flows down the pipe, even one step,
     * this function CAN NOT be used to manage errors 
     */
    http->storeEntry(e);
}

ErrorState *
clientBuildError(err_type page_id, http_status status, char const *url,

                 struct in_addr * src_addr, request_t * request)
{
    ErrorState *err = errorCon(page_id, status);
    err->src_addr = *src_addr;

    if (url)
        err->url = xstrdup(url);

    if (request)
        err->request = requestLink(request);

    return err;
}
