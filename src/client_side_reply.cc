
/*
 * $Id: client_side_reply.cc,v 1.24 2002/10/26 04:57:29 adrian Exp $
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
#include "StoreClient.h"
#include "Store.h"

#include "clientStream.h"
#include "authenticate.h"

class clientReplyContext : public StoreClient {
public:
    void *operator new (size_t byteCount);
    void operator delete (void *address);
	
    void saveState(clientHttpRequest *);
    void restoreState(clientHttpRequest *);
    void purgeRequest ();
    void purgeRequestFindObjectToPurge();
    void purgeDoMissPurge();
    void purgeFoundGet(_StoreEntry *newEntry);
    void purgeFoundHead(_StoreEntry *newEntry);
    void purgeFoundObject(_StoreEntry *entry);
    void purgeDoPurgeGet(_StoreEntry *entry);
    void purgeDoPurgeHead(_StoreEntry *entry);
    void doGetMoreData();
    void identifyStoreObject();
    void identifyFoundObject(_StoreEntry *entry);
    int storeOKTransferDone() const;
    int storeNotOKTransferDone() const;
    
    http_status purgeStatus;

    /* state variable - replace with class to handle storeentries at some point */
    int lookingforstore;
    virtual void created (_StoreEntry *newEntry);
  
    clientHttpRequest *http;
    int headers_sz;
    store_client *sc;		/* The store_client we're using */
    store_client *old_sc;	/* ... for entry to be validated */
    StoreIOBuffer tempBuffer;	/* For use in validating requests via IMS */
    int old_reqsize;		/* ... again, for the buffer */
    size_t reqsize;
    off_t reqofs;
    char tempbuf[HTTP_REQBUF_SZ];	/* a temporary buffer if we need working storage */
#if USE_CACHE_DIGESTS
    const char *lookup_type;	/* temporary hack: storeGet() result: HIT/MISS/NONE */
#endif
    struct {
	int storelogiccomplete:1;
	int complete:1;		/* we have read all we can from upstream */
	int headersSent:1;
    } flags;
    clientStreamNode *ourNode;	/* This will go away if/when this file gets refactored some more */
private:
    clientStreamNode *getNextNode();
};

CBDATA_TYPE(clientReplyContext);

/* Local functions */
static int clientGotNotEnough(clientHttpRequest const *);
static int clientReplyBodyTooLarge(HttpReply *, ssize_t);
static int clientOnlyIfCached(clientHttpRequest * http);
static void clientProcessExpired(clientReplyContext *);
static void clientProcessMiss(clientReplyContext *);
static STCB clientCacheHit;
static void clientProcessOnlyIfCachedMiss(clientReplyContext *);
static int clientGetsOldEntry(StoreEntry *, StoreEntry * old,
    request_t * request);
static STCB clientHandleIMSReply;
static int modifiedSince(StoreEntry *, request_t *);
static void clientTraceReply(clientStreamNode *, clientReplyContext *);
static StoreEntry *clientCreateStoreEntry(clientReplyContext *, method_t,
    request_flags);
static STCB clientSendMoreData;
static void clientRemoveStoreReference(clientReplyContext *, store_client **,
    StoreEntry **);
extern "C" CSS clientReplyStatus;
extern ErrorState *clientBuildError(err_type, http_status, char const *,
    struct in_addr *, request_t *);

static void startError(clientReplyContext * context, clientHttpRequest * http, ErrorState * err);
static void triggerStoreReadWithClientParameters(clientReplyContext * context, clientHttpRequest * http);
static int clientCheckTransferDone(clientReplyContext * context);

/* The clientReply clean interface */
/* privates */
static FREE clientReplyFree;

void
clientReplyFree(void *data)
{
    clientReplyContext *thisClient = (clientReplyContext *)data;
    clientRemoveStoreReference(thisClient, &thisClient->sc, &thisClient->http->entry);
    /* old_entry might still be set if we didn't yet get the reply
     * code in clientHandleIMSReply() */
    clientRemoveStoreReference(thisClient, &thisClient->old_sc, &thisClient->http->old_entry);
    safe_free(thisClient->tempBuffer.data);
    cbdataReferenceDone(thisClient->http);
}

void *
clientReplyNewContext(clientHttpRequest * clientContext)
{
    clientReplyContext *context = new clientReplyContext;
    context->http = cbdataReference(clientContext);
    return context;
}

/* create an error in the store awaiting the client side to read it. */
void
clientSetReplyToError(void *data,
    err_type err, http_status status, method_t method, char const *uri,
    struct in_addr *addr, request_t * failedrequest, char *unparsedrequest,
    auth_user_request_t * auth_user_request)
{
    clientReplyContext *context = (clientReplyContext *)data;
    ErrorState *errstate =
    clientBuildError(err, status, uri, addr, failedrequest);
    if (unparsedrequest)
	errstate->request_hdrs = xstrdup(unparsedrequest);

    if (status == HTTP_NOT_IMPLEMENTED && context->http->request)
	/* prevent confusion over whether we default to persistent or not */
	context->http->request->flags.proxy_keepalive = 0;
    context->http->al.http.code = errstate->httpStatus;

    context->http->entry =
	clientCreateStoreEntry(context, method, request_flags());
    if (auth_user_request) {
	errstate->auth_user_request = auth_user_request;
	authenticateAuthUserRequestLock(errstate->auth_user_request);
    }
    assert(errstate->callback_data == NULL);
    errorAppendEntry(context->http->entry, errstate);
    /* Now the caller reads to get this */
}

void
clientRemoveStoreReference(clientReplyContext * context, store_client ** scp,
    StoreEntry ** ep)
{
    StoreEntry *e;
    store_client *sc = *scp;
    if ((e = *ep) != NULL) {
	*ep = NULL;
	storeUnregister(sc, e, context);
	*scp = NULL;
	storeUnlockObject(e);
    }
}

void *
clientReplyContext::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (clientReplyContext));
    CBDATA_INIT_TYPE_FREECB(clientReplyContext, clientReplyFree);
    return cbdataAlloc(clientReplyContext);
}

void
clientReplyContext::operator delete (void *address)
{
    cbdataFree ((clientReplyContext *)address);
}


void
clientReplyContext::saveState(clientHttpRequest * http)
{
    assert(old_sc == NULL);
    debug(88, 1) ("clientReplyContext::saveState: saving store context\n");
    http->old_entry = http->entry;
    old_sc = sc;
    old_reqsize = reqsize;
    tempBuffer.offset = reqofs;
    /* Prevent accessing the now saved entries */
    http->entry = NULL;
    sc = NULL;
    reqsize = 0;
    reqofs = 0;
}

void
clientReplyContext::restoreState(clientHttpRequest * http)
{
    assert(old_sc != NULL);
    debug(88, 1) ("clientReplyContext::restoreState: Restoring store context\n");
    http->entry = http->old_entry;
    sc = old_sc;
    reqsize = old_reqsize;
    reqofs = tempBuffer.offset;
    /* Prevent accessed the old saved entries */
    http->old_entry = NULL;
    old_sc = NULL;
    old_reqsize = 0;
    tempBuffer.offset = 0;
}

void
startError(clientReplyContext * context, clientHttpRequest * http, ErrorState * err)
{
    http->entry = clientCreateStoreEntry(context, http->request->method, request_flags());
    triggerStoreReadWithClientParameters(context, http);
    errorAppendEntry(http->entry, err);
}

clientStreamNode *
clientReplyContext::getNextNode()
{
    return (clientStreamNode *)ourNode->node.next->data; 
}

void
triggerStoreReadWithClientParameters(clientReplyContext * context, clientHttpRequest * http)
{
    clientStreamNode *next = (clientStreamNode *)http->client_stream.head->next->data;
    StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
    /* collapse this to one object if we never tickle the assert */
    assert(context->http == http);
    tempBuffer.offset = next->readBuffer.offset;
    tempBuffer.length = next->readBuffer.length;
    tempBuffer.data = next->readBuffer.data;
    storeClientCopy(context->sc, http->entry, tempBuffer, clientSendMoreData, context);
}

/* there is an expired entry in the store.
 * setup a temporary buffer area and perform an IMS to the origin
 */
static void
clientProcessExpired(clientReplyContext * context)
{
    clientHttpRequest *http = context->http;
    char *url = http->uri;
    StoreEntry *entry = NULL;
    debug(88, 3) ("clientProcessExpired: '%s'\n", http->uri);
    assert(http->entry->lastmod >= 0);
    /*
     * check if we are allowed to contact other servers
     * @?@: Instead of a 504 (Gateway Timeout) reply, we may want to return 
     *      a stale entry *if* it matches client requirements
     */
    if (clientOnlyIfCached(http)) {
	clientProcessOnlyIfCachedMiss(context);
	return;
    }
    http->request->flags.refresh = 1;
#if STORE_CLIENT_LIST_DEBUG
    /* Prevent a race with the store client memory free routines
     */
    assert(storeClientIsThisAClient(context->sc, context));
#endif
    /* Prepare to make a new temporary request */
    context->saveState(http);
    entry = storeCreateEntry(url,
	http->log_uri, http->request->flags, http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    context->sc = storeClientListAdd(entry, context);
#if DELAY_POOLS
    /* delay_id is already set on original store client */
    delaySetStoreClient(context->sc, delayClient(http));
#endif
    http->request->lastmod = http->old_entry->lastmod;
    debug(88, 5) ("clientProcessExpired: lastmod %ld\n",
	(long int) entry->lastmod);
    http->entry = entry;
    assert(http->out.offset == 0);
    fwdStart(http->conn ? http->conn->fd : -1, http->entry, http->request);
    /* Register with storage manager to receive updates when data comes in. */
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
	debug(88, 0) ("clientProcessExpired: found ENTRY_ABORTED object\n");
    {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	/* start counting the length from 0 */
	tempBuffer.offset = 0;
	tempBuffer.length = HTTP_REQBUF_SZ;
	tempBuffer.data = context->tempbuf;
	storeClientCopy(context->sc, entry,
	    tempBuffer, clientHandleIMSReply, context);
    }
}

int
modifiedSince(StoreEntry * entry, request_t * request)
{
    int object_length;
    MemObject *mem = entry->mem_obj;
    time_t mod_time = entry->lastmod;
    debug(88, 3) ("modifiedSince: '%s'\n", storeUrl(entry));
    if (mod_time < 0)
	mod_time = entry->timestamp;
    debug(88, 3) ("modifiedSince: mod_time = %ld\n", (long int) mod_time);
    if (mod_time < 0)
	return 1;
    /* Find size of the object */
    object_length = mem->reply->content_length;
    if (object_length < 0)
	object_length = contentLen(entry);
    if (mod_time > request->ims) {
	debug(88, 3) ("--> YES: entry newer than client\n");
	return 1;
    } else if (mod_time < request->ims) {
	debug(88, 3) ("-->  NO: entry older than client\n");
	return 0;
    } else if (request->imslen < 0) {
	debug(88, 3) ("-->  NO: same LMT, no client length\n");
	return 0;
    } else if (request->imslen == object_length) {
	debug(88, 3) ("-->  NO: same LMT, same length\n");
	return 0;
    } else {
	debug(88, 3) ("--> YES: same LMT, different length\n");
	return 1;
    }
}

static int
clientGetsOldEntry(StoreEntry * new_entry, StoreEntry * old_entry,
    request_t * request)
{
    const http_status status = new_entry->mem_obj->reply->sline.status;
    if (0 == status) {
	debug(88, 5) ("clientGetsOldEntry: YES, broken HTTP reply\n");
	return 1;
    }
    /* If the reply is a failure then send the old object as a last
     * resort */
    if (status >= 500 && status < 600) {
	debug(88, 3) ("clientGetsOldEntry: YES, failure reply=%d\n", status);
	return 1;
    }
    /* If the reply is anything but "Not Modified" then
     * we must forward it to the client */
    if (HTTP_NOT_MODIFIED != status) {
	debug(88, 5) ("clientGetsOldEntry: NO, reply=%d\n", status);
	return 0;
    }
    /* If the client did not send IMS in the request, then it
     * must get the old object, not this "Not Modified" reply */
    if (!request->flags.ims) {
	debug(88, 5) ("clientGetsOldEntry: YES, no client IMS\n");
	return 1;
    }
    /* If the client IMS time is prior to the entry LASTMOD time we
     * need to send the old object */
    if (modifiedSince(old_entry, request)) {
	debug(88, 5) ("clientGetsOldEntry: YES, modified since %ld\n",
	    (long int) request->ims);
	return 1;
    }
    debug(88, 5) ("clientGetsOldEntry: NO, new one is fine\n");
    return 0;
}

void
clientHandleIMSReply(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = (clientReplyContext *)data;
    clientHttpRequest *http = context->http;
    StoreEntry *entry = http->entry;
    MemObject *mem;
    const char *url = storeUrl(entry);
    int unlink_request = 0;
    StoreEntry *oldentry;
    http_status status;
    debug(88, 3) ("clientHandleIMSReply: %s, %lu bytes\n", url,
	(long unsigned) result.length);
    if (entry == NULL) {
	return;
    }
    if (result.flags.error && !EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	return;
    }
    /* update size of the request */
    context->reqsize = result.length + context->reqofs;
    context->reqofs = context->reqsize;
    mem = entry->mem_obj;
    status = mem->reply->sline.status;
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	debug(88, 3) ("clientHandleIMSReply: ABORTED '%s'\n", url);
	/* We have an existing entry, but failed to validate it */
	/* Its okay to send the old one anyway */
	http->logType = LOG_TCP_REFRESH_FAIL_HIT;
	clientRemoveStoreReference(context, &context->sc, &entry);
	/* Get the old request back */
	context->restoreState(http);
	entry = http->entry;
	return;
    }
    if (STORE_PENDING == entry->store_status && 0 == status) {
	/* more headers needed to decide */
	debug(88, 3) ("clientHandleIMSReply: Incomplete headers for '%s'\n",
	    url);
	if (result.length + context->reqofs >= HTTP_REQBUF_SZ) {
	    /* will not get any bigger than that */
	    debug(88, 3)
		("clientHandleIMSReply: Reply is too large '%s', using old entry\n",
		url);
	    /* use old entry, this repeats the code abovez */
	    http->logType = LOG_TCP_REFRESH_FAIL_HIT;
	    clientRemoveStoreReference(context, &context->sc, &entry);
	    entry = http->entry = http->old_entry;
	    /* Get the old request back */
	    context->restoreState(http);
	    entry = http->entry;
	} else {
	    StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	    tempBuffer.offset = context->reqofs;
	    tempBuffer.length = HTTP_REQBUF_SZ - context->reqofs;
	    tempBuffer.data = context->tempbuf + context->reqofs;
	    storeClientCopy(context->sc, entry,
		tempBuffer,
		clientHandleIMSReply, context);
	}
	return;
    }
    if (clientGetsOldEntry(entry, http->old_entry, http->request)) {
	/* We initiated the IMS request, the client is not expecting
	 * 304, so put the good one back.  First, make sure the old entry
	 * headers have been loaded from disk. */
	clientStreamNode *next = (clientStreamNode *)context->http->client_stream.head->next->data;
	StoreIOBuffer tempresult = EMPTYIOBUFFER;
	oldentry = http->old_entry;
	http->logType = LOG_TCP_REFRESH_HIT;
	if (oldentry->mem_obj->request == NULL) {
	    oldentry->mem_obj->request = requestLink(mem->request);
	    unlink_request = 1;
	}
	/* Don't memcpy() the whole reply structure here.  For example,
	 * www.thegist.com (Netscape/1.13) returns a content-length for
	 * 304's which seems to be the length of the 304 HEADERS!!! and
	 * not the body they refer to.  */
	httpReplyUpdateOnNotModified(oldentry->mem_obj->reply, mem->reply);
	storeTimestampsSet(oldentry);
	clientRemoveStoreReference(context, &context->sc, &entry);
	oldentry->timestamp = squid_curtime;
	if (unlink_request) {
	    requestUnlink(oldentry->mem_obj->request);
	    oldentry->mem_obj->request = NULL;
	}
	/* Get the old request back */
	context->restoreState(http);
	entry = http->entry;
	/* here the data to send is in the next nodes buffers already */
	assert(!EBIT_TEST(entry->flags, ENTRY_ABORTED));
	tempresult.length = context->reqsize;
	tempresult.data = next->readBuffer.data;
	clientSendMoreData(context, tempresult);
	return;
    }
    debug(88, 3) ("clientHandleIMSReply: Sending client the IMS reply for '%s'\n", url);
    {
	/* the client can handle this reply, whatever it is */
	StoreIOBuffer tempresult = EMPTYIOBUFFER;
	http->logType = LOG_TCP_REFRESH_MISS;
	if (HTTP_NOT_MODIFIED == mem->reply->sline.status) {
	    httpReplyUpdateOnNotModified(http->old_entry->mem_obj->reply,
		mem->reply);
	    storeTimestampsSet(http->old_entry);
	    http->logType = LOG_TCP_REFRESH_HIT;
	}
	clientRemoveStoreReference(context, &context->old_sc, &http->old_entry);
	/* here the data to send is the data we just recieved */
	context->tempBuffer.offset = 0;
	context->old_reqsize = 0;
	/* clientSendMoreData tracks the offset as well. 
	 * Force it back to zero */
	context->reqofs = 0;
	assert(!EBIT_TEST(entry->flags, ENTRY_ABORTED));
	/* TODO: provide SendMoreData with the ready parsed reply */
	tempresult.length = context->reqsize;
	tempresult.data = context->tempbuf;
	clientSendMoreData(context, tempresult);
	return;
    }
}

extern "C" CSR clientGetMoreData;
extern "C" CSD clientReplyDetach;

/*
 * clientCacheHit should only be called until the HTTP reply headers
 * have been parsed.  Normally this should be a single call, but
 * it might take more than one.  As soon as we have the headers,
 * we hand off to clientSendMoreData, clientProcessExpired, or
 * clientProcessMiss.
 */
void
clientCacheHit(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = (clientReplyContext *)data;
    clientHttpRequest *http = context->http;
    StoreEntry *e = http->entry;
    MemObject *mem;
    request_t *r = http->request;
    debug(88, 3) ("clientCacheHit: %s, %ud bytes\n", http->uri, (unsigned int)result.length);
    if (http->entry == NULL) {
	debug(88, 3) ("clientCacheHit: request aborted\n");
	return;
    } else if (result.flags.error) {
	/* swap in failure */
	debug(88, 3) ("clientCacheHit: swapin failure for %s\n", http->uri);
	http->logType = LOG_TCP_SWAPFAIL_MISS;
	clientRemoveStoreReference(context, &context->sc, &http->entry);
	clientProcessMiss(context);
	return;
    }
    assert(result.length > 0);
    mem = e->mem_obj;
    assert(!EBIT_TEST(e->flags, ENTRY_ABORTED));
    /* update size of the request */
    context->reqsize = result.length + context->reqofs;
    if (mem->reply->sline.status == 0) {
	/*
	 * we don't have full reply headers yet; either wait for more or
	 * punt to clientProcessMiss.
	 */
	if (e->mem_status == IN_MEMORY || e->store_status == STORE_OK) {
	    clientProcessMiss(context);
	} else if (result.length + context->reqofs >= HTTP_REQBUF_SZ
	    && http->out.offset == 0) {
	    clientProcessMiss(context);
	} else {
	    clientStreamNode *next;
	    StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	    debug(88, 3) ("clientCacheHit: waiting for HTTP reply headers\n");
	    context->reqofs += result.length;
	    assert(context->reqofs <= HTTP_REQBUF_SZ);
	    /* get the next users' buffer */
	    /* FIXME: HTTP_REQBUF_SZ must be wrong here ??!
	     */
	    next = (clientStreamNode *)context->http->client_stream.head->next->data;
	    tempBuffer.offset = http->out.offset + context->reqofs;
	    tempBuffer.length = HTTP_REQBUF_SZ;
	    tempBuffer.data = next->readBuffer.data + context->reqofs;
	    storeClientCopy(context->sc, e,
		tempBuffer, clientCacheHit, context);
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
	clientRemoveStoreReference(context, &context->sc, &http->entry);
	e = NULL;
	/* Note: varyEvalyateMatch updates the request with vary information
	 * so we only get here once. (it also takes care of cancelling loops)
	 */
	debug(88, 2) ("clientProcessHit: Vary detected!\n");
	clientGetMoreData(context->ourNode, http);
	return;
    case VARY_CANCEL:
	/* varyEvaluateMatch found a object loop. Process as miss */
	debug(88, 1) ("clientProcessHit: Vary object loop!\n");
	clientProcessMiss(context);
	return;
    }
    if (r->method == METHOD_PURGE) {
	clientRemoveStoreReference(context, &context->sc, &http->entry);
	e = NULL;
	context->purgeRequest();
	return;
    }
    if (storeCheckNegativeHit(e)) {
	http->logType = LOG_TCP_NEGATIVE_HIT;
	clientSendMoreData(context, result);
    } else if (r->method == METHOD_HEAD) {
	/*
	 * RFC 2068 seems to indicate there is no "conditional HEAD"
	 * request.  We cannot validate a cached object for a HEAD
	 * request, nor can we return 304.
	 */
	if (e->mem_status == IN_MEMORY)
	    http->logType = LOG_TCP_MEM_HIT;
	clientSendMoreData(context, result);
    } else if (refreshCheckHTTP(e, r) && !http->flags.internal) {
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
	    clientProcessMiss(context);
	} else if (r->flags.nocache) {
	    /*
	     * This did not match a refresh pattern that overrides no-cache
	     * we should honour the client no-cache header.
	     */
	    http->logType = LOG_TCP_CLIENT_REFRESH_MISS;
	    clientProcessMiss(context);
	} else if (r->protocol == PROTO_HTTP) {
	    /*
	     * Object needs to be revalidated
	     * XXX This could apply to FTP as well, if Last-Modified is known.
	     */
	    http->logType = LOG_TCP_REFRESH_MISS;
	    clientProcessExpired(context);
	} else {
	    /*
	     * We don't know how to re-validate other protocols. Handle
	     * them as if the object has expired.
	     */
	    http->logType = LOG_TCP_MISS;
	    clientProcessMiss(context);
	}
    } else if (r->flags.ims) {
	/*
	 * Handle If-Modified-Since requests from the client
	 */
	if (mem->reply->sline.status != HTTP_OK) {
	    debug(88, 4) ("clientCacheHit: Reply code %d != 200\n",
		mem->reply->sline.status);
	    http->logType = LOG_TCP_MISS;
	    clientProcessMiss(context);
	} else if (modifiedSince(e, http->request)) {
	    http->logType = LOG_TCP_IMS_HIT;
	    clientSendMoreData(context, result);
	} else {
	    time_t timestamp = e->timestamp;
	    MemBuf mb = httpPacked304Reply(e->mem_obj->reply);
	    http->logType = LOG_TCP_IMS_HIT;
	    clientRemoveStoreReference(context, &context->sc, &http->entry);
	    http->entry = e =
		clientCreateStoreEntry(context, http->request->method,
		request_flags());
	    /*
	     * Copy timestamp from the original entry so the 304
	     * reply has a meaningful Age: header.
	     */
	    e->timestamp = timestamp;
	    httpReplyParse(e->mem_obj->reply, mb.buf, mb.size);
	    storeAppend(e, mb.buf, mb.size);
	    memBufClean(&mb);
	    storeComplete(e);
	    /* TODO: why put this in the store and then serialise it and then parse it again.
	     * Simply mark the request complete in our context and
	     * write the reply struct to the client side
	     */
	    triggerStoreReadWithClientParameters(context, http);
	}
    } else {
	/*
	 * plain ol' cache hit
	 */
	if (e->mem_status == IN_MEMORY)
	    http->logType = LOG_TCP_MEM_HIT;
	else if (Config.onoff.offline)
	    http->logType = LOG_TCP_OFFLINE_HIT;
	clientSendMoreData(context, result);
    }
}

/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 */
void
clientProcessMiss(clientReplyContext * context)
{
    clientHttpRequest *http = context->http;
    char *url = http->uri;
    request_t *r = http->request;
    ErrorState *err = NULL;
    debug(88, 4) ("clientProcessMiss: '%s %s'\n",
	RequestMethodStr[r->method], url);
    /*
     * We might have a left-over StoreEntry from a failed cache hit
     * or IMS request.
     */
    if (http->entry) {
	if (EBIT_TEST(http->entry->flags, ENTRY_SPECIAL)) {
	    debug(88, 0) ("clientProcessMiss: miss on a special object (%s).\n",
		url);
	    debug(88, 0) ("\tlog_type = %s\n", log_tags[http->logType]);
	    storeEntryDump(http->entry, 1);
	}
	clientRemoveStoreReference(context, &context->sc, &http->entry);
    }
    if (r->method == METHOD_PURGE) {
	context->purgeRequest();
	return;
    }
    if (clientOnlyIfCached(http)) {
	clientProcessOnlyIfCachedMiss(context);
	return;
    }
    /*
     * Deny loops when running in accelerator/transproxy mode.
     */
    if (http->flags.accel && r->flags.loopdetect) {
	http->al.http.code = HTTP_FORBIDDEN;
	err =
	    clientBuildError(ERR_ACCESS_DENIED, HTTP_FORBIDDEN, NULL,
	    &http->conn->peer.sin_addr, http->request);
	http->entry =
	    clientCreateStoreEntry(context, r->method, request_flags());
	errorAppendEntry(http->entry, err);
	triggerStoreReadWithClientParameters(context, http);
	return;
    } else {
	assert(http->out.offset == 0);
	http->entry = clientCreateStoreEntry(context, r->method, r->flags);
	triggerStoreReadWithClientParameters(context, http);
	if (http->redirect.status) {
	    HttpReply *rep = httpReplyCreate();
#if LOG_TCP_REDIRECTS
	    http->logType = LOG_TCP_REDIRECT;
#endif
	    storeReleaseRequest(http->entry);
	    httpRedirectReply(rep, http->redirect.status,
		http->redirect.location);
	    httpReplySwapOut(rep, http->entry);
	    httpReplyDestroy(rep);
	    storeComplete(http->entry);
	    return;
	}
	if (http->flags.internal)
	    r->protocol = PROTO_INTERNAL;
	fwdStart(http->conn ? http->conn->fd : -1, http->entry, r);
    }
}

/*
 * client issued a request with an only-if-cached cache-control directive;
 * we did not find a cached object that can be returned without
 *     contacting other servers;
 * respond with a 504 (Gateway Timeout) as suggested in [RFC 2068]
 */
static void
clientProcessOnlyIfCachedMiss(clientReplyContext * context)
{
    clientHttpRequest *http = context->http;
    char *url = http->uri;
    request_t *r = http->request;
    ErrorState *err = NULL;
    debug(88, 4) ("clientProcessOnlyIfCachedMiss: '%s %s'\n",
	RequestMethodStr[r->method], url);
    http->al.http.code = HTTP_GATEWAY_TIMEOUT;
    err = clientBuildError(ERR_ONLY_IF_CACHED_MISS, HTTP_GATEWAY_TIMEOUT, NULL,
	&http->conn->peer.sin_addr, http->request);
    clientRemoveStoreReference(context, &context->sc, &http->entry);
    startError(context, http, err);
}

void
clientReplyContext::purgeRequestFindObjectToPurge()
{
    /* Try to find a base entry */
    http->flags.purging = 1;
    lookingforstore = 1;
    _StoreEntry::getPublicByRequestMethod(this, http->request, METHOD_GET);
}

void
clientReplyContext::created(_StoreEntry *newEntry)
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
clientReplyContext::purgeFoundGet(_StoreEntry *newEntry)
{
    if (newEntry->isNull()) {
	lookingforstore = 2;
	_StoreEntry::getPublicByRequestMethod(this, http->request, METHOD_HEAD);
    } else
	purgeFoundObject (newEntry);
}

void
clientReplyContext::purgeFoundHead(_StoreEntry *newEntry)
{
    if (newEntry->isNull())
	purgeDoMissPurge();
    else
	purgeFoundObject (newEntry);
}
	
void
clientReplyContext::purgeFoundObject(_StoreEntry *entry)
{
    assert (entry && !entry->isNull());
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	/* Swap in the metadata */
	http->entry = entry;
	storeLockObject(http->entry);
	storeCreateMemObject(http->entry, http->uri, http->log_uri);
	http->entry->mem_obj->method = http->request->method;
	sc = storeClientListAdd(http->entry, this);
	http->logType = LOG_TCP_HIT;
	reqofs = 0;
	tempBuffer.offset = http->out.offset;
	clientStreamNode *next = (clientStreamNode *)http->client_stream.head->next->data;
	tempBuffer.length = next->readBuffer.length;
	tempBuffer.data = next->readBuffer.data;
	storeClientCopy(sc, http->entry,
	    tempBuffer, clientCacheHit, this);
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
	    &http->conn->peer.sin_addr, http->request);
	startError(this, http, err);
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
    _StoreEntry::getPublicByRequestMethod(this,http->request, METHOD_GET);
}

void
clientReplyContext::purgeDoPurgeGet(_StoreEntry *newEntry)
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
    _StoreEntry::getPublicByRequestMethod(this, http->request, METHOD_HEAD);
}

void
clientReplyContext::purgeDoPurgeHead(_StoreEntry *newEntry)
{
    if (newEntry) {
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
    http->entry =
	clientCreateStoreEntry(this, http->request->method,
	request_flags());
    triggerStoreReadWithClientParameters(this, http);
    httpReplyReset(r = http->entry->mem_obj->reply);
    httpBuildVersion(&version, 1, 0);
    httpReplySetHeaders(r, version, purgeStatus, NULL, NULL, 0, 0, -1);
    httpReplySwapOut(r, http->entry);
    storeComplete(http->entry);
}

void
clientTraceReply(clientStreamNode * node, clientReplyContext * context)
{
    HttpReply *rep;
    http_version_t version;
    clientStreamNode *next = (clientStreamNode *)node->node.next->data;
    StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
    assert(context->http->request->max_forwards == 0);
    context->http->entry =
	clientCreateStoreEntry(context, context->http->request->method,
	request_flags());
    tempBuffer.offset = next->readBuffer.offset + context->headers_sz;
    tempBuffer.length = next->readBuffer.length;
    tempBuffer.data = next->readBuffer.data;
    storeClientCopy(context->sc, context->http->entry,
	tempBuffer, clientSendMoreData, context);
    storeReleaseRequest(context->http->entry);
    storeBuffer(context->http->entry);
    rep = httpReplyCreate();
    httpBuildVersion(&version, 1, 0);
    httpReplySetHeaders(rep, version, HTTP_OK, NULL, "text/plain",
	httpRequestPrefixLen(context->http->request), 0, squid_curtime);
    httpReplySwapOut(rep, context->http->entry);
    httpReplyDestroy(rep);
    httpRequestSwapOut(context->http->request, context->http->entry);
    storeComplete(context->http->entry);
}

#define SENDING_BODY 0
#define SENDING_HDRSONLY 1
int
clientCheckTransferDone(clientReplyContext * context)
{
    StoreEntry *entry = context->http->entry;
    if (entry == NULL)
	return 0;
    /*  
     * For now, 'done_copying' is used for special cases like
     * Range and HEAD requests.
     */
    if (context->http->flags.done_copying)
	return 1;
    /*
     * Handle STORE_OK objects.
     * objectLen(entry) will be set proprely.
     * RC: Does objectLen(entry) include the Headers? 
     * RC: Yes.
     */
    if (entry->store_status == STORE_OK) {
	return context->storeOKTransferDone();
    } else {
	return context->storeNotOKTransferDone();
    }
}

int
clientReplyContext::storeOKTransferDone() const
{
    if (http->out.offset >= objectLen(http->entry) - headers_sz)
	return 1;
    return 0;
}

int
clientReplyContext::storeNotOKTransferDone() const
{
    /*
     * Now, handle STORE_PENDING objects
     */
    MemObject *mem = http->entry->mem_obj;
    assert(mem != NULL);
    assert(http->request != NULL);
    /* mem->reply was wrong because it uses the UPSTREAM header length!!! */
    http_reply *reply = mem->reply;
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



int
clientGotNotEnough(clientHttpRequest const *http)
{
    int cl =
    httpReplyBodySize(http->request->method, http->entry->mem_obj->reply);
    assert(cl >= 0);
    if (http->out.offset < cl)
	return 1;
    return 0;
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
	    inet_ntoa(http->conn ? http->conn->peer.sin_addr : no_addr));
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
	    inet_ntoa(http->conn ? http->conn->peer.sin_addr : no_addr));
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
    clientReplyContext *context = (clientReplyContext *)aNode->data;
    int done;
    /* Here because lower nodes don't need it */
    if (http->entry == NULL)
	return STREAM_FAILED;	/* yuck, but what can we do? */
    if (EBIT_TEST(http->entry->flags, ENTRY_ABORTED))
	/* TODO: Could upstream read errors (result.flags.error) be
	 * lost, and result in undersize requests being considered
	 * complete. Should we tcp reset such connections ?
	 */
	return STREAM_FAILED;
    if ((done = clientCheckTransferDone(context)) != 0 || context->flags.complete) {
	debug(88, 5) ("clientReplyStatus: transfer is DONE\n");
	/* Ok we're finished, but how? */
	if (httpReplyBodySize(http->request->method,
		http->entry->mem_obj->reply) < 0) {
	    debug(88, 5) ("clientReplyStatus: closing, content_length < 0\n");
	    return STREAM_FAILED;
	}
	if (!done) {
	    debug(88, 5) ("clientReplyStatus: closing, !done, but read 0 bytes\n");
	    return STREAM_FAILED;
	}
	if (clientGotNotEnough(http)) {
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
    if (clientReplyBodyTooLarge(http->entry->mem_obj->reply, http->out.offset)) {
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
static int
clientAlwaysAllowResponse(http_status sline)
{
    switch (sline) {
    case HTTP_CONTINUE:
    case HTTP_SWITCHING_PROTOCOLS:
    case HTTP_PROCESSING:
    case HTTP_NO_CONTENT:
    case HTTP_NOT_MODIFIED:
	return 1;
	/* unreached */
	break;
    default:
	return 0;
    }
}

/*
 * filters out unwanted entries from original reply header
 * adds extra entries if we have more info than origin server
 * adds Squid specific entries
 */
static void
clientBuildReplyHeader(clientReplyContext *context, HttpReply * rep)
{
    clientHttpRequest * http = context->http;
    HttpHeader *hdr = &rep->header;
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
    /* handle Connection header */
    if (httpHeaderHas(hdr, HDR_CONNECTION)) {
	/* anything that matches Connection list member will be deleted */
	String strConnection = httpHeaderGetList(hdr, HDR_CONNECTION);
	const HttpHeaderEntry *e;
	HttpHeaderPos pos = HttpHeaderInitPos;
	/*
	 * think: on-average-best nesting of the two loops (hdrEntry
	 * and strListItem) @?@
	 */
	/*
	 * maybe we should delete standard stuff ("keep-alive","close")
	 * from strConnection first?
	 */
	while ((e = httpHeaderGetEntry(hdr, &pos))) {
	    if (strListIsMember(&strConnection, strBuf(e->name), ','))
		httpHeaderDelAt(hdr, pos);
	}
	httpHeaderDelById(hdr, HDR_CONNECTION);
	stringClean(&strConnection);
    }
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
	if (NULL == http->entry)
	    (void) 0;
	else if (http->entry->timestamp < 0)
	    (void) 0;
	else if (http->entry->timestamp < squid_curtime)
	    httpHeaderPutInt(hdr, HDR_AGE,
		squid_curtime - http->entry->timestamp);
    }
    /* Handle authentication headers */
    if (request->auth_user_request)
	authenticateFixHeader(rep, request->auth_user_request, request,
	    http->flags.accel, 0);
    /* Append X-Cache */
    httpHeaderPutStrf(hdr, HDR_X_CACHE, "%s from %s",
	is_hit ? "HIT" : "MISS", getMyHostname());
#if USE_CACHE_DIGESTS
    /* Append X-Cache-Lookup: -- temporary hack, to be removed @?@ @?@ */
    httpHeaderPutStrf(hdr, HDR_X_CACHE_LOOKUP, "%s from %s:%d",
	context->lookup_type ? context->lookup_type : "NONE",
	getMyHostname(), getMyPort());
#endif
    if (httpReplyBodySize(request->method, rep) < 0) {
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
	    rep->sline.version.major,
	    rep->sline.version.minor,
	    ThisCache);
	strListAdd(&strVia, bbuf, ',');
	httpHeaderDelById(hdr, HDR_VIA);
	httpHeaderPutStr(hdr, HDR_VIA, strBuf(strVia));
	stringClean(&strVia);
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
	http->entry->mem_obj->url ? http->entry->mem_obj->url : http->uri);
#endif
    httpHdrMangleList(hdr, request);
}


static HttpReply *
clientBuildReply(clientReplyContext *context, const char *buf, size_t size)
{
    HttpReply *rep = httpReplyCreate();
    size_t k = headersEnd(buf, size);
    if (k && httpReplyParse(rep, buf, k)) {
	/* enforce 1.0 reply version */
	httpBuildVersion(&rep->sline.version, 1, 0);
	/* do header conversions */
	clientBuildReplyHeader(context, rep);
    } else {
	/* parsing failure, get rid of the invalid reply */
	httpReplyDestroy(rep);
	rep = NULL;
    }
    return rep;
}

void
clientReplyContext::identifyStoreObject()
{
    request_t *r = http->request;
    if (r->flags.cachable || r->flags.internal) {
	lookingforstore = 5;
	_StoreEntry::getPublicByRequest (this, r);
    } else
	identifyFoundObject (NullStoreEntry::getInstance());
}

void
clientReplyContext::identifyFoundObject(StoreEntry *newEntry)
{
    StoreEntry *e = newEntry;
    request_t *r = http->request;
    if (e->isNull()) {
	http->entry = NULL;
    } else {
	http->entry = e;
    }
    /* Release negatively cached IP-cache entries on reload */
    if (r->flags.nocache)
	ipcacheInvalidate(r->host);
#if HTTP_VIOLATIONS
    else if (r->flags.nocache_hack)
	ipcacheInvalidate(r->host);
#endif
#if USE_CACHE_DIGESTS
    lookup_type = http->entry ? "HIT" : "MISS";
#endif
    if (NULL == http->entry) {
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
	http->entry = NULL;
	http->logType = LOG_TCP_MISS;
	doGetMoreData();
	return;
    }
    if (!storeEntryValidToSend(e)) {
	debug(85, 3) ("clientProcessRequest2: !storeEntryValidToSend MISS\n");
	http->entry = NULL;
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
    if (http->entry->store_status == STORE_PENDING) {
	if (r->flags.nocache || r->flags.nocache_hack) {
	    debug(85, 3) ("Clearing no-cache for STORE_PENDING request\n\t%s\n",
		storeUrl(http->entry));
	    r->flags.nocache = 0;
	    r->flags.nocache_hack = 0;
	}
    }
#endif
    if (r->flags.nocache) {
	debug(85, 3) ("clientProcessRequest2: no-cache REFRESH MISS\n");
	http->entry = NULL;
	http->logType = LOG_TCP_CLIENT_REFRESH_MISS;
	doGetMoreData();
	return;
    }
    /* We don't cache any range requests (for now!) -- adrian */
    if (r->flags.range) {
	http->entry = NULL;
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
    clientStreamNode *next;
    clientReplyContext *context;
    /* Test preconditions */
    assert(aNode != NULL);
    assert(cbdataReferenceValid(aNode));
    assert(aNode->data != NULL);
    assert(aNode->node.prev == NULL);
    assert(aNode->node.next != NULL);
    context = (clientReplyContext *)aNode->data;
    assert(context->http == http);

    next = ( clientStreamNode *)aNode->node.next->data;
    if (!context->ourNode)
	context->ourNode = aNode;
    /* no cbdatareference, this is only used once, and safely */
    if (context->flags.storelogiccomplete) {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	tempBuffer.offset = next->readBuffer.offset + context->headers_sz;
	tempBuffer.length = next->readBuffer.length;
	tempBuffer.data = next->readBuffer.data;

	storeClientCopy(context->sc, http->entry,
	    tempBuffer, clientSendMoreData, context);
	return;
    }
    if (context->http->request->method == METHOD_PURGE) {
	context->purgeRequest();
	return;
    }
    if (context->http->request->method == METHOD_TRACE) {
	if (context->http->request->max_forwards == 0) {
	    clientTraceReply(aNode, context);
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
    if (http->entry != NULL) {
	/* someone found the object in the cache for us */
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	storeLockObject(http->entry);
	if (http->entry->mem_obj == NULL) {
	    /*
	     * This if-block exists because we don't want to clobber
	     * a preexiting mem_obj->method value if the mem_obj
	     * already exists.  For example, when a HEAD request
	     * is a cache hit for a GET response, we want to keep
	     * the method as GET.
	     */
	    storeCreateMemObject(http->entry, http->uri,
		http->log_uri);
	    http->entry->mem_obj->method =
		http->request->method;
	}
	sc = storeClientListAdd(http->entry, this);
#if DELAY_POOLS
	delaySetStoreClient(sc, delayClient(http));
#endif
	assert(http->logType == LOG_TCP_HIT);
	reqofs = 0;
	/* guarantee nothing has been sent yet! */
	assert(http->out.size == 0);
	assert(http->out.offset == 0);
	tempBuffer.offset = reqofs;
	tempBuffer.length = getNextNode()->readBuffer.length;
	tempBuffer.data = getNextNode()->readBuffer.data;
	storeClientCopy(sc, http->entry,
	    tempBuffer, clientCacheHit, this);
    } else {
	/* MISS CASE, http->logType is already set! */
	clientProcessMiss(this);
    }
}

/* the next node has removed itself from the stream. */
void
clientReplyDetach(clientStreamNode * node, clientHttpRequest * http)
{
    /* detach from the stream */
    /* NB: This cbdataFrees our context,
     * so the clientSendMoreData callback (if any)
     * pending in the store will not trigger
     */
    clientStreamDetach(node, http);
}

/*
 * accepts chunk of a http message in buf, parses prefix, filters headers and
 * such, writes processed message to the message recipient
 */
void
clientSendMoreData(void *data, StoreIOBuffer result)
{
    clientReplyContext *context = static_cast<clientReplyContext *>(data);
    clientHttpRequest *http = context->http;
    clientStreamNode *next = (clientStreamNode*)http->client_stream.head->next->data;
    StoreEntry *entry = http->entry;
    ConnStateData *conn = http->conn;
    int fd = conn ? conn->fd : -1;
    HttpReply *rep = NULL;
    char *buf = next->readBuffer.data;
    char *body_buf = buf;
    ssize_t size = context->reqofs + result.length;
    ssize_t body_size = size;

    /* This is not valid once we start doing range requests.
     * Then it becomes context->reqofs == startoffirstrangeentry
     */
    assert(context->reqofs == 0 || context->flags.storelogiccomplete);

    if (context->flags.headersSent && buf != result.data) {
	/* we've got to copy some data */
	assert(result.length <= next->readBuffer.length);
	xmemcpy(buf, result.data, result.length);
	body_buf = buf;
    } else if (!context->flags.headersSent &&
	       buf + context->reqofs !=result.data) {
	/* we've got to copy some data */
	assert(result.length + context->reqofs <= next->readBuffer.length);
	xmemcpy(buf + context->reqofs, result.data, result.length);
	body_buf = buf;
    }
    /* We've got the final data to start pushing... */
    context->flags.storelogiccomplete = 1;

    debug(88, 5) ("clientSendMoreData: %s, %d bytes (%u new bytes)\n",
	http->uri, (int) size, (unsigned int)result.length);
    assert(size <= HTTP_REQBUF_SZ || context->flags.headersSent);
    assert(http->request != NULL);
    /* ESI TODO: remove this assert once everything is stable */
    assert(http->client_stream.head->data
	&& cbdataReferenceValid(http->client_stream.head->data));
    dlinkDelete(&http->active, &ClientActiveRequests);
    dlinkAdd(http, &http->active, &ClientActiveRequests);
    debug(88, 5) ("clientSendMoreData: FD %d '%s', out.offset=%ld \n",
	fd, storeUrl(entry), (long int) http->out.offset);
    /* update size of the request */
    context->reqsize = size;
    if (http->request->flags.resetTCP()) {
	/* yuck. FIXME: move to client_side.c */
	if (fd != -1)
	    comm_reset_close(fd);
	return;
    } else if (			/* aborted request */
	    (entry && EBIT_TEST(entry->flags, ENTRY_ABORTED)) ||
	/* Upstream read error */ (result.flags.error) ||
	/* Upstream EOF */ (body_size == 0)) {
	/* call clientWriteComplete so the client socket gets closed */
	/* We call into the stream, because we don't know that there is a
	 * client socket!
	 */
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	context->flags.complete = 1;
	tempBuffer.flags.error = result.flags.error;
	clientStreamCallback((clientStreamNode*)http->client_stream.head->data, http, NULL,
	    tempBuffer);
	/* clientWriteComplete(fd, NULL, 0, COMM_OK, http); */
	return;
    }
    if (context->flags.headersSent != 0) {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	if (result.length == 0)
	    context->flags.complete = 1;
	/* REMOVE ME: Only useful for two node streams */
	assert(result.offset - context->headers_sz == ((clientStreamNode *) http->client_stream.tail->data)->readBuffer.offset);
	tempBuffer.offset = result.offset - context->headers_sz;
	tempBuffer.length = result.length;
	tempBuffer.data = buf;
	clientStreamCallback((clientStreamNode*)http->client_stream.head->data, http, NULL,
	    tempBuffer);
	return;
    }
    /* handle headers */
    if (Config.onoff.log_mime_hdrs) {
	size_t k;
	if ((k = headersEnd(buf, size))) {
	    safe_free(http->al.headers.reply);
	    http->al.headers.reply = (char *)xcalloc(k + 1, 1);
	    xstrncpy(http->al.headers.reply, buf, k);
	}
    }
    rep = clientBuildReply(context, buf, size);
    if (rep) {
	aclCheck_t *ch;
	int rv;
	httpReplyBodyBuildSize(http->request, rep, &Config.ReplyBodySize);
	if (clientReplyBodyTooLarge(rep, rep->content_length)) {
	    ErrorState *err =
	    clientBuildError(ERR_TOO_BIG, HTTP_FORBIDDEN, NULL,
		http->conn ? &http->conn->peer.sin_addr : &no_addr,
		http->request);
	    clientRemoveStoreReference(context, &context->sc, &http->entry);
	    startError(context, http, err);
	    httpReplyDestroy(rep);
	    return;
	}
	context->headers_sz = rep->hdr_sz;
	body_size = size - rep->hdr_sz;
	assert(body_size >= 0);
	body_buf = buf + rep->hdr_sz;
	debug(88,
	    3)
	    ("clientSendMoreData: Appending %d bytes after %d bytes of headers\n",
	    (int) body_size, rep->hdr_sz);
	ch = clientAclChecklistCreate(Config.accessList.reply, http);
	ch->reply = rep;
	rv = aclCheckFast(Config.accessList.reply, ch);
	aclChecklistFree(ch);
	ch = NULL;
	debug(88, 2) ("The reply for %s %s is %s, because it matched '%s'\n",
	    RequestMethodStr[http->request->method], http->uri,
	    rv ? "ALLOWED" : "DENIED",
	    AclMatchedName ? AclMatchedName : "NO ACL's");
	if (!rv && rep->sline.status != HTTP_FORBIDDEN
	    && !clientAlwaysAllowResponse(rep->sline.status)) {
	    /* the if above is slightly broken, but there is no way
	     * to tell if this is a squid generated error page, or one from
	     *  upstream at this point. */
	    ErrorState *err;
	    err =
		clientBuildError(ERR_ACCESS_DENIED, HTTP_FORBIDDEN, NULL,
		http->conn ? &http->conn->peer.sin_addr : &no_addr,
		http->request);
	    clientRemoveStoreReference(context, &context->sc, &http->entry);
	    startError(context, http, err);
	    httpReplyDestroy(rep);
	    return;
	}
    } else if (size < HTTP_REQBUF_SZ && entry->store_status == STORE_PENDING) {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	/* wait for more to arrive */
	context->reqofs += result.length;
	assert(context->reqofs <= HTTP_REQBUF_SZ);
	/* TODO: copy into the supplied buffer */
	tempBuffer.offset = context->reqofs;
	tempBuffer.length = next->readBuffer.length - context->reqofs;
	tempBuffer.data = next->readBuffer.data + context->reqofs;
	storeClientCopy(context->sc, entry,
	    tempBuffer, clientSendMoreData, context);
	return;
    }
    if (!context->flags.headersSent)
	context->flags.headersSent = 1;
    if (http->request->method == METHOD_HEAD) {
	if (rep) {
	    /* do not forward body for HEAD replies */
	    /* ESI TODO: Can ESI affect headers on the master document */
	    body_size = 0;
	    http->flags.done_copying = 1;
	    context->flags.complete = 1;
	} else {
	    /*
	     * If we are here, then store_status == STORE_OK and it
	     * seems we have a HEAD repsponse which is missing the
	     * empty end-of-headers line (home.mira.net, phttpd/0.99.72
	     * does this).  Because clientBuildReply() fails we just
	     * call this reply a body, set the done_copying flag and
	     * continue...
	     */
	    http->flags.done_copying = 1;
	    context->flags.complete = 1;
	}
    } {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	assert(rep || (body_buf && body_size));
	tempBuffer.length = body_size;
	tempBuffer.data = body_buf;
	/* TODO: move the data in the buffer back by the request header size */
	clientStreamCallback((clientStreamNode *)http->client_stream.head->data, http, rep,
	    tempBuffer);
    }
}

int
clientReplyBodyTooLarge(HttpReply * rep, ssize_t clen)
{
    if (0 == rep->maxBodySize)
	return 0;		/* disabled */
    if (clen < 0)
	return 0;		/* unknown */
    if ((unsigned int)clen > rep->maxBodySize)
	return 1;		/* too large */
    return 0;
}

/*
 * returns true if client specified that the object must come from the cache
 * without contacting origin server
 */
static int
clientOnlyIfCached(clientHttpRequest * http)
{
    const request_t *r = http->request;
    assert(r);
    return r->cache_control &&
	EBIT_TEST(r->cache_control->mask, CC_ONLY_IF_CACHED);
}

/* Using this breaks the client layering just a little!
 */
StoreEntry *
clientCreateStoreEntry(clientReplyContext * context, method_t m,
    request_flags flags)
{
    clientHttpRequest *h = context->http;
    StoreEntry *e;
    assert(h != NULL);
    /*
     * For erroneous requests, we might not have a h->request,
     * so make a fake one.
     */
    if (h->request == NULL)
	h->request = requestLink(requestCreate(m, PROTO_NONE, null_string));
    e = storeCreateEntry(h->uri, h->log_uri, flags, m);
    context->sc = storeClientListAdd(e, context);
#if DELAY_POOLS
    delaySetStoreClient(context->sc, delayClient(h));
#endif
    context->reqofs = 0;
    context->reqsize = 0;
    /* I don't think this is actually needed! -- adrian */
    /* h->reqbuf = h->norm_reqbuf; */
//    assert(h->reqbuf == h->norm_reqbuf);
    /* The next line is illegal because we don't know if the client stream
     * buffers have been set up 
     */
//    storeClientCopy(h->sc, e, 0, HTTP_REQBUF_SZ, h->reqbuf,
    //        clientSendMoreData, context);
    /* So, we mark the store logic as complete */
    context->flags.storelogiccomplete = 1;
    /* and get the caller to request a read, from whereever they are */
    /* NOTE: after ANY data flows down the pipe, even one step, 
     * this function CAN NOT be used to manage errors 
     */
    return e;
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
