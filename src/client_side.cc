
/*
 * $Id: client_side.cc,v 1.614 2003/01/27 08:36:22 hno Exp $
 *
 * DEBUG: section 33    Client-side Routines
 * AUTHOR: Duane Wessels
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

/* Errors and client side 
 *
 * Problem the first: the store entry is no longer authoritative on the
 * reply status. EBITTEST (E_ABORT) is no longer a valid test outside
 * of client_side_reply.c.
 * Problem the second: resources are wasted if we delay in cleaning up.
 * Problem the third we can't depend on a connection close to clean up.
 * 
 * Nice thing the first: Any step in the stream can callback with data 
 * representing an error.
 * Nice thing the second: once you stop requesting reads from upstream,
 * upstream can be stopped too.
 *
 * Solution #1: Error has a callback mechanism to hand over a membuf
 * with the error content. The failing node pushes that back as the 
 * reply. Can this be generalised to reduce duplicate efforts?
 * A: Possibly. For now, only one location uses this.
 * How to deal with pre-stream errors?
 * Tell client_side_reply that we *want* an error page before any
 * stream calls occur. Then we simply read as normal.
 */

#include "squid.h"
#include "clientStream.h"
#include "IPInterception.h"
#include "authenticate.h"
#include "Store.h"
#include "comm.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "fde.h"
#include "client_side_request.h"

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

/* Persistent connection logic:
 *
 * requests (httpClientRequest structs) get added to the connection
 * list, with the current one being chr
 * 
 * The request is *immediately* kicked off, and data flows through
 * to clientSocketRecipient.
 * 
 * If the data that arrives at clientSocketRecipient is not for the current
 * request, clientSocketRecipient simply returns, without requesting more
 * data, or sending it.
 *
 * ClientKeepAliveNextRequest will then detect the presence of data in 
 * the next clientHttpRequest, and will send it, restablishing the 
 * data flow.
 */

/* our socket-related context */
class ClientSocketContext {
public:
    clientHttpRequest *http;	/* we own this */
    char reqbuf[HTTP_REQBUF_SZ];
    ClientSocketContext *next;
    struct {
	int deferred:1;		/* This is a pipelined request waiting for the
				 * current object to complete */
	int parsed_ok:1;        /* Was this parsed correctly? */
    } flags;
    bool mayUseConnection() const {return mayUseConnection_;}
    void mayUseConnection(bool aBool) {mayUseConnection_ = aBool;
    debug (33,3)("ClientSocketContext::mayUseConnection: This %p marked %d\n",
		 this, aBool);}
    struct {
	clientStreamNode *node;
	HttpReply *rep;
	StoreIOBuffer queuedBuffer;
    } deferredparams;
    off_t writtenToSocket;
    void pullData();
    off_t getNextRangeOffset() const;
    bool canPackMoreRanges() const;
    clientStream_status_t socketState();
    void sendBody(HttpReply * rep, StoreIOBuffer bodyData);
    void sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData);
    size_t lengthToSend(size_t maximum);
    void noteSentBodyBytes(size_t);
    void buildRangeHeader(HttpReply * rep);
    int fd() const;
    clientStreamNode * getTail() const;
    clientStreamNode * getClientReplyContext() const;
    void removeFromConnectionList(ConnStateData * conn);
    void deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer recievedData);
    bool multipartRangeRequest() const;
    void packRange(const char **buf,
    size_t size,
    MemBuf * mb);
private:
    void prepareReply(HttpReply * rep);
    bool mayUseConnection_; /* This request may use the connection -
			     * don't read anymore requests for now
			     */
};

CBDATA_TYPE(ClientSocketContext);

/* Local functions */
/* ClientSocketContext */
static FREE ClientSocketContextFree;
static ClientSocketContext *ClientSocketContextNew(clientHttpRequest *);
/* other */
static CWCB clientWriteComplete;
static IOWCB clientWriteBodyComplete;
static IOCB clientReadRequest;
static PF connStateFree;
static PF requestTimeout;
static PF clientLifetimeTimeout;
static ClientSocketContext *parseHttpRequestAbort(ConnStateData * conn,
    const char *uri);
static ClientSocketContext *parseHttpRequest(ConnStateData *, method_t *,
    char **, size_t *);
#if USE_IDENT
static IDCB clientIdentDone;
#endif
static CSCB clientSocketRecipient;
static CSD clientSocketDetach;
static void clientSetKeepaliveFlag(clientHttpRequest *);
static int clientIsContentLengthValid(request_t * r);
static DEFER httpAcceptDefer;
static int clientIsRequestBodyValid(int bodyLength);
static int clientIsRequestBodyTooLargeForPolicy(size_t bodyLength);
static void clientProcessBody(ConnStateData * conn);
static void clientUpdateStatHistCounters(log_type logType, int svc_time);
static void clientUpdateStatCounters(log_type logType);
static void clientUpdateHierCounters(HierarchyLogEntry *);
static bool clientPingHasFinished(ping_data const *aPing);
static void clientPrepareLogWithRequestDetails(request_t *, AccessLogEntry *);
static int connIsUsable(ConnStateData * conn);
static ClientSocketContext *connGetCurrentContext(ConnStateData * conn);
static int responseFinishedOrFailed(HttpReply * rep, StoreIOBuffer const &recievedData);
static int contextStartOfOutput(ClientSocketContext * context);
static void connReadNextRequest(ConnStateData * conn);
static void ClientSocketContextPushDeferredIfNeeded(ClientSocketContext * deferredRequest, ConnStateData * conn);
static void clientUpdateSocketStats(log_type logType, size_t size);

static ClientSocketContext *clientCheckRequestLineIsParseable(char *inbuf, size_t req_sz, ConnStateData * conn);
static ClientSocketContext *clientParseRequestMethod(char *inbuf, method_t * method_p, ConnStateData * conn);
static char *skipLeadingSpace(char *aString);
static char *findTrailingHTTPVersion(char *uriAndHTTPVersion);
static void trimTrailingSpaces(char *aString, size_t len);
static ClientSocketContext *parseURIandHTTPVersion(char **url_p, http_version_t * http_ver_p, ConnStateData * conn);
static void setLogUri(clientHttpRequest * http, char const *uri);
static void prepareInternalUrl(clientHttpRequest * http, char *url);
static void prepareForwardProxyUrl(clientHttpRequest * http, char *url);
static void prepareAcceleratedUrl(clientHttpRequest * http, char *url, char *req_hdr);
static int connGetAvailableBufferLength(ConnStateData const *conn);
static void connMakeSpaceAvailable(ConnStateData * conn);
static void connAddContextToQueue(ConnStateData * conn, ClientSocketContext * context);
static int connGetConcurrentRequestCount(ConnStateData * conn);
static int connReadWasError(ConnStateData * conn, comm_err_t, int size);
static int connFinishedWithConn(ConnStateData * conn, int size);
static void connNoteUseOfBuffer(ConnStateData * conn, size_t byteCount);
static int connKeepReadingIncompleteRequest(ConnStateData * conn);
static void connCancelIncompleteRequests(ConnStateData * conn);
static ConnStateData *connStateCreate(struct sockaddr_in *peer, struct sockaddr_in *me, int fd);
static int connAreAllContextsForThisConnection(ConnStateData * connState);
static void connFreeAllContexts(ConnStateData * connState);

int
ClientSocketContext::fd() const
{
    assert (http);
    assert (http->conn);
    return http->conn->fd;
}

clientStreamNode *
ClientSocketContext::getTail() const
{
    return (clientStreamNode *)http->client_stream.tail->data;
}

clientStreamNode *
ClientSocketContext::getClientReplyContext() const
{
    return (clientStreamNode *)http->client_stream.tail->prev->data;
}

/*
 * This routine should be called to grow the inbuf and then
 * call comm_read().
 */
void
clientReadSomeData(ConnStateData *conn)
{
    if (conn->reading)
	return;
    conn->reading = true;
    size_t len;
    
    debug(33, 4) ("clientReadSomeData: FD %d: reading request...\n", conn->fd);

    connMakeSpaceAvailable(conn);
    len = connGetAvailableBufferLength(conn) - 1;
    
    /* Make sure we are not still reading from the client side! */
    /* XXX this could take a bit of CPU time! aiee! -- adrian */
    assert(!comm_has_pending_read(conn->fd));
    comm_read(conn->fd, conn->in.buf + conn->in.notYetUsed, len, clientReadRequest, conn);
}
      

void
ClientSocketContext::removeFromConnectionList(ConnStateData * conn)
{
    ClientSocketContext **tempContextPointer;
    assert(conn);
    assert(connGetCurrentContext(conn) != NULL);
    /* Unlink us from the connection request list */
    tempContextPointer = (ClientSocketContext **) & conn->currentobject;
    while (*tempContextPointer) {
	if (*tempContextPointer == this)
	    break;
	tempContextPointer = &(*tempContextPointer)->next;
    }
    assert(*tempContextPointer != NULL);
    *tempContextPointer = next;
    next = NULL;
}

void
ClientSocketContextFree(void *data)
{
    ClientSocketContext *context = (ClientSocketContext *)data;
    ConnStateData *conn = context->http->conn;
    clientStreamNode *node = context->getTail();
    /* We are *always* the tail - prevent recursive free */
    assert(context == node->data);
    node->data = NULL;
    httpRequestFree(context->http);
    /* clean up connection links to us */
    assert(context != context->next);
    if (conn)
	context->removeFromConnectionList(conn);
}

ClientSocketContext *
ClientSocketContextNew(clientHttpRequest * http)
{
    ClientSocketContext *newContext;
    assert(http != NULL);
    CBDATA_INIT_TYPE_FREECB(ClientSocketContext, ClientSocketContextFree);
    newContext = cbdataAlloc(ClientSocketContext);
    newContext->http = http;
    return newContext;
}

#if USE_IDENT
static void
clientIdentDone(const char *ident, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    xstrncpy(conn->rfc931, ident ? ident : dash_str, USER_IDENT_SZ);
}

#endif

void
clientUpdateStatCounters(log_type logType)
{
    statCounter.client_http.requests++;
    if (logTypeIsATcpHit(logType))
	statCounter.client_http.hits++;
    if (logType == LOG_TCP_HIT)
	statCounter.client_http.disk_hits++;
    else if (logType == LOG_TCP_MEM_HIT)
	statCounter.client_http.mem_hits++;
}

void
clientUpdateStatHistCounters(log_type logType, int svc_time)
{
    statHistCount(&statCounter.client_http.all_svc_time, svc_time);
    /*
     * The idea here is not to be complete, but to get service times
     * for only well-defined types.  For example, we don't include
     * LOG_TCP_REFRESH_FAIL_HIT because its not really a cache hit
     * (we *tried* to validate it, but failed).
     */
    switch (logType) {
    case LOG_TCP_REFRESH_HIT:
	statHistCount(&statCounter.client_http.nh_svc_time, svc_time);
	break;
    case LOG_TCP_IMS_HIT:
	statHistCount(&statCounter.client_http.nm_svc_time, svc_time);
	break;
    case LOG_TCP_HIT:
    case LOG_TCP_MEM_HIT:
    case LOG_TCP_OFFLINE_HIT:
	statHistCount(&statCounter.client_http.hit_svc_time, svc_time);
	break;
    case LOG_TCP_MISS:
    case LOG_TCP_CLIENT_REFRESH_MISS:
	statHistCount(&statCounter.client_http.miss_svc_time, svc_time);
	break;
    default:
	/* make compiler warnings go away */
	break;
    }
}

bool
clientPingHasFinished(ping_data const *aPing)
{
    if (0 != aPing->stop.tv_sec && 0 != aPing->start.tv_sec)
	return true;
    return false;
}

void
clientUpdateHierCounters(HierarchyLogEntry * someEntry)
{
    ping_data *i;
    switch (someEntry->code) {
#if USE_CACHE_DIGESTS
    case CD_PARENT_HIT:
    case CD_SIBLING_HIT:
	statCounter.cd.times_used++;
	break;
#endif
    case SIBLING_HIT:
    case PARENT_HIT:
    case FIRST_PARENT_MISS:
    case CLOSEST_PARENT_MISS:
	statCounter.icp.times_used++;
	i = &someEntry->ping;
	if (clientPingHasFinished(i))
	    statHistCount(&statCounter.icp.query_svc_time,
		tvSubUsec(i->start, i->stop));
	if (i->timeout)
	    statCounter.icp.query_timeouts++;
	break;
    case CLOSEST_PARENT:
    case CLOSEST_DIRECT:
	statCounter.netdb.times_used++;
	break;
    default:
	break;
    }
}

void
ClientHttpRequest::updateCounters()
{
    clientUpdateStatCounters(logType);
    if (request->errType != ERR_NONE)
	statCounter.client_http.errors++;
    clientUpdateStatHistCounters(logType,
	tvSubMsec(start, current_time));
    clientUpdateHierCounters(&request->hier);
}

MemObject *
ClientHttpRequest::memObject() const
{
    if (entry)
	return entry->mem_obj;
    return NULL;
}

void
clientPrepareLogWithRequestDetails(request_t * request, AccessLogEntry * aLogEntry)
{
    Packer p;
    MemBuf mb;
    assert(request);
    assert(aLogEntry);
    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    httpHeaderPackInto(&request->header, &p);
    aLogEntry->http.method = request->method;
    aLogEntry->http.version = request->http_ver;
    aLogEntry->headers.request = xstrdup(mb.buf);
    aLogEntry->hier = request->hier;
    if (request->auth_user_request) {
	aLogEntry->cache.authuser =
	    xstrdup(authenticateUserRequestUsername(request->
		auth_user_request));
	authenticateAuthUserRequestUnlock(request->auth_user_request);
	request->auth_user_request = NULL;
    }
    packerClean(&p);
    memBufClean(&mb);
}

void
ClientHttpRequest::logRequest()
{
    if (out.size || logType) {
	al.icp.opcode = ICP_INVALID;
	al.url = log_uri;
	debug(33, 9) ("clientLogRequest: al.url='%s'\n", al.url);
	if (memObject()) {
	    al.http.code = memObject()->getReply()->sline.status;
	    al.http.content_type = memObject()->getReply()->content_type.buf();
	}
	al.cache.caddr = conn ? conn->log_addr : no_addr;
	al.cache.size = out.size;
	al.cache.code = logType;
	al.cache.msec = tvSubMsec(start, current_time);
	if (request)
	    clientPrepareLogWithRequestDetails(request, &al);
	if (conn && conn->rfc931[0])
	    al.cache.rfc931 = conn->rfc931;
#if USE_SSL
	if (conn)
	    al.cache.ssluser = sslGetUserEmail(fd_table[conn->fd].ssl);
#endif
	accessLogLog(&al);
	accessLogFreeMemory(&al);
	updateCounters();
	if (conn)
	    clientdbUpdate(conn->peer.sin_addr, logType, PROTO_HTTP, out.size);
    }
}

void
ClientHttpRequest::freeResources()
{
    safe_free(uri);
    safe_free(log_uri);
    safe_free(redirect.location);
    range_iter.boundary.clean();
    requestUnlink(request);
    request = NULL;
    if (client_stream.tail)
	clientStreamAbort((clientStreamNode *)client_stream.tail->data, this);
}

void
httpRequestFree(void *data)
{
    clientHttpRequest *http = (clientHttpRequest *)data;
    assert(http != NULL);
    delete http;
}

int
connAreAllContextsForThisConnection(ConnStateData * connState)
{
    ClientSocketContext *context;
    assert(connState != NULL);
    context = connGetCurrentContext(connState);
    while (context) {
	if (context->http->conn != connState)
	    return 0;
	context = context->next;
    }
    return -1;
}

void
connFreeAllContexts(ConnStateData * connState)
{
    ClientSocketContext *context;
    while ((context = connGetCurrentContext(connState)) != NULL) {
	assert(connGetCurrentContext(connState) !=
	    connGetCurrentContext(connState)->next);
	cbdataFree(context);
    }
}

/* This is a handler normally called by comm_close() */
static void
connStateFree(int fd, void *data)
{
    ConnStateData *connState = (ConnStateData *)data;
    debug(33, 3) ("connStateFree: FD %d\n", fd);
    assert(connState != NULL);
    clientdbEstablished(connState->peer.sin_addr, -1);	/* decrement */
    assert(connAreAllContextsForThisConnection(connState));
    connFreeAllContexts(connState);
    if (connState->auth_user_request)
	authenticateAuthUserRequestUnlock(connState->auth_user_request);
    connState->auth_user_request = NULL;
    authenticateOnCloseConnection(connState);
    memFreeBuf(connState->in.allocatedSize, connState->in.buf);
    pconnHistCount(0, connState->nrequests);
    cbdataFree(connState);
}

/*
 * clientSetKeepaliveFlag() sets request->flags.proxy_keepalive.
 * This is the client-side persistent connection flag.  We need
 * to set this relatively early in the request processing
 * to handle hacks for broken servers and clients.
 */
static void
clientSetKeepaliveFlag(clientHttpRequest * http)
{
    request_t *request = http->request;
    const HttpHeader *req_hdr = &request->header;

    debug(33, 3) ("clientSetKeepaliveFlag: http_ver = %d.%d\n",
	request->http_ver.major, request->http_ver.minor);
    debug(33, 3) ("clientSetKeepaliveFlag: method = %s\n",
	RequestMethodStr[request->method]);
    if (!Config.onoff.client_pconns)
	request->flags.proxy_keepalive = 0;
    else {
	http_version_t http_ver;
	httpBuildVersion(&http_ver, 1, 0);
	/* we are HTTP/1.0, no matter what the client requests... */
	if (httpMsgIsPersistent(http_ver, req_hdr))
	    request->flags.proxy_keepalive = 1;
    }
}

static int
clientIsContentLengthValid(request_t * r)
{
    switch (r->method) {
    case METHOD_PUT:
    case METHOD_POST:
	/* PUT/POST requires a request entity */
	return (r->content_length >= 0);
    case METHOD_GET:
    case METHOD_HEAD:
	/* We do not want to see a request entity on GET/HEAD requests */
	return (r->content_length <= 0 || Config.onoff.request_entities);
    default:
	/* For other types of requests we don't care */
	return 1;
    }
    /* NOT REACHED */
}

int
clientIsRequestBodyValid(int bodyLength)
{
    if (bodyLength >= 0)
	return 1;
    return 0;
}

int
clientIsRequestBodyTooLargeForPolicy(size_t bodyLength)
{
    if (Config.maxRequestBodySize &&
	bodyLength > Config.maxRequestBodySize)
	return 1;		/* too large */
    return 0;
}

int
connIsUsable(ConnStateData * conn)
{
    if (!conn || conn->fd == -1)
	return 0;
    return 1;
}

ClientSocketContext *
connGetCurrentContext(ConnStateData * conn)
{
    assert(conn);
    return (ClientSocketContext *)conn->currentobject;
}

void
ClientSocketContext::deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer recievedData)
{
    debug(33, 2) ("clientSocketRecipient: Deferring %s\n", http->uri);
    assert(flags.deferred == 0);
    flags.deferred = 1;
    deferredparams.node = node;
    deferredparams.rep = rep;
    deferredparams.queuedBuffer = recievedData;
    return;
}

int
responseFinishedOrFailed(HttpReply * rep, StoreIOBuffer const & recievedData)
{
    if (rep == NULL && recievedData.data == NULL && recievedData.length == 0)
	return 1;
    return 0;
}

int
contextStartOfOutput(ClientSocketContext * context)
{
    return context->http->out.size == 0 ? 1 : 0;
}

size_t
ClientSocketContext::lengthToSend(size_t maximum)
{
    if (!http->request->range)
	return maximum;
    assert (canPackMoreRanges());
    if (http->range_iter.debt() == -1)
	return maximum;
    assert (http->range_iter.debt() > 0);
    return XMIN(http->range_iter.debt(), (ssize_t)maximum);
}

void
ClientSocketContext::noteSentBodyBytes(size_t bytes)
{
    http->out.offset += bytes;
    if (!http->request->range)
	return;
    if (http->range_iter.debt() != -1) {
	http->range_iter.debt(http->range_iter.debt() - bytes);
	assert (http->range_iter.debt() >= 0);
    }
    assert (http->range_iter.debt() == -1 ||
	    http->range_iter.debt() >= 0);
}
 
bool
ClientHttpRequest::multipartRangeRequest() const
{
    return request->multipartRangeRequest();
}

bool
ClientSocketContext::multipartRangeRequest() const
{
    return http->multipartRangeRequest();
}

void
ClientSocketContext::sendBody(HttpReply * rep, StoreIOBuffer bodyData)
{
    assert(rep == NULL);

    if (!multipartRangeRequest()) {
	size_t length = lengthToSend(bodyData.length);
	noteSentBodyBytes (length);
	comm_write(fd(), bodyData.data, length,
		   clientWriteBodyComplete, this);
	return;
    }

    MemBuf mb;
    memBufDefInit(&mb);
    char const *t = bodyData.data;
    packRange(&t, bodyData.length, &mb);
    /* write */
    comm_old_write_mbuf(fd(), mb, clientWriteComplete, this);
    return;
}

/* put terminating boundary for multiparts */
static void
clientPackTermBound(String boundary, MemBuf * mb)
{
    memBufPrintf(mb, "\r\n--%s--\r\n", boundary.buf());
    debug(33, 6) ("clientPackTermBound: buf offset: %ld\n", (long int) mb->size);
}

/* appends a "part" HTTP header (as in a multi-part/range reply) to the buffer */
static void
clientPackRangeHdr(const HttpReply * rep, const HttpHdrRangeSpec * spec, String boundary, MemBuf * mb)
{
    HttpHeader hdr;
    Packer p;
    assert(rep);
    assert(spec);

    /* put boundary */
    debug(33, 5) ("clientPackRangeHdr: appending boundary: %s\n", boundary.buf());
    /* rfc2046 requires to _prepend_ boundary with <crlf>! */
    memBufPrintf(mb, "\r\n--%s\r\n", boundary.buf());

    /* stuff the header with required entries and pack it */
    httpHeaderInit(&hdr, hoReply);
    if (httpHeaderHas(&rep->header, HDR_CONTENT_TYPE))
	httpHeaderPutStr(&hdr, HDR_CONTENT_TYPE, httpHeaderGetStr(&rep->header, HDR_CONTENT_TYPE));
    httpHeaderAddContRange(&hdr, *spec, rep->content_length);
    packerToMemInit(&p, mb);
    httpHeaderPackInto(&hdr, &p);
    packerClean(&p);
    httpHeaderClean(&hdr);

    /* append <crlf> (we packed a header, not a reply) */
    memBufPrintf(mb, "\r\n");
}

/*
 * extracts a "range" from *buf and appends them to mb, updating
 * all offsets and such.
 */
void
ClientSocketContext::packRange(const char **buf,
    size_t size,
    MemBuf * mb)
{
    HttpHdrRangeIter * i = &http->range_iter;
    size_t available = size;
    while (i->currentSpec() && available) {
	const size_t copy_sz = lengthToSend(available);
	/*
	 * intersection of "have" and "need" ranges must not be empty
	 */
	assert(http->out.offset < i->currentSpec()->offset + i->currentSpec()->length);
	assert(http->out.offset + available > (size_t)i->currentSpec()->offset);

	/*
	 * put boundary and headers at the beginning of a range in a
	 * multi-range
	 */
	if (http->multipartRangeRequest() && i->debt() == i->currentSpec()->length) {
	    assert(http->entry->mem_obj);
	    clientPackRangeHdr(
		http->entry->mem_obj->getReply(),	/* original reply */
		i->currentSpec(),		/* current range */
		i->boundary,	/* boundary, the same for all */
		mb);
	}
	/*
	 * append content
	 */
	debug(33, 3) ("clientPackRange: appending %ld bytes\n", (long int) copy_sz);
	noteSentBodyBytes (copy_sz);
	memBufAppend(mb, *buf, copy_sz);
	/*
	 * update offsets
	 */
	available -= copy_sz;
	//body_off += copy_sz;
	*buf += copy_sz;
	/*
	 * paranoid check
	 */
	assert(available >= 0 && i->debt() >= 0 || i->debt() == -1);
	if (i->debt() == 0)
	    /* put terminating boundary for multiparts */
	    clientPackTermBound(i->boundary, mb);
	if (!canPackMoreRanges())
	    return;
	off_t next = getNextRangeOffset();
	assert (next >= http->out.offset);
	size_t skip = next - http->out.offset;
	if (available <= skip)
	    return;
	available -= skip;
	*buf += skip;
    }
}

/* returns expected content length for multi-range replies
 * note: assumes that httpHdrRangeCanonize has already been called
 * warning: assumes that HTTP headers for individual ranges at the
 *          time of the actuall assembly will be exactly the same as
 *          the headers when clientMRangeCLen() is called */
int
ClientHttpRequest::mRangeCLen()
{
    int clen = 0;
    MemBuf mb;

    assert(entry->mem_obj);

    memBufDefInit(&mb);
    HttpHdrRange::iterator pos = request->range->begin();
    while (pos != request->range->end()) {
	/* account for headers for this range */
	memBufReset(&mb);
	clientPackRangeHdr(entry->mem_obj->getReply(),
	    *pos, range_iter.boundary, &mb);
	clen += mb.size;

	/* account for range content */
	clen += (*pos)->length;

	debug(33, 6) ("clientMRangeCLen: (clen += %ld + %ld) == %d\n",
	    (long int) mb.size, (long int) (*pos)->length, clen);
	++pos;
    }
    /* account for the terminating boundary */
    memBufReset(&mb);
    clientPackTermBound(range_iter.boundary, &mb);
    clen += mb.size;

    memBufClean(&mb);
    return clen;
}

/*
 * returns true if If-Range specs match reply, false otherwise
 */
static int
clientIfRangeMatch(clientHttpRequest * http, HttpReply * rep)
{
    const TimeOrTag spec = httpHeaderGetTimeOrTag(&http->request->header, HDR_IF_RANGE);
    /* check for parsing falure */
    if (!spec.valid)
	return 0;
    /* got an ETag? */
    if (spec.tag.str) {
	ETag rep_tag = httpHeaderGetETag(&rep->header, HDR_ETAG);
	debug(33, 3) ("clientIfRangeMatch: ETags: %s and %s\n",
	    spec.tag.str, rep_tag.str ? rep_tag.str : "<none>");
	if (!rep_tag.str)
	    return 0;		/* entity has no etag to compare with! */
	if (spec.tag.weak || rep_tag.weak) {
	    debug(33, 1) ("clientIfRangeMatch: Weak ETags are not allowed in If-Range: %s ? %s\n",
		spec.tag.str, rep_tag.str);
	    return 0;		/* must use strong validator for sub-range requests */
	}
	return etagIsEqual(&rep_tag, &spec.tag);
    }
    /* got modification time? */
    if (spec.time >= 0) {
	return http->entry->lastmod <= spec.time;
    }
    assert(0);			/* should not happen */
    return 0;
}

/* generates a "unique" boundary string for multipart responses
 * the caller is responsible for cleaning the string */
String
ClientHttpRequest::rangeBoundaryStr() const
{
    assert(this);
    const char *key;
    String b (full_appname_string);
    b.append (":",1);
    key = entry->getMD5Text();
    b.append(key, strlen(key));
    return b;
}

/* adds appropriate Range headers if needed */
void
ClientSocketContext::buildRangeHeader(HttpReply * rep)
{
    HttpHeader *hdr = rep ? &rep->header : 0;
    const char *range_err = NULL;
    request_t *request = http->request;
    assert(request->range);
    /* check if we still want to do ranges */
    if (!rep)
	range_err = "no [parse-able] reply";
    else if ((rep->sline.status != HTTP_OK) && (rep->sline.status != HTTP_PARTIAL_CONTENT))
	range_err = "wrong status code";
#if 0
    else if (httpHeaderHas(hdr, HDR_CONTENT_RANGE))
	range_err = "origin server does ranges";
#endif
    else if (rep->content_length < 0)
	range_err = "unknown length";
    else if (rep->content_length != http->entry->mem_obj->getReply()->content_length)
	range_err = "INCONSISTENT length";	/* a bug? */
    else if (httpHeaderHas(&http->request->header, HDR_IF_RANGE) && !clientIfRangeMatch(http, rep))
	range_err = "If-Range match failed";
    else if (!http->request->range->canonize(rep))
	range_err = "canonization failed";
    else if (http->request->range->isComplex())
	range_err = "too complex range header";
    else if (!request->flags.cachable)	/* from we_do_ranges in http.c */
	range_err = "non-cachable request";
#if 0
    else if (!logTypeIsATcpHit(http->logType); && http->request->range->offsetLimitExceeded())
	range_err = "range outside range_offset_limit";
#endif
    /* get rid of our range specs on error */
    if (range_err) {
	/* XXX Why do we do this here, and not when parsing the request ? */
	debug(33, 3) ("clientBuildRangeHeader: will not do ranges: %s.\n", range_err);
	http->request->range->deleteSelf();
	http->request->range = NULL;
    } else {
	const int spec_count = http->request->range->specs.count;
	int actual_clen = -1;

	debug(33, 3) ("clientBuildRangeHeader: range spec count: %d virgin clen: %d\n",
	    spec_count, rep->content_length);
	assert(spec_count > 0);
	/* ETags should not be returned with Partial Content replies? */
	httpHeaderDelById(hdr, HDR_ETAG);
	/* append appropriate header(s) */
	if (spec_count == 1) {
	    HttpHdrRange::iterator pos = http->request->range->begin();
	    assert(*pos);
	    /* append Content-Range */
	    if (!httpHeaderHas(hdr, HDR_CONTENT_RANGE)) {
		/* No content range, so this was a full object we are 
		 * sending parts of.
		 */
		httpHeaderAddContRange(hdr, **pos, rep->content_length);
	    }
	    /* set new Content-Length to the actual number of bytes
	     * transmitted in the message-body */
	    actual_clen = (*pos)->length;
	} else {
	    /* multipart! */
	    /* generate boundary string */
	    http->range_iter.boundary = http->rangeBoundaryStr();
	    /* delete old Content-Type, add ours */
	    httpHeaderDelById(hdr, HDR_CONTENT_TYPE);
	    httpHeaderPutStrf(hdr, HDR_CONTENT_TYPE,
		"multipart/byteranges; boundary=\"%s\"",
		http->range_iter.boundary.buf());
	    /* Content-Length is not required in multipart responses
	     * but it is always nice to have one */
	    actual_clen = http->mRangeCLen();
	}

	/* replace Content-Length header */
	assert(actual_clen >= 0);
	httpHeaderDelById(hdr, HDR_CONTENT_LENGTH);
	httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, actual_clen);
	debug(33, 3) ("clientBuildRangeHeader: actual content length: %d\n", actual_clen);
	/* And start the range iter off */
	http->range_iter.updateSpec();
    }
}

void
ClientSocketContext::prepareReply(HttpReply * rep)
{
    if (http->request->range)
	buildRangeHeader(rep);
}

void
ClientSocketContext::sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData)
{
    prepareReply(rep);
    /* init mb; put status line and headers if any */
    assert (rep);
    MemBuf mb = httpReplyPack(rep);
    /* Save length of headers for persistent conn checks */
    http->out.headers_sz = mb.size;
#if HEADERS_LOG
    headersLog(0, 0, http->request->method, rep);
#endif
    httpReplyDestroy(rep);
    rep = NULL;
    if (bodyData.data && bodyData.length) {
	if (!multipartRangeRequest()) {
	    size_t length = lengthToSend(bodyData.length);
	    noteSentBodyBytes (length);
	    
	    memBufAppend(&mb, bodyData.data, length);
	} else {
	    char const *t = bodyData.data;
	    packRange(&t,
			    bodyData.length,
			    &mb);
	}
    }
    /* write */
    comm_old_write_mbuf(fd(), mb, clientWriteComplete, this);
    /* if we don't do it, who will? */
}

/*
 * Write a chunk of data to a client socket. If the reply is present, send the reply headers down the wire too,
 * and clean them up when finished.
 * Pre-condition: 
 *   The request is one backed by a connection, not an internal request.
 *   data context is not NULL
 *   There are no more entries in the stream chain.
 */
static void
clientSocketRecipient(clientStreamNode * node, clientHttpRequest * http,
    HttpReply * rep, StoreIOBuffer recievedData)
{
    int fd;
    ClientSocketContext *context;
    /* Test preconditions */
    assert(node != NULL);
    /* TODO: handle this rather than asserting 
     * - it should only ever happen if we cause an abort and 
     * the callback chain loops back to here, so we can simply return. 
     * However, that itself shouldn't happen, so it stays as an assert for now. 
     */
    assert(cbdataReferenceValid(node));
    assert(node->data != NULL);
    assert(node->node.next == NULL);
    context = (ClientSocketContext *)node->data;
    assert(connIsUsable(http->conn));
    fd = http->conn->fd;
    /* TODO: check offset is what we asked for */
    if (connGetCurrentContext(http->conn) != context) {
	context->deferRecipientForLater(node, rep, recievedData);
	return;
    }
    if (responseFinishedOrFailed(rep, recievedData)) {
	clientWriteComplete(fd, NULL, 0, COMM_OK, context);
	return;
    }
    if (!contextStartOfOutput(context))
	context->sendBody(rep, recievedData);
    else
	context->sendStartOfMessage(rep, recievedData);
}

/* Called when a downstream node is no longer interested in 
 * our data. As we are a terminal node, this means on aborts
 * only
 */
void
clientSocketDetach(clientStreamNode * node, clientHttpRequest * http)
{
    ClientSocketContext *context;
    /* Test preconditions */
    assert(node != NULL);
    /* TODO: handle this rather than asserting 
     * - it should only ever happen if we cause an abort and 
     * the callback chain loops back to here, so we can simply return. 
     * However, that itself shouldn't happen, so it stays as an assert for now.
     */
    assert(cbdataReferenceValid(node));
    /* Set null by ContextFree */
    assert(node->data == NULL);
    assert(node->node.next == NULL);
    context = (ClientSocketContext *)node->data;
    /* We are only called when the client socket shutsdown.
     * Tell the prev pipeline member we're finished
     */
    clientStreamDetach(node, http);
}

static void
clientWriteBodyComplete(int fd, char *buf, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    clientWriteComplete(fd, NULL, size, errflag, data);
}

void
connReadNextRequest(ConnStateData * conn)
{
    debug(33, 5) ("clientReadNextRequest: FD %d reading next req\n",
	conn->fd);
    fd_note(conn->fd, "Waiting for next request");
    /*
     * Set the timeout BEFORE calling clientReadRequest().
     */
    commSetTimeout(conn->fd, Config.Timeout.persistent_request,
	requestTimeout, conn);
    conn->defer.until = 0;	/* Kick it to read a new request */
    clientReadSomeData(conn);
    /* Please don't do anything with the FD past here! */
}

void
ClientSocketContextPushDeferredIfNeeded(ClientSocketContext * deferredRequest, ConnStateData * conn)
{
    debug(33, 2) ("ClientSocketContextPushDeferredIfNeeded: FD %d Sending next\n",
	conn->fd);
    /* If the client stream is waiting on a socket write to occur, then */
    if (deferredRequest->flags.deferred) {
	/* NO data is allowed to have been sent */
	assert(deferredRequest->http->out.size == 0);
	clientSocketRecipient(deferredRequest->deferredparams.node,
	    deferredRequest->http,
	    deferredRequest->deferredparams.rep,
	    deferredRequest->deferredparams.queuedBuffer);
    }
    /* otherwise, the request is still active in a callbacksomewhere,
     * and we are done
     */
}

static void
clientKeepaliveNextRequest(ClientSocketContext * context)
{
    clientHttpRequest *http = context->http;
    ConnStateData *conn = http->conn;
    ClientSocketContext *deferredRequest;

    debug(33, 3) ("clientKeepaliveNextRequest: FD %d\n", conn->fd);
    cbdataFree(context);
    if ((deferredRequest = connGetCurrentContext(conn)) == NULL)
	connReadNextRequest(conn);
    else
	ClientSocketContextPushDeferredIfNeeded(deferredRequest, conn);
}

void
clientUpdateSocketStats(log_type logType, size_t size)
{
    if (size == 0)
	return;
    kb_incr(&statCounter.client_http.kbytes_out, size);
    if (logTypeIsATcpHit(logType))
	kb_incr(&statCounter.client_http.hit_kbytes_out, size);
}

/* returns true if there is still data available to pack more ranges
 * increments iterator "i"
 * used by clientPackMoreRanges */
bool
ClientSocketContext::canPackMoreRanges() const
{
    /* first update "i" if needed */
    if (!http->range_iter.debt()) {
	debug (33,5)("ClientSocketContext::canPackMoreRanges: At end of current range spec for fd %d\n",fd());
	if (http->range_iter.pos.incrementable())
	    ++http->range_iter.pos;
	http->range_iter.updateSpec();
    }
    assert(!http->range_iter.debt() == !http->range_iter.currentSpec());
    /* paranoid sync condition */
    /* continue condition: need_more_data */
    debug (33,5)("ClientSocketContext::canPackMoreRanges: returning %d\n", http->range_iter.currentSpec() ? true : false);
    return http->range_iter.currentSpec() ? true : false;
}

off_t
ClientSocketContext::getNextRangeOffset() const
{
    if (http->request->range) {
	/* offset in range specs does not count the prefix of an http msg */
	debug (0,0) ("ClientSocketContext::getNextRangeOffset: http offset %lu\n", http->out.offset);
	/* check: reply was parsed and range iterator was initialized */
	assert(http->range_iter.valid);
	/* filter out data according to range specs */
	assert (canPackMoreRanges());
	  {
	    off_t start;		/* offset of still missing data */
	    assert(http->range_iter.currentSpec());
	    start = http->range_iter.currentSpec()->offset + http->range_iter.currentSpec()->length - http->range_iter.debt();
	    debug(33, 3) ("clientPackMoreRanges: in:  offset: %ld\n",
			  (long int) http->out.offset);
	    debug(33, 3) ("clientPackMoreRanges: out: start: %ld spec[%ld]: [%ld, %ld), len: %ld debt: %ld\n",
			  (long int) start, (long int) (http->range_iter.pos - http->request->range->begin()), (long int) http->range_iter.currentSpec()->offset, (long int) (http->range_iter.currentSpec()->offset + http->range_iter.currentSpec()->length), (long int) http->range_iter.currentSpec()->length, (long int) http->range_iter.debt());
	    if (http->range_iter.currentSpec()->length != -1)
	    assert(http->out.offset <= start);	/* we did not miss it */
	    return start;
	}
#if 0
    } else if (http->request->range->specs.count > 1) {
	/* put terminating boundary for multiparts */
	clientPackTermBound(i->boundary, mb);
#endif
    }

    return http->out.offset;
}

void
ClientSocketContext::pullData()
{
    debug (33,5)("ClientSocketContext::pullData: FD %d attempting to pull upstream data\n", fd());
    /* More data will be coming from the stream. */
    StoreIOBuffer readBuffer;
    /* XXX: Next requested byte in the range sequence */
    /* XXX: length = getmaximumrangelenfgth */
    readBuffer.offset = getNextRangeOffset();
    readBuffer.length = HTTP_REQBUF_SZ;
    readBuffer.data = reqbuf;
    /* we may note we have reached the end of the wanted ranges */
    clientStreamRead(getTail(), http, readBuffer);
}

clientStream_status_t 
ClientSocketContext::socketState()
{
    switch (clientStreamStatus(getTail(), http)) {
      case STREAM_NONE:
        /* check for range support ending */
        if (http->request->range) {
	    /* check: reply was parsed and range iterator was initialized */
	    assert(http->range_iter.valid);
	    /* filter out data according to range specs */
	    if (!canPackMoreRanges()) {
		debug (33,5)("ClientSocketContext::socketState: Range request has hit end of returnable range sequence on fd %d\n", fd());
		if (http->request->flags.proxy_keepalive)
		    return STREAM_COMPLETE;
	        else
		    return STREAM_UNPLANNED_COMPLETE;
	    }
	}
	return STREAM_NONE;
      case STREAM_COMPLETE:
        return STREAM_COMPLETE;
      case STREAM_UNPLANNED_COMPLETE:
	return STREAM_UNPLANNED_COMPLETE;
      case STREAM_FAILED:
	return STREAM_FAILED;
    }
    fatal ("unreachable code\n");
    return STREAM_NONE;
}

/* A write has just completed to the client, or we have just realised there is
 * no more data to send.
 */
void
clientWriteComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag, void *data)
{
    ClientSocketContext *context = (ClientSocketContext *)data;
    clientHttpRequest *http = context->http;
    StoreEntry *entry = http->entry;
    http->out.size += size;
    assert(fd > -1);
    debug(33, 5) ("clientWriteComplete: FD %d, sz %ld, err %d, off %ld, len %d\n",
	fd, (long int) size, errflag, (long int) http->out.size, entry ? objectLen(entry) : 0);
    clientUpdateSocketStats(http->logType, size);
    if (errflag || clientHttpRequestStatus(fd, http)) {
	debug (33,5)("clientWriteComplete: FD %d, closing connection due to failure, or true requeststatus\n", fd);
	comm_close(fd);
	/* Do we leak here ? */
	return;
    }
    switch (context->socketState()) {
    case STREAM_NONE:
	context->pullData();
	break;
    case STREAM_COMPLETE:
	debug(33, 5) ("clientWriteComplete: FD %d Keeping Alive\n", fd);
	clientKeepaliveNextRequest(context);
	return;
    case STREAM_UNPLANNED_COMPLETE:
	/* fallthrough */
    case STREAM_FAILED:
	comm_close(fd);
	return;
    default:
	fatal("Hit unreachable code in clientWriteComplete\n");
    }
}

extern "C" CSR clientGetMoreData;
extern "C" CSS clientReplyStatus;
extern "C" CSD clientReplyDetach;

static ClientSocketContext *
parseHttpRequestAbort(ConnStateData * conn, const char *uri)
{
    clientHttpRequest *http;
    ClientSocketContext *context;
    StoreIOBuffer tempBuffer;
    http = new ClientHttpRequest;
    http->conn = conn;
    http->req_sz = conn->in.notYetUsed;
    http->uri = xstrdup(uri);
    setLogUri (http, uri);
    context = ClientSocketContextNew(http);
    tempBuffer.data = context->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
	clientReplyStatus, clientReplyNewContext(http), clientSocketRecipient,
	clientSocketDetach, context, tempBuffer);
    dlinkAdd(http, &http->active, &ClientActiveRequests);
    return context;
}

ClientSocketContext *
clientCheckRequestLineIsParseable(char *inbuf, size_t req_sz, ConnStateData * conn)
{
    if (strlen(inbuf) != req_sz) {
	debug(33, 1) ("clientCheckRequestLineIsParseable: Requestheader contains NULL characters\n");
	return parseHttpRequestAbort(conn, "error:invalid-request");
    }
    return NULL;
}

ClientSocketContext *
clientParseRequestMethod(char *inbuf, method_t * method_p, ConnStateData * conn)
{
    char *mstr = NULL;
    if ((mstr = strtok(inbuf, "\t ")) == NULL) {
	debug(33, 1) ("clientParseRequestMethod: Can't get request method\n");
	return parseHttpRequestAbort(conn, "error:invalid-request-method");
    }
    *method_p = urlParseMethod(mstr);
    if (*method_p == METHOD_NONE) {
	debug(33, 1) ("clientParseRequestMethod: Unsupported method '%s'\n", mstr);
	return parseHttpRequestAbort(conn, "error:unsupported-request-method");
    }
    debug(33, 5) ("clientParseRequestMethod: Method is '%s'\n", mstr);
    return NULL;
}

char *
skipLeadingSpace(char *aString)
{
    char *result = aString;
    while (xisspace(*aString))
	++aString;
    return result;
}

char *
findTrailingHTTPVersion(char *uriAndHTTPVersion)
{
    char *token = uriAndHTTPVersion + strlen(uriAndHTTPVersion);
    assert(*token == '\0');
    while (token > uriAndHTTPVersion) {
	--token;
	if (xisspace(*token) && !strncmp(token + 1, "HTTP/", 5))
	    return token + 1;
    }
    return uriAndHTTPVersion;
}

void
trimTrailingSpaces(char *aString, size_t len)
{
    char *endPointer = aString + len;
    while (endPointer > aString && xisspace(*endPointer))
	*(endPointer--) = '\0';
}

ClientSocketContext *
parseURIandHTTPVersion(char **url_p, http_version_t * http_ver_p,
    ConnStateData * conn)
{
    char *url;
    char *token;
    /* look for URL+HTTP/x.x */
    if ((url = strtok(NULL, "\n")) == NULL) {
	debug(33, 1) ("parseHttpRequest: Missing URL\n");
	return parseHttpRequestAbort(conn, "error:missing-url");
    }
    url = skipLeadingSpace(url);
    token = findTrailingHTTPVersion(url);
    trimTrailingSpaces(url, token - url - 1);

    debug(33, 5) ("parseHttpRequest: URI is '%s'\n", url);
    *url_p = url;
    if (token == NULL) {
	debug(33, 3) ("parseHttpRequest: Missing HTTP identifier\n");
#if RELAXED_HTTP_PARSER
	httpBuildVersion(http_ver_p, 0, 9);	/* wild guess */
#else
	return parseHttpRequestAbort(conn, "error:missing-http-ident");
#endif
    } else {
	if (sscanf(token + 5, "%d.%d", &http_ver_p->major,
		&http_ver_p->minor) != 2) {
	    debug(33, 3) ("parseHttpRequest: Invalid HTTP identifier.\n");
	    return parseHttpRequestAbort(conn, "error: invalid HTTP-ident");
	}
	debug(33, 6) ("parseHttpRequest: Client HTTP version %d.%d.\n",
	    http_ver_p->major, http_ver_p->minor);
    }
    return NULL;
}

/* Utility function to perform part of request parsing */
static ClientSocketContext *
clientParseHttpRequestLine(char *inbuf, size_t req_sz, ConnStateData * conn,
    method_t * method_p, char **url_p, http_version_t * http_ver_p)
{
    ClientSocketContext *result = NULL;
    if ((result = clientCheckRequestLineIsParseable(inbuf, req_sz, conn))
	|| (result = clientParseRequestMethod(inbuf, method_p, conn))
	|| (result = parseURIandHTTPVersion(url_p, http_ver_p, conn)))
	return result;

    return NULL;
}

void
setLogUri(clientHttpRequest * http, char const *uri)
{
    safe_free(http->log_uri);
    if (!stringHasCntl(uri))
	http->log_uri = xstrndup(uri, MAX_URL);
    else
	http->log_uri = xstrndup(rfc1738_escape_unescaped(uri), MAX_URL);
}

void
prepareInternalUrl(clientHttpRequest * http, char *url)
{
    http->uri = xstrdup(internalLocalUri(NULL, url));
    http->flags.internal = 1;
    http->flags.accel = 1;
}

void
prepareForwardProxyUrl(clientHttpRequest * http, char *url)
{
    size_t url_sz;
    /* URL may be rewritten later, so make extra room */
    url_sz = strlen(url) + Config.appendDomainLen + 5;
    http->uri = (char *)xcalloc(url_sz, 1);
    strcpy(http->uri, url);
    http->flags.accel = 0;
}

void
prepareAcceleratedUrl(clientHttpRequest * http, char *url, char *req_hdr)
{
    size_t url_sz;
    char *t;
    /* prepend the accel prefix */
    if (opt_accel_uses_host && (t = mime_get_header(req_hdr, "Host"))) {
	int vport;
	char *q;
	const char *protocol_name = "http";
	if (vport_mode)
	    vport = (int) ntohs(http->conn->me.sin_port);
	else
	    vport = (int) Config.Accel.port;
	/* If a Host: header was specified, use it to build the URL 
	 * instead of the one in the Config file. */
	/*
	 * XXX Use of the Host: header here opens a potential
	 * security hole.  There are no checks that the Host: value
	 * corresponds to one of your servers.  It might, for example,
	 * refer to www.playboy.com.  The 'dst' and/or 'dst_domain' ACL 
	 * types should be used to prevent httpd-accelerators 
	 * handling requests for non-local servers */
	strtok(t, " /;@");
	if ((q = strchr(t, ':'))) {
	    *q++ = '\0';
	    if (vport_mode)
		vport = atoi(q);
	}
	url_sz = strlen(url) + 32 + Config.appendDomainLen + strlen(t);
	http->uri = (char *)xcalloc(url_sz, 1);

#if SSL_FORWARDING_NOT_YET_DONE
	if (Config.Sockaddr.https->s.sin_port == http->conn->me.sin_port) {
	    protocol_name = "https";
	    vport = ntohs(http->conn->me.sin_port);
	}
#endif
	snprintf(http->uri, url_sz, "%s://%s:%d%s",
	    protocol_name, t, vport, url);
    } else if (vhost_mode) {
	int vport;
	/* Put the local socket IP address as the hostname */
	url_sz = strlen(url) + 32 + Config.appendDomainLen;
	http->uri = (char *)xcalloc(url_sz, 1);
	if (vport_mode)
	    vport = (int) ntohs(http->conn->me.sin_port);
	else
	    vport = (int) Config.Accel.port;
	rewriteURIwithInterceptedDetails(url, http->uri, url_sz, http->conn->fd,
	    http->conn->me, http->conn->peer, vport);
	debug(33, 5) ("VHOST REWRITE: '%s'\n", http->uri);
    } else {
	url_sz = strlen(Config2.Accel.prefix) + strlen(url) +
	    Config.appendDomainLen + 1;
	http->uri = (char *)xcalloc(url_sz, 1);
	snprintf(http->uri, url_sz, "%s%s", Config2.Accel.prefix, url);
    }
    http->flags.accel = 1;
}

/*
 *  parseHttpRequest()
 * 
 *  Returns
 *  NULL on incomplete requests
 *  a ClientSocketContext structure on success or failure.
 *  Sets result->flags.parsed_ok to 0 if failed to parse the request.
 *  Sets result->flags.parsed_ok to 1 if we have a good request.
 */
static ClientSocketContext *
parseHttpRequest(ConnStateData * conn, method_t * method_p,
    char **prefix_p, size_t * req_line_sz_p)
{
    char *inbuf = NULL;
    char *url = NULL;
    char *req_hdr = NULL;
    http_version_t http_ver;
    char *end;
    size_t header_sz;		/* size of headers, not including first line */
    size_t prefix_sz;		/* size of whole request (req-line + headers) */
    size_t req_sz;
    clientHttpRequest *http;
    ClientSocketContext *result;
    StoreIOBuffer tempBuffer;

    /* pre-set these values to make aborting simpler */
    *prefix_p = NULL;
    *method_p = METHOD_NONE;

    if ((req_sz = headersEnd(conn->in.buf, conn->in.notYetUsed)) == 0) {
	debug(33, 5) ("Incomplete request, waiting for end of headers\n");
	return NULL;
    }
    assert(req_sz <= conn->in.notYetUsed);
    /* Use memcpy, not strdup! */
    inbuf = (char *)xmalloc(req_sz + 1);
    xmemcpy(inbuf, conn->in.buf, req_sz);
    *(inbuf + req_sz) = '\0';

    /* Is there a legitimate first line to the headers ? */
    if ((result =
	    clientParseHttpRequestLine(inbuf, req_sz, conn, method_p, &url,
		&http_ver))) {
	/* something wrong, abort */
	xfree(inbuf);
	return result;
    }
    /*
     * Process headers after request line
     * TODO: Use httpRequestParse here.
     */
    req_hdr = strtok(NULL, null_string);
    header_sz = req_sz - (req_hdr - inbuf);
    if (0 == header_sz) {
	debug(33, 3) ("parseHttpRequest: header_sz == 0\n");
	xfree(inbuf);
	return NULL;
    }
    assert(header_sz > 0);
    debug(33, 3) ("parseHttpRequest: req_hdr = {%s}\n", req_hdr);
    end = req_hdr + header_sz;
    debug(33, 3) ("parseHttpRequest: end = {%s}\n", end);

    prefix_sz = end - inbuf;
    *req_line_sz_p = req_hdr - inbuf;
    debug(33, 3) ("parseHttpRequest: prefix_sz = %d, req_line_sz = %d\n",
	(int) prefix_sz, (int) *req_line_sz_p);
    assert(prefix_sz <= conn->in.notYetUsed);

    /* Ok, all headers are received */
    http = new ClientHttpRequest;
    http->http_ver = http_ver;
    http->conn = conn;
    http->req_sz = prefix_sz;
    result = ClientSocketContextNew(http);
    tempBuffer.data = result->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
	clientReplyStatus, clientReplyNewContext(http), clientSocketRecipient,
	clientSocketDetach, result, tempBuffer);
    *prefix_p = (char *)xmalloc(prefix_sz + 1);
    xmemcpy(*prefix_p, conn->in.buf, prefix_sz);
    *(*prefix_p + prefix_sz) = '\0';
    dlinkAdd(http, &http->active, &ClientActiveRequests);

    /* XXX this function is still way to long. here is a natural point for further simplification */

    debug(33, 5) ("parseHttpRequest: Request Header is\n%s\n",
	(*prefix_p) + *req_line_sz_p);
#if THIS_VIOLATES_HTTP_SPECS_ON_URL_TRANSFORMATION
    if ((t = strchr(url, '#')))	/* remove HTML anchors */
	*t = '\0';
#endif

    if (internalCheck(url))
	prepareInternalUrl(http, url);
    else if (Config2.Accel.on && *url == '/')
	prepareAcceleratedUrl(http, url, req_hdr);
    else
	prepareForwardProxyUrl(http, url);
    setLogUri(http, http->uri);
    debug(33, 5) ("parseHttpRequest: Complete request received\n");
    xfree(inbuf);
    result->flags.parsed_ok = 1;
    return result;
}

static int
clientReadDefer(int fdnotused, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    if (conn->body.size_left)
	return conn->in.notYetUsed >= conn->in.allocatedSize - 1;
    else
	return conn->defer.until > squid_curtime;
}

int
connGetAvailableBufferLength(ConnStateData const *conn)
{
    return conn->in.allocatedSize - conn->in.notYetUsed;
}

void
connMakeSpaceAvailable(ConnStateData * conn)
{
    if (connGetAvailableBufferLength(conn) < 2) {
	conn->in.buf = (char *)memReallocBuf(conn->in.buf, conn->in.allocatedSize * 2, &conn->in.allocatedSize);
	debug(33, 2) ("growing request buffer: notYetUsed=%ld size=%ld\n",
	    (long) conn->in.notYetUsed, (long) conn->in.allocatedSize);
    }
}

void
connAddContextToQueue(ConnStateData * conn, ClientSocketContext * context)
{
    ClientSocketContext **S;
    for (S = (ClientSocketContext **) & conn->currentobject; *S;
	S = &(*S)->next);
    *S = context;
    ++conn->nrequests;
}

int
connGetConcurrentRequestCount(ConnStateData * conn)
{
    int result = 0;
    ClientSocketContext **T;
    for (T = (ClientSocketContext **) & conn->currentobject;
	*T; T = &(*T)->next, ++result);
    return result;
}

int
connReadWasError(ConnStateData * conn, comm_err_t flag, int size)
{
    if (flag != COMM_OK) {
	debug(50, 2) ("connReadWasError: FD %d: got flag %d\n", conn->fd, flag);
	return 1;
    }
    if (size < 0) {
	if (!ignoreErrno(errno)) {
	    debug(50, 2) ("connReadWasError: FD %d: %s\n", conn->fd, xstrerror());
	    return 1;
	} else if (conn->in.notYetUsed == 0) {
	    debug(50, 2) ("connReadWasError: FD %d: no data to process (%s)\n",
		conn->fd, xstrerror());
	}
    }
    return 0;
}

int
connFinishedWithConn(ConnStateData * conn, int size)
{
    if (size == 0) {
	if (connGetConcurrentRequestCount(conn) == 0 && conn->in.notYetUsed == 0) {
	    /* no current or pending requests */
	    debug(33, 4) ("connFinishedWithConn: FD %d closed\n", conn->fd);
	    return 1;
	} else if (!Config.onoff.half_closed_clients) {
	    /* admin doesn't want to support half-closed client sockets */
	    debug(33, 3) ("connFinishedWithConn: FD %d aborted (half_closed_clients disabled)\n", conn->fd);
	    return 1;
	}
    }
    return 0;
}

void
connNoteUseOfBuffer(ConnStateData * conn, size_t byteCount)
{
    assert(byteCount > 0 && byteCount <= conn->in.notYetUsed);
    conn->in.notYetUsed -= byteCount;
    debug(33, 5) ("conn->in.notYetUsed = %u\n", (unsigned) conn->in.notYetUsed);
    /*
     * If there is still data that will be used, 
     * move it to the beginning.
     */
    if (conn->in.notYetUsed > 0)
	xmemmove(conn->in.buf, conn->in.buf + byteCount,
	    conn->in.notYetUsed);
}

int
connKeepReadingIncompleteRequest(ConnStateData * conn)
{
    return conn->in.notYetUsed >= Config.maxRequestHeaderSize ? 0 : 1;
}

void
connCancelIncompleteRequests(ConnStateData * conn)
{
    ClientSocketContext *context = parseHttpRequestAbort(conn, "error:request-too-large");
    clientStreamNode *node = context->getClientReplyContext();
    assert(!connKeepReadingIncompleteRequest(conn));
    debug(33, 1) ("Request header is too large (%u bytes)\n",
	(unsigned) conn->in.notYetUsed);
    debug(33, 1) ("Config 'request_header_max_size'= %ld bytes.\n",
	(long int) Config.maxRequestHeaderSize);
    clientSetReplyToError(node->data, ERR_TOO_BIG,
	HTTP_REQUEST_ENTITY_TOO_LARGE, METHOD_NONE, NULL,
	&conn->peer.sin_addr, NULL, NULL, NULL);
    connAddContextToQueue(conn, context);
    context->pullData();
}

static void
clientMaybeReadData(ConnStateData *conn, int do_next_read)
{
    if (do_next_read) {
	conn->flags.readMoreRequests = 1;
	clientReadSomeData(conn);
    }
}

static void
clientAfterReadingRequests(int fd, ConnStateData *conn, int do_next_read)
{
    fde *F = &fd_table[fd];

    /* Check if a half-closed connection was aborted in the middle */
    if (F->flags.socket_eof) {
       if (conn->in.notYetUsed != conn->body.size_left) {
	   /* != 0 when no request body */
           /* Partial request received. Abort client connection! */
           debug(33, 3) ("clientReadRequest: FD %d aborted, partial request\n",+                         fd);
           comm_close(fd);
           return;
       }
    }

    clientMaybeReadData (conn, do_next_read);
}


static void
clientProcessRequest(ConnStateData *conn, ClientSocketContext *context, method_t method, char *prefix, size_t req_line_sz)
{
    clientHttpRequest *http = context->http;
    request_t *request = NULL;
    /* We have an initial client stream in place should it be needed */
    /* setup our private context */
    connNoteUseOfBuffer(conn, http->req_sz);

    connAddContextToQueue(conn, context);

    if (context->flags.parsed_ok == 0) {
       clientStreamNode *node = context->getClientReplyContext();
       debug(33, 1) ("clientReadRequest: Invalid Request\n");
       clientSetReplyToError(node->data,
                             ERR_INVALID_REQ, HTTP_BAD_REQUEST, method, NULL,
                             &conn->peer.sin_addr, NULL, conn->in.buf, NULL);
       assert(context->http->out.offset == 0);
       context->pullData();
       conn->flags.readMoreRequests = 0;
       return;
    }

    if ((request = urlParse(method, http->uri)) == NULL) {
       clientStreamNode *node = context->getClientReplyContext();
       debug(33, 5) ("Invalid URL: %s\n", http->uri);
       clientSetReplyToError(node->data,
                             ERR_INVALID_URL, HTTP_BAD_REQUEST, method, http->uri,
                             &conn->peer.sin_addr, NULL, NULL, NULL);
       assert(context->http->out.offset == 0);
       context->pullData();
       conn->flags.readMoreRequests = 0;
       return;
    } 

    /* compile headers */
    /* we should skip request line! */
    if (!httpRequestParseHeader(request, prefix + req_line_sz))
        debug(33, 1) ("Failed to parse request headers: %s\n%s\n",
                      http->uri, prefix);
    /* continue anyway? */

    request->flags.accelerated = http->flags.accel;
    if (!http->flags.internal) {
       if (internalCheck(request->urlpath.buf())) {
           if (internalHostnameIs(request->host) &&
               request->port == getMyPort()) {
               http->flags.internal = 1;
           } else if (internalStaticCheck(request->urlpath.buf())) {
               xstrncpy(request->host, internalHostname(),
                        SQUIDHOSTNAMELEN);
               request->port = getMyPort();
               http->flags.internal = 1;
           }
       }
    }

    request->flags.internal = http->flags.internal;
    setLogUri (http, urlCanonicalClean(request));
    request->client_addr = conn->peer.sin_addr;
    request->my_addr = conn->me.sin_addr;
    request->my_port = ntohs(conn->me.sin_port);
    request->http_ver = http->http_ver;
    if (!urlCheckRequest(request) ||
       httpHeaderHas(&request->header, HDR_TRANSFER_ENCODING)) {
       clientStreamNode *node = context->getClientReplyContext();
       clientSetReplyToError(node->data, ERR_UNSUP_REQ,
                             HTTP_NOT_IMPLEMENTED, request->method, NULL,
                             &conn->peer.sin_addr, request, NULL, NULL);
       assert(context->http->out.offset == 0);
       context->pullData();
       conn->flags.readMoreRequests = 0;
       return;
    }


    if (!clientIsContentLengthValid(request)) {
       clientStreamNode *node = context->getClientReplyContext();
       clientSetReplyToError(node->data, ERR_INVALID_REQ,
                             HTTP_LENGTH_REQUIRED, request->method, NULL,
                             &conn->peer.sin_addr, request, NULL, NULL);
       assert(context->http->out.offset == 0);
       context->pullData();
       conn->flags.readMoreRequests = 0;
       return;
    }

    http->request = requestLink(request);
    clientSetKeepaliveFlag(http);
    /* Do we expect a request-body? */
    if (request->content_length > 0) {
       conn->body.size_left = request->content_length;
       request->body_connection = conn;
       /* Is it too large? */
       if (!clientIsRequestBodyValid(request->content_length) ||
           clientIsRequestBodyTooLargeForPolicy(request->content_length)) {
           clientStreamNode *node = context->getClientReplyContext();
           clientSetReplyToError(node->data, ERR_TOO_BIG,
                                 HTTP_REQUEST_ENTITY_TOO_LARGE, METHOD_NONE, NULL,
                                 &conn->peer.sin_addr, http->request, NULL, NULL);
           assert(context->http->out.offset == 0);
           context->pullData();
           conn->flags.readMoreRequests = 0;
           return;
       }
       context->mayUseConnection(true);
    }

    /* If this is a CONNECT, don't schedule a read - ssl.c will handle it */
    if (http->request->method == METHOD_CONNECT)
       context->mayUseConnection(true);
    clientAccessCheck(http);
}

static void
connStripBufferWhitespace (ConnStateData *conn)
{
    while (conn->in.notYetUsed > 0 && xisspace(conn->in.buf[0])) {
       xmemmove(conn->in.buf, conn->in.buf + 1, conn->in.notYetUsed - 1);
       --conn->in.notYetUsed;
    }
}

static int
connOkToAddRequest(ConnStateData *conn)
{
    int result = connGetConcurrentRequestCount(conn) < (Config.onoff.pipeline_prefetch ? 2 : 1);
    if (!result) {
       debug(33, 3) ("clientReadRequest: FD %d max concurrent requests reached\n",
           conn->fd);
       debug(33, 5) ("clientReadRequest: FD %d defering new request until one is done\n",
           conn->fd);
    }
    return result;
}

static void
connSetDefer (ConnStateData *conn, size_t milliSeconds)
{
    conn->defer.until = squid_curtime + milliSeconds;
    conn->defer.n++;
}

static void
clientReadRequest(int fd, char *buf, size_t size, comm_err_t flag, int xerrno,
void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    assert (conn->reading);
    conn->reading = false;
    method_t method;
    char *prefix = NULL;
    ClientSocketContext *context;
    int do_next_read = 1; /* the default _is_ to read data! - adrian */

    assert (fd == conn->fd);

    /* Bail out quickly on COMM_ERR_CLOSING - close handlers will tidy up */
    if (flag == COMM_ERR_CLOSING) {
        return;
    }
    /*
     * Don't reset the timeout value here.  The timeout value will be
     * set to Config.Timeout.request by httpAccept() and
     * clientWriteComplete(), and should apply to the request as a
     * whole, not individual read() calls.  Plus, it breaks our
     * lame half-close detection
     */
    if (connReadWasError(conn, flag, size)) {
	comm_close(fd);
	return;
    }

    if (flag == COMM_OK) {
       if (size > 0) {
           kb_incr(&statCounter.client_http.kbytes_in, size);
           conn->in.notYetUsed += size;
           conn->in.buf[conn->in.notYetUsed] = '\0';   /* Terminate the string
*/
       } else if (size == 0) {
           debug(33, 5) ("clientReadRequest: FD %d closed?\n", fd);
           if (connFinishedWithConn(conn, size)) {
               comm_close(fd);
               return;
           }
           /* It might be half-closed, we can't tell */
           fd_table[fd].flags.socket_eof = 1;
           connSetDefer (conn, 1);
           fd_note(fd, "half-closed");
           /* There is one more close check at the end, to detect aborted
            * (partial) requests. At this point we can't tell if the request
            * is partial.
            */
           /* Continue to process previously read data */
       }
    }


    /* Process request body if any */
    if (conn->in.notYetUsed > 0 && conn->body.callback != NULL)
	clientProcessBody(conn);
    /* Process next request */
    if (connGetConcurrentRequestCount(conn) == 0)
	fd_note(conn->fd, "Reading next request");

    while (conn->in.notYetUsed > 0 && conn->body.size_left == 0) {
	size_t req_line_sz;
       connStripBufferWhitespace (conn);
       if (conn->in.notYetUsed == 0) {
           clientAfterReadingRequests(fd, conn, do_next_read);
           return;
	}
	/* Limit the number of concurrent requests to 2 */
       if (!connOkToAddRequest(conn)) {
           /* Reset when a request is complete */
           connSetDefer (conn, 100);
           clientMaybeReadData (conn, do_next_read);
	    return;
	}
       /* Should not be needed anymore */
       /* Terminate the string */
       conn->in.buf[conn->in.notYetUsed] = '\0';
	/* Process request */
	context = parseHttpRequest(conn,
	    &method, &prefix, &req_line_sz);
	/* partial or incomplete request */
	if (!context) {
	    safe_free(prefix);
	    if (!connKeepReadingIncompleteRequest(conn))
               connCancelIncompleteRequests(conn);
           break; /* conn->in.notYetUsed > 0 && conn->body.size_left == 0 */
       }

       /* status -1 or 1 */
	if (context) {
	    commSetTimeout(fd, Config.Timeout.lifetime, clientLifetimeTimeout,
		context->http);

	    clientProcessRequest(conn, context, method, prefix, req_line_sz);

	    safe_free(prefix);
           if (!conn->flags.readMoreRequests) {
               conn->flags.readMoreRequests = 1;
		break;
	    }
	    if (context->mayUseConnection()) {
		debug (33, 3) ("clientReadRequest: Not reading, as this request may need the connection\n");
		do_next_read = 0;
	    }
	    continue;		/* while offset > 0 && body.size_left == 0 */
	}
    }				/* while offset > 0 && conn->body.size_left == 0 */
    clientAfterReadingRequests(fd, conn, do_next_read);
}

/* file_read like function, for reading body content */
void
clientReadBody(request_t * request, char *buf, size_t size, CBCB * callback,
    void *cbdata)
{
    ConnStateData *conn = request->body_connection;
    if (!conn) {
	debug(33, 5) ("clientReadBody: no body to read, request=%p\n", request);
	callback(buf, 0, cbdata);	/* Signal end of body */
	return;
    }
    debug(33, 2) ("clientReadBody: start fd=%d body_size=%lu in.notYetUsed=%ld cb=%p req=%p\n",
	conn->fd, (unsigned long int) conn->body.size_left,
	(unsigned long int) conn->in.notYetUsed, callback, request);
    conn->body.callback = callback;
    conn->body.cbdata = cbdata;
    conn->body.buf = buf;
    conn->body.bufsize = size;
    conn->body.request = requestLink(request);
    clientProcessBody(conn);
}

/* Called by clientReadRequest to process body content */
static void
clientProcessBody(ConnStateData * conn)
{
    size_t size;
    char *buf = conn->body.buf;
    void *cbdata = conn->body.cbdata;
    CBCB *callback = conn->body.callback;
    request_t *request = conn->body.request;
    /* Note: request is null while eating "aborted" transfers */
    debug(33, 2) ("clientProcessBody: start fd=%d body_size=%lu in.notYetUsed=%lu cb=%p req=%p\n",
	conn->fd, (unsigned long int) conn->body.size_left,
	(unsigned long int) conn->in.notYetUsed, callback, request);
    if (conn->in.notYetUsed) {
	/* Some sanity checks... */
	assert(conn->body.size_left > 0);
	assert(conn->in.notYetUsed > 0);
	assert(callback != NULL);
	assert(buf != NULL);
	/* How much do we have to process? */
	size = conn->in.notYetUsed;
	if (size > conn->body.size_left)	/* only process the body part */
	    size = conn->body.size_left;
	if (size > conn->body.bufsize)	/* don't copy more than requested */
	    size = conn->body.bufsize;
	xmemcpy(buf, conn->in.buf, size);
	conn->body.size_left -= size;
	/* Move any remaining data */
	conn->in.notYetUsed -= size;
	if (conn->in.notYetUsed > 0)
	    xmemmove(conn->in.buf, conn->in.buf + size, conn->in.notYetUsed);
	/* Remove request link if this is the last part of the body, as
	 * clientReadRequest automatically continues to process next request */
	if (conn->body.size_left <= 0 && request != NULL)
	    request->body_connection = NULL;
	/* Remove clientReadBody arguments (the call is completed) */
	conn->body.request = NULL;
	conn->body.callback = NULL;
	conn->body.buf = NULL;
	conn->body.bufsize = 0;
	/* Remember that we have touched the body, not restartable */
	if (request != NULL)
	    request->flags.body_sent = 1;
	/* Invoke callback function */
	callback(buf, size, cbdata);
	if (request != NULL)
	    requestUnlink(request);	/* Linked in clientReadBody */
	debug(33, 2) ("clientProcessBody: end fd=%d size=%lu body_size=%lu in.notYetUsed=%lu cb=%p req=%p\n",
	    conn->fd, (unsigned long int)size, (unsigned long int) conn->body.size_left,
	    (unsigned long) conn->in.notYetUsed, callback, request);
    }
}

/* A dummy handler that throws away a request-body */
static void
clientReadBodyAbortHandler(char *buf, ssize_t size, void *data)
{
    static char bodyAbortBuf[SQUID_TCP_SO_RCVBUF];
    ConnStateData *conn = (ConnStateData *) data;
    debug(33, 2) ("clientReadBodyAbortHandler: fd=%d body_size=%lu in.notYetUsed=%lu\n",
	conn->fd, (unsigned long int) conn->body.size_left,
	(unsigned long) conn->in.notYetUsed);
    if (size != 0 && conn->body.size_left != 0) {
	debug(33, 3) ("clientReadBodyAbortHandler: fd=%d shedule next read\n",
	    conn->fd);
	conn->body.callback = clientReadBodyAbortHandler;
	conn->body.buf = bodyAbortBuf;
	conn->body.bufsize = sizeof(bodyAbortBuf);
	conn->body.cbdata = data;
    }
}

/* Abort a body request */
int
clientAbortBody(request_t * request)
{
    ConnStateData *conn = request->body_connection;
    char *buf;
    CBCB *callback;
    void *cbdata;
    request->body_connection = NULL;
    if (!conn || conn->body.size_left <= 0)
	return 0;		/* No body to abort */
    if (conn->body.callback != NULL) {
	buf = conn->body.buf;
	callback = conn->body.callback;
	cbdata = conn->body.cbdata;
	assert(request == conn->body.request);
	conn->body.buf = NULL;
	conn->body.callback = NULL;
	conn->body.cbdata = NULL;
	conn->body.request = NULL;
	callback(buf, -1, cbdata);	/* Signal abort to clientReadBody caller */
	requestUnlink(request);
    }
    clientReadBodyAbortHandler(NULL, -1, conn);		/* Install abort handler */
    /* clientProcessBody() */
    return 1;			/* Aborted */
}

/* general lifetime handler for HTTP requests */
static void
requestTimeout(int fd, void *data)
{
#if THIS_CONFUSES_PERSISTENT_CONNECTION_AWARE_BROWSERS_AND_USERS
    ConnStateData *conn = data;
    debug(33, 3) ("requestTimeout: FD %d: lifetime is expired.\n", fd);
    if (fd_table[fd].rwstate) {
	/*
	 * Some data has been sent to the client, just close the FD
	 */
	comm_close(fd);
    } else if (conn->nrequests) {
	/*
	 * assume its a persistent connection; just close it
	 */
	comm_close(fd);
    } else {
	/*
	 * Generate an error
	 */
	clientHttpRequest **H;
	clientStreamNode *node;
	clientHttpRequest *http =
	parseHttpRequestAbort(conn, "error:Connection%20lifetime%20expired");
	node = http->client_stream.tail->prev->data;
	clientSetReplyToError(node->data, ERR_LIFETIME_EXP,
	    HTTP_REQUEST_TIMEOUT, METHOD_NONE, "N/A", &conn->peer.sin_addr,
	    NULL, NULL, NULL);
	/* No requests can be outstanded */
	assert(conn->chr == NULL);
	/* add to the client request queue */
	for (H = &conn->chr; *H; H = &(*H)->next);
	*H = http;
	clientStreamRead(http->client_stream.tail->data, http, 0,
	    HTTP_REQBUF_SZ, context->reqbuf);
	/*
	 * if we don't close() here, we still need a timeout handler!
	 */
	commSetTimeout(fd, 30, requestTimeout, conn);
	/*
	 * Aha, but we don't want a read handler!
	 */
	commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
    }
#else
    /*
     * Just close the connection to not confuse browsers
     * using persistent connections. Some browsers opens
     * an connection and then does not use it until much
     * later (presumeably because the request triggering
     * the open has already been completed on another
     * connection)
     */
    debug(33, 3) ("requestTimeout: FD %d: lifetime is expired.\n", fd);
    comm_close(fd);
#endif
}

static void
clientLifetimeTimeout(int fd, void *data)
{
    clientHttpRequest *http = (clientHttpRequest *)data;
    ConnStateData *conn = http->conn;
    debug(33,
	1) ("WARNING: Closing client %s connection due to lifetime timeout\n",
	inet_ntoa(conn->peer.sin_addr));
    debug(33, 1) ("\t%s\n", http->uri);
    comm_close(fd);
}

static int
httpAcceptDefer(int fdunused, void *dataunused)
{
    static time_t last_warn = 0;
    if (fdNFree() >= RESERVED_FD)
	return 0;
    if (last_warn + 15 < squid_curtime) {
	debug(33, 0) ("WARNING! Your cache is running out of filedescriptors\n");
	last_warn = squid_curtime;
    }
    return 1;
}

ConnStateData *
connStateCreate(struct sockaddr_in *peer, struct sockaddr_in *me, int fd)
{
    ConnStateData *result = cbdataAlloc(ConnStateData);
    result->peer = *peer;
    result->log_addr = peer->sin_addr;
    result->log_addr.s_addr &= Config.Addrs.client_netmask.s_addr;
    result->me = *me;
    result->fd = fd;
    result->in.buf = (char *)memAllocBuf(CLIENT_REQ_BUF_SZ, &result->in.allocatedSize);
    result->flags.readMoreRequests = 1;
    return result;
}

/* Handle a new connection on HTTP socket. */
void
httpAccept(int sock, int newfd, struct sockaddr_in *me, struct sockaddr_in *peer,
  comm_err_t flag, int xerrno, void *data)
{
    int *N = &incoming_sockets_accepted;
    ConnStateData *connState = NULL;
#if USE_IDENT
    static aclCheck_t identChecklist;
#endif

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    /* kick off another one for later */
    comm_accept(sock, httpAccept, NULL);

    /* XXX we're not considering httpAcceptDefer yet! */

	if (flag != COMM_OK) {
	    errno = xerrno;
	    debug(50, 1) ("httpAccept: FD %d: accept failure: %s\n",
		    sock, xstrerror());
	    return;
	}
	
	debug(33, 4) ("httpAccept: FD %d: accepted\n", newfd);
	connState = connStateCreate(peer, me, newfd);
	comm_add_close_handler(newfd, connStateFree, connState);
	if (Config.onoff.log_fqdn)
	    fqdncache_gethostbyaddr(peer->sin_addr, FQDN_LOOKUP_IF_MISS);
	commSetTimeout(newfd, Config.Timeout.request, requestTimeout, connState);
#if USE_IDENT
	identChecklist.src_addr = peer->sin_addr;
	identChecklist.my_addr = me->sin_addr;
	identChecklist.my_port = ntohs(me->sin_port);
	if (aclCheckFast(Config.accessList.identLookup, &identChecklist))
	    identStart(me, peer, clientIdentDone, connState);
#endif
	clientReadSomeData(connState);
	commSetDefer(newfd, clientReadDefer, connState);
	clientdbEstablished(peer->sin_addr, 1);
	assert(N);
	(*N)++;
}

#if USE_SSL

/* negotiate an SSL connection */
static void
clientNegotiateSSL(int fd, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    X509 *client_cert;
    SSL *ssl = fd_table[fd].ssl;
    int ret;

    if ((ret = SSL_accept(ssl)) <= 0) {
	int ssl_error = SSL_get_error(ssl, ret);
	switch (ssl_error) {
	case SSL_ERROR_WANT_READ:
	    commSetSelect(fd, COMM_SELECT_READ, clientNegotiateSSL, conn, 0);
	    return;
	case SSL_ERROR_WANT_WRITE:
	    commSetSelect(fd, COMM_SELECT_WRITE, clientNegotiateSSL, conn, 0);
	    return;
	default:
	    debug(81, 1) ("clientNegotiateSSL: Error negotiating SSL connection on FD %d: %s (%d/%d)\n",
		    fd, ERR_error_string(ERR_get_error(), NULL), ssl_error, ret);
	    comm_close(fd);
	    return;
	}
	/* NOTREACHED */
    }
    debug(83, 5) ("clientNegotiateSSL: FD %d negotiated cipher %s\n", fd,
	SSL_get_cipher(fd_table[fd].ssl));

    client_cert = SSL_get_peer_certificate(fd_table[fd].ssl);
    if (client_cert != NULL) {
	debug(83, 5) ("clientNegotiateSSL: FD %d client certificate: subject: %s\n",
	    fd, X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0));

	debug(83, 5) ("clientNegotiateSSL: FD %d client certificate: issuer: %s\n",
	    fd, X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0));

	X509_free(client_cert);
    } else {
	debug(83, 5) ("clientNegotiateSSL: FD %d has no certificate.\n", fd);
    }

    clientReadSomeData(conn);
}

struct _https_port_data {
    SSL_CTX *sslContext;
};
typedef struct _https_port_data https_port_data;
CBDATA_TYPE(https_port_data);

/* handle a new HTTPS connection */
static void
httpsAccept(int sock, int newfd, struct sockaddr_in *me, struct sockaddr_in *peer,
  comm_err_t flag, int xerrno, void *data)
{
    int *N = &incoming_sockets_accepted;
    https_port_data *https_port = (https_port_data *)data;
    SSL_CTX *sslContext = https_port->sslContext;
    ConnStateData *connState = NULL;
    SSL *ssl;
    int ssl_error;
#if USE_IDENT
    static aclCheck_t identChecklist;
#endif

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    if (flag != COMM_OK) {
	errno = xerrno;
	debug(50, 1) ("httpsAccept: FD %d: accept failure: %s\n",
	    sock, xstrerror());
	return;
    }
    
    if ((ssl = SSL_new(sslContext)) == NULL) {
	ssl_error = ERR_get_error();
	debug(83, 1) ("httpsAccept: Error allocating handle: %s\n",
	    ERR_error_string(ssl_error, NULL));
	return;
    }

    SSL_set_fd(ssl, newfd);
    fd_table[newfd].ssl = ssl;
    fd_table[newfd].read_method = &ssl_read_method;
    fd_table[newfd].write_method = &ssl_write_method;
    debug(50, 5) ("httpsAccept: FD %d accepted, starting SSL negotiation.\n", newfd);
    
    connState = connStateCreate(peer, me, newfd);
    /* XXX account connState->in.buf */
    comm_add_close_handler(newfd, connStateFree, connState);
    if (Config.onoff.log_fqdn)
	fqdncache_gethostbyaddr(peer->sin_addr, FQDN_LOOKUP_IF_MISS);
    commSetTimeout(newfd, Config.Timeout.request, requestTimeout, connState);
#if USE_IDENT
    identChecklist.src_addr = peer->sin_addr;
    identChecklist.my_addr = me->sin_addr;
    identChecklist.my_port = ntohs(me->sin_port);
    if (aclCheckFast(Config.accessList.identLookup, &identChecklist))
	identStart(me, peer, clientIdentDone, connState);
#endif
    commSetSelect(newfd, COMM_SELECT_READ, clientNegotiateSSL, connState, 0);
    commSetDefer(newfd, clientReadDefer, connState);
    clientdbEstablished(peer->sin_addr, 1);
    (*N)++;
}

#endif /* USE_SSL */


static void
clientHttpConnectionsOpen(void)
{
    sockaddr_in_list *s;
    int fd;
    for (s = Config.Sockaddr.http; s; s = s->next) {
	if (MAXHTTPPORTS == NHttpSockets) {
	    debug(1, 1) ("WARNING: You have too many 'http_port' lines.\n");
	    debug(1, 1) ("         The limit is %d\n", MAXHTTPPORTS);
	    continue;
	}
	enter_suid();
	fd = comm_open(SOCK_STREAM,
	    0,
	    s->s.sin_addr,
	    ntohs(s->s.sin_port), COMM_NONBLOCKING, "HTTP Socket");
	leave_suid();
	if (fd < 0)
	    continue;
	comm_listen(fd);
	comm_accept(fd, httpAccept, NULL);
	/*
	 * We need to set a defer handler here so that we don't
	 * peg the CPU with select() when we hit the FD limit.
	 */
	commSetDefer(fd, httpAcceptDefer, NULL);
	debug(1, 1) ("Accepting HTTP connections at %s, port %d, FD %d.\n",
	    inet_ntoa(s->s.sin_addr), (int) ntohs(s->s.sin_port), fd);
	HttpSockets[NHttpSockets++] = fd;
    }
}

#if USE_SSL
static void
clientHttpsConnectionsOpen(void)
{
    https_port_list *s;
    https_port_data *https_port;
    int fd;
    for (s = Config.Sockaddr.https; s; s = s->next) {
	if (MAXHTTPPORTS == NHttpSockets) {
	    debug(1, 1) ("WARNING: You have too many 'https_port' lines.\n");
	    debug(1, 1) ("         The limit is %d\n", MAXHTTPPORTS);
	    continue;
	}
	enter_suid();
	fd = comm_open(SOCK_STREAM,
	    0,
	    s->s.sin_addr,
	    ntohs(s->s.sin_port), COMM_NONBLOCKING, "HTTPS Socket");
	leave_suid();
	if (fd < 0)
	    continue;
	CBDATA_INIT_TYPE(https_port_data);
	https_port = cbdataAlloc(https_port_data);
	https_port->sslContext = s->sslContext;
	comm_listen(fd);
	comm_accept(fd, httpsAccept, https_port);
	commSetDefer(fd, httpAcceptDefer, NULL);
	debug(1, 1) ("Accepting HTTPS connections at %s, port %d, FD %d.\n",
	    inet_ntoa(s->s.sin_addr), (int) ntohs(s->s.sin_port), fd);
	HttpSockets[NHttpSockets++] = fd;
    }
}

#endif

void
clientOpenListenSockets(void)
{
    clientHttpConnectionsOpen();
#if USE_SSL
    clientHttpsConnectionsOpen();
#endif
    if (NHttpSockets < 1)
	fatal("Cannot open HTTP Port");
}

void
clientHttpConnectionsClose(void)
{
    int i;
    for (i = 0; i < NHttpSockets; i++) {
	if (HttpSockets[i] >= 0) {
	    debug(1, 1) ("FD %d Closing HTTP connection\n", HttpSockets[i]);
	    comm_close(HttpSockets[i]);
	    HttpSockets[i] = -1;
	}
    }
    NHttpSockets = 0;
}

int
varyEvaluateMatch(StoreEntry * entry, request_t * request)
{
    const char *vary = request->vary_headers;
    int has_vary = httpHeaderHas(&entry->getReply()->header, HDR_VARY);
#if X_ACCELERATOR_VARY
    has_vary |=
	httpHeaderHas(&entry->getReply()->header, HDR_X_ACCELERATOR_VARY);
#endif
    if (!has_vary || !entry->mem_obj->vary_headers) {
	if (vary) {
	    /* Oops... something odd is going on here.. */
	    debug(33,
		1)
		("varyEvaluateMatch: Oops. Not a Vary object on second attempt, '%s' '%s'\n",
		entry->mem_obj->url, vary);
	    safe_free(request->vary_headers);
	    return VARY_CANCEL;
	}
	if (!has_vary) {
	    /* This is not a varying object */
	    return VARY_NONE;
	}
	/* virtual "vary" object found. Calculate the vary key and
	 * continue the search
	 */
	vary = httpMakeVaryMark(request, entry->getReply());
	if (vary) {
	    request->vary_headers = xstrdup(vary);
	    return VARY_OTHER;
	} else {
	    /* Ouch.. we cannot handle this kind of variance */
	    /* XXX This cannot really happen, but just to be complete */
	    return VARY_CANCEL;
	}
    } else {
	if (!vary) {
	    vary = httpMakeVaryMark(request, entry->getReply());
	    if (vary)
		request->vary_headers = xstrdup(vary);
	}
	if (!vary) {
	    /* Ouch.. we cannot handle this kind of variance */
	    /* XXX This cannot really happen, but just to be complete */
	    return VARY_CANCEL;
	} else if (strcmp(vary, entry->mem_obj->vary_headers) == 0) {
	    return VARY_MATCH;
	} else {
	    /* Oops.. we have already been here and still haven't
	     * found the requested variant. Bail out
	     */
	    debug(33, 1) ("varyEvaluateMatch: Oops. Not a Vary match on second attempt, '%s' '%s'\n",
		entry->mem_obj->url, vary);
	    return VARY_CANCEL;
	}
    }
}

aclCheck_t *
clientAclChecklistCreate(const acl_access * acl, const clientHttpRequest * http)
{
    aclCheck_t *ch;
    ConnStateData *conn = http->conn;
    ch = aclChecklistCreate(acl, http->request, conn ? conn->rfc931 : dash_str);

    /*
     * hack for ident ACL. It needs to get full addresses, and a place to store
     * the ident result on persistent connections...
     */
    /* connection oriented auth also needs these two lines for it's operation. */
    /*
     * Internal requests do not have a connection reference, because: A) their
     * byte count may be transformed before being applied to an outbound
     * connection B) they are internal - any limiting on them should be done on
     * the server end.
     */
    if (conn)
	ch->conn = cbdataReference(conn);	/* unreferenced in acl.c */

    return ch;
}
