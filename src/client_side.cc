/*
 * $Id$
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

/**
 \defgroup ClientSide Client-Side Logics
 *
 \section cserrors Errors and client side
 *
 \par Problem the first:
 * the store entry is no longer authoritative on the
 * reply status. EBITTEST (E_ABORT) is no longer a valid test outside
 * of client_side_reply.c.
 * Problem the second: resources are wasted if we delay in cleaning up.
 * Problem the third we can't depend on a connection close to clean up.
 *
 \par Nice thing the first:
 * Any step in the stream can callback with data
 * representing an error.
 * Nice thing the second: once you stop requesting reads from upstream,
 * upstream can be stopped too.
 *
 \par Solution #1:
 * Error has a callback mechanism to hand over a membuf
 * with the error content. The failing node pushes that back as the
 * reply. Can this be generalised to reduce duplicate efforts?
 * A: Possibly. For now, only one location uses this.
 * How to deal with pre-stream errors?
 * Tell client_side_reply that we *want* an error page before any
 * stream calls occur. Then we simply read as normal.
 *
 *
 \section pconn_logic Persistent connection logic:
 *
 \par
 * requests (httpClientRequest structs) get added to the connection
 * list, with the current one being chr
 *
 \par
 * The request is *immediately* kicked off, and data flows through
 * to clientSocketRecipient.
 *
 \par
 * If the data that arrives at clientSocketRecipient is not for the current
 * request, clientSocketRecipient simply returns, without requesting more
 * data, or sending it.
 *
 \par
 * ClientKeepAliveNextRequest will then detect the presence of data in
 * the next ClientHttpRequest, and will send it, restablishing the
 * data flow.
 */

#include "squid.h"
#include "client_side.h"
#include "clientStream.h"
#include "ProtoPort.h"
#include "auth/UserRequest.h"
#include "Store.h"
#include "comm.h"
#include "HttpHdrContRange.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ident/Config.h"
#include "ident/Ident.h"
#include "ip/IpIntercept.h"
#include "MemObject.h"
#include "fde.h"
#include "client_side_request.h"
#include "acl/FilledChecklist.h"
#include "ConnectionDetail.h"
#include "client_side_reply.h"
#include "ClientRequestContext.h"
#include "MemBuf.h"
#include "SquidTime.h"
#include "ChunkedCodingParser.h"
#include "rfc1738.h"

#if USE_SSL
#include "ssl/context_storage.h"
#include "ssl/helper.h"
#include "ssl/gadgets.h"
#endif
#if USE_SSL_CRTD
#include "ssl/crtd_message.h"
#include "ssl/certificate_db.h"
#endif

#if HAVE_LIMITS
#include <limits>
#endif

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

/* our socket-related context */


CBDATA_CLASS_INIT(ClientSocketContext);

void *
ClientSocketContext::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ClientSocketContext));
    CBDATA_INIT_TYPE(ClientSocketContext);
    return cbdataAlloc(ClientSocketContext);
}

void
ClientSocketContext::operator delete (void *address)
{
    cbdataFree (address);
}

/* Local functions */
/* ClientSocketContext */
static ClientSocketContext *ClientSocketContextNew(ClientHttpRequest *);
/* other */
static IOCB clientWriteComplete;
static IOCB clientWriteBodyComplete;
static bool clientParseRequest(ConnStateData * conn, bool &do_next_read);
static PF clientLifetimeTimeout;
static ClientSocketContext *parseHttpRequestAbort(ConnStateData * conn,
        const char *uri);
static ClientSocketContext *parseHttpRequest(ConnStateData *, HttpParser *, HttpRequestMethod *, HttpVersion *);
#if USE_IDENT
static IDCB clientIdentDone;
#endif
static CSCB clientSocketRecipient;
static CSD clientSocketDetach;
static void clientSetKeepaliveFlag(ClientHttpRequest *);
static int clientIsContentLengthValid(HttpRequest * r);
static bool okToAccept();
static int clientIsRequestBodyValid(int64_t bodyLength);
static int clientIsRequestBodyTooLargeForPolicy(int64_t bodyLength);

static void clientUpdateStatHistCounters(log_type logType, int svc_time);
static void clientUpdateStatCounters(log_type logType);
static void clientUpdateHierCounters(HierarchyLogEntry *);
static bool clientPingHasFinished(ping_data const *aPing);
void prepareLogWithRequestDetails(HttpRequest *, AccessLogEntry *);
#ifndef PURIFY
static int connIsUsable(ConnStateData * conn);
#endif
static int responseFinishedOrFailed(HttpReply * rep, StoreIOBuffer const &receivedData);
static void ClientSocketContextPushDeferredIfNeeded(ClientSocketContext::Pointer deferredRequest, ConnStateData * conn);
static void clientUpdateSocketStats(log_type logType, size_t size);

char *skipLeadingSpace(char *aString);
static void connNoteUseOfBuffer(ConnStateData* conn, size_t byteCount);
static int connKeepReadingIncompleteRequest(ConnStateData * conn);
static void connCancelIncompleteRequests(ConnStateData * conn);

static ConnStateData *connStateCreate(const IpAddress &peer, const IpAddress &me, int fd, http_port_list *port);


int
ClientSocketContext::fd() const
{
    assert (http);
    assert (http->getConn() != NULL);
    return http->getConn()->fd;
}

clientStreamNode *
ClientSocketContext::getTail() const
{
    if (http->client_stream.tail)
        return (clientStreamNode *)http->client_stream.tail->data;

    return NULL;
}

clientStreamNode *
ClientSocketContext::getClientReplyContext() const
{
    return (clientStreamNode *)http->client_stream.tail->prev->data;
}

/**
 * This routine should be called to grow the inbuf and then
 * call comm_read().
 */
void
ConnStateData::readSomeData()
{
    if (reading())
        return;

    debugs(33, 4, "clientReadSomeData: FD " << fd << ": reading request...");

    if (!maybeMakeSpaceAvailable())
        return;

    typedef CommCbMemFunT<ConnStateData, CommIoCbParams> Dialer;
    reader = JobCallback(33, 5,
                         Dialer, this, ConnStateData::clientReadRequest);
    comm_read(fd, in.addressToReadInto(), getAvailableBufferLength(), reader);
}


void
ClientSocketContext::removeFromConnectionList(ConnStateData * conn)
{
    ClientSocketContext::Pointer *tempContextPointer;
    assert(conn != NULL && cbdataReferenceValid(conn));
    assert(conn->getCurrentContext() != NULL);
    /* Unlink us from the connection request list */
    tempContextPointer = & conn->currentobject;

    while (tempContextPointer->getRaw()) {
        if (*tempContextPointer == this)
            break;

        tempContextPointer = &(*tempContextPointer)->next;
    }

    assert(tempContextPointer->getRaw() != NULL);
    *tempContextPointer = next;
    next = NULL;
}

ClientSocketContext::~ClientSocketContext()
{
    clientStreamNode *node = getTail();

    if (node) {
        ClientSocketContext *streamContext = dynamic_cast<ClientSocketContext *> (node->data.getRaw());

        if (streamContext) {
            /* We are *always* the tail - prevent recursive free */
            assert(this == streamContext);
            node->data = NULL;
        }
    }

    if (connRegistered_)
        deRegisterWithConn();

    httpRequestFree(http);

    /* clean up connection links to us */
    assert(this != next.getRaw());
}

void
ClientSocketContext::registerWithConn()
{
    assert (!connRegistered_);
    assert (http);
    assert (http->getConn() != NULL);
    connRegistered_ = true;
    http->getConn()->addContextToQueue(this);
}

void
ClientSocketContext::deRegisterWithConn()
{
    assert (connRegistered_);
    removeFromConnectionList(http->getConn());
    connRegistered_ = false;
}

void
ClientSocketContext::connIsFinished()
{
    assert (http);
    assert (http->getConn() != NULL);
    deRegisterWithConn();
    /* we can't handle any more stream data - detach */
    clientStreamDetach(getTail(), http);
}

ClientSocketContext::ClientSocketContext() : http(NULL), reply(NULL), next(NULL),
        writtenToSocket(0),
        mayUseConnection_ (false),
        connRegistered_ (false)
{
    memset (reqbuf, '\0', sizeof (reqbuf));
    flags.deferred = 0;
    flags.parsed_ok = 0;
    deferredparams.node = NULL;
    deferredparams.rep = NULL;
}

ClientSocketContext *
ClientSocketContextNew(ClientHttpRequest * http)
{
    ClientSocketContext *newContext;
    assert(http != NULL);
    newContext = new ClientSocketContext;
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
    /**
     * The idea here is not to be complete, but to get service times
     * for only well-defined types.  For example, we don't include
     * LOG_TCP_REFRESH_FAIL because its not really a cache hit
     * (we *tried* to validate it, but failed).
     */

    switch (logType) {

    case LOG_TCP_REFRESH_UNMODIFIED:
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
                                 tvSubMsec(start_time, current_time));

    clientUpdateHierCounters(&request->hier);
}

void
prepareLogWithRequestDetails(HttpRequest * request, AccessLogEntry * aLogEntry)
{
    assert(request);
    assert(aLogEntry);

#if ICAP_CLIENT
    Adaptation::Icap::History::Pointer ih = request->icapHistory();
#endif
    if (Config.onoff.log_mime_hdrs) {
        Packer p;
        MemBuf mb;
        mb.init();
        packerToMemInit(&p, &mb);
        request->header.packInto(&p);
        //This is the request after adaptation or redirection
        aLogEntry->headers.adapted_request = xstrdup(mb.buf);

        // the virgin request is saved to aLogEntry->request
        if (aLogEntry->request) {
            packerClean(&p);
            mb.reset();
            packerToMemInit(&p, &mb);
            aLogEntry->request->header.packInto(&p);
            aLogEntry->headers.request = xstrdup(mb.buf);
        }

#if ICAP_CLIENT
        packerClean(&p);
        mb.reset();
        packerToMemInit(&p, &mb);

        if (ih != NULL)
            ih->lastIcapHeader.packInto(&p);
        aLogEntry->headers.icap = xstrdup(mb.buf);
#endif

        packerClean(&p);
        mb.clean();
    }

#if ICAP_CLIENT
    if (ih != NULL)
        aLogEntry->icap.processingTime = ih->processingTime();
#endif

    aLogEntry->http.method = request->method;
    aLogEntry->http.version = request->http_ver;
    aLogEntry->hier = request->hier;
    if (request->content_length > 0) // negative when no body or unknown length
        aLogEntry->cache.requestSize += request->content_length;
    aLogEntry->cache.extuser = request->extacl_user.termedBuf();

    if (request->auth_user_request) {

        if (request->auth_user_request->username())
            aLogEntry->cache.authuser =
                xstrdup(request->auth_user_request->username());

        AUTHUSERREQUESTUNLOCK(request->auth_user_request, "request via clientPrepareLogWithRequestDetails");
    }
}

void
ClientHttpRequest::logRequest()
{
    if (out.size || logType) {
        al.icp.opcode = ICP_INVALID;
        al.url = log_uri;
        debugs(33, 9, "clientLogRequest: al.url='" << al.url << "'");

        if (al.reply) {
            al.http.code = al.reply->sline.status;
            al.http.content_type = al.reply->content_type.termedBuf();
        } else if (loggingEntry() && loggingEntry()->mem_obj) {
            al.http.code = loggingEntry()->mem_obj->getReply()->sline.status;
            al.http.content_type = loggingEntry()->mem_obj->getReply()->content_type.termedBuf();
        }

        debugs(33, 9, "clientLogRequest: http.code='" << al.http.code << "'");

        if (loggingEntry() && loggingEntry()->mem_obj)
            al.cache.objectSize = loggingEntry()->contentLen();

        al.cache.caddr.SetNoAddr();

        if (getConn() != NULL) al.cache.caddr = getConn()->log_addr;

        al.cache.requestSize = req_sz;
        al.cache.requestHeadersSize = req_sz;

        al.cache.replySize = out.size;
        al.cache.replyHeadersSize = out.headers_sz;

        al.cache.highOffset = out.offset;

        al.cache.code = logType;

        al.cache.msec = tvSubMsec(start_time, current_time);

        if (request)
            prepareLogWithRequestDetails(request, &al);

        if (getConn() != NULL && getConn()->rfc931[0])
            al.cache.rfc931 = getConn()->rfc931;

#if USE_SSL && 0

        /* This is broken. Fails if the connection has been closed. Needs
         * to snarf the ssl details some place earlier..
         */
        if (getConn() != NULL)
            al.cache.ssluser = sslGetUserEmail(fd_table[getConn()->fd].ssl);

#endif

        ACLFilledChecklist *checklist = clientAclChecklistCreate(Config.accessList.log, this);

        if (al.reply)
            checklist->reply = HTTPMSGLOCK(al.reply);

        if (!Config.accessList.log || checklist->fastCheck()) {
            if (request)
                al.adapted_request = HTTPMSGLOCK(request);
            accessLogLog(&al, checklist);
            updateCounters();

            if (getConn() != NULL)
                clientdbUpdate(getConn()->peer, logType, PROTO_HTTP, out.size);
        }

        delete checklist;
    }

    accessLogFreeMemory(&al);
}

void
ClientHttpRequest::freeResources()
{
    safe_free(uri);
    safe_free(log_uri);
    safe_free(redirect.location);
    range_iter.boundary.clean();
    HTTPMSGUNLOCK(request);

    if (client_stream.tail)
        clientStreamAbort((clientStreamNode *)client_stream.tail->data, this);
}

void
httpRequestFree(void *data)
{
    ClientHttpRequest *http = (ClientHttpRequest *)data;
    assert(http != NULL);
    delete http;
}

bool
ConnStateData::areAllContextsForThisConnection() const
{
    assert(this != NULL);
    ClientSocketContext::Pointer context = getCurrentContext();

    while (context.getRaw()) {
        if (context->http->getConn() != this)
            return false;

        context = context->next;
    }

    return true;
}

void
ConnStateData::freeAllContexts()
{
    ClientSocketContext::Pointer context;

    while ((context = getCurrentContext()).getRaw() != NULL) {
        assert(getCurrentContext() !=
               getCurrentContext()->next);
        context->connIsFinished();
        assert (context != currentobject);
    }
}

/* This is a handler normally called by comm_close() */
void ConnStateData::connStateClosed(const CommCloseCbParams &io)
{
    assert (fd == io.fd);
    deleteThis("ConnStateData::connStateClosed");
}

// cleans up before destructor is called
void
ConnStateData::swanSong()
{
    debugs(33, 2, "ConnStateData::swanSong: FD " << fd);
    fd = -1;
    flags.readMoreRequests = false;
    clientdbEstablished(peer, -1);	/* decrement */
    assert(areAllContextsForThisConnection());
    freeAllContexts();

    if (auth_user_request != NULL) {
        debugs(33, 4, "ConnStateData::swanSong: freeing auth_user_request '" << auth_user_request << "' (this is '" << this << "')");
        auth_user_request->onConnectionClose(this);
    }

    if (pinning.fd >= 0)
        comm_close(pinning.fd);

    BodyProducer::swanSong();
    flags.swanSang = true;
}

bool
ConnStateData::isOpen() const
{
    return cbdataReferenceValid(this) && // XXX: checking "this" in a method
           fd >= 0 &&
           !fd_table[fd].closing();
}

ConnStateData::~ConnStateData()
{
    assert(this != NULL);
    debugs(33, 3, "ConnStateData::~ConnStateData: FD " << fd);

    if (isOpen())
        debugs(33, 1, "BUG: ConnStateData did not close FD " << fd);

    if (!flags.swanSang)
        debugs(33, 1, "BUG: ConnStateData was not destroyed properly; FD " << fd);

    AUTHUSERREQUESTUNLOCK(auth_user_request, "~conn");

    cbdataReferenceDone(port);

    if (bodyPipe != NULL)
        stopProducingFor(bodyPipe, false);
}

/**
 * clientSetKeepaliveFlag() sets request->flags.proxy_keepalive.
 * This is the client-side persistent connection flag.  We need
 * to set this relatively early in the request processing
 * to handle hacks for broken servers and clients.
 */
static void
clientSetKeepaliveFlag(ClientHttpRequest * http)
{
    HttpRequest *request = http->request;
    const HttpHeader *req_hdr = &request->header;

    debugs(33, 3, "clientSetKeepaliveFlag: http_ver = " <<
           request->http_ver.major << "." << request->http_ver.minor);
    debugs(33, 3, "clientSetKeepaliveFlag: method = " <<
           RequestMethodStr(request->method));

    if (httpMsgIsPersistent(request->http_ver, req_hdr))
        request->flags.proxy_keepalive = 1;
}

static int
clientIsContentLengthValid(HttpRequest * r)
{
    switch (r->method.id()) {

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
clientIsRequestBodyValid(int64_t bodyLength)
{
    if (bodyLength >= 0)
        return 1;

    return 0;
}

int
clientIsRequestBodyTooLargeForPolicy(int64_t bodyLength)
{
    if (Config.maxRequestBodySize &&
            bodyLength > Config.maxRequestBodySize)
        return 1;		/* too large */

    return 0;
}

#ifndef PURIFY
int
connIsUsable(ConnStateData * conn)
{
    if (conn == NULL || !cbdataReferenceValid(conn) || conn->fd == -1)
        return 0;

    return 1;
}

#endif

ClientSocketContext::Pointer
ConnStateData::getCurrentContext() const
{
    assert(this);
    return currentobject;
}

void
ClientSocketContext::deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer receivedData)
{
    debugs(33, 2, "clientSocketRecipient: Deferring request " << http->uri);
    assert(flags.deferred == 0);
    flags.deferred = 1;
    deferredparams.node = node;
    deferredparams.rep = rep;
    deferredparams.queuedBuffer = receivedData;
    return;
}

int
responseFinishedOrFailed(HttpReply * rep, StoreIOBuffer const & receivedData)
{
    if (rep == NULL && receivedData.data == NULL && receivedData.length == 0)
        return 1;

    return 0;
}

bool
ClientSocketContext::startOfOutput() const
{
    return http->out.size == 0;
}

size_t
ClientSocketContext::lengthToSend(Range<int64_t> const &available)
{
    /*the size of available range can always fit in a size_t type*/
    size_t maximum = (size_t)available.size();

    if (!http->request->range)
        return maximum;

    assert (canPackMoreRanges());

    if (http->range_iter.debt() == -1)
        return maximum;

    assert (http->range_iter.debt() > 0);

    /* TODO this + the last line could be a range intersection calculation */
    if (available.start < http->range_iter.currentSpec()->offset)
        return 0;

    return min(http->range_iter.debt(), (int64_t)maximum);
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

    /* debt() always stops at -1, below that is a bug */
    assert (http->range_iter.debt() >= -1);
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
        size_t length = lengthToSend(bodyData.range());
        noteSentBodyBytes (length);
        AsyncCall::Pointer call = commCbCall(33, 5, "clientWriteBodyComplete",
                                             CommIoCbPtrFun(clientWriteBodyComplete, this));
        comm_write(fd(), bodyData.data, length, call );
        return;
    }

    MemBuf mb;
    mb.init();
    packRange(bodyData, &mb);

    if (mb.contentSize()) {
        /* write */
        AsyncCall::Pointer call = commCbCall(33, 5, "clientWriteComplete",
                                             CommIoCbPtrFun(clientWriteComplete, this));
        comm_write_mbuf(fd(), &mb, call);
    }  else
        writeComplete(fd(), NULL, 0, COMM_OK);
}

/** put terminating boundary for multiparts */
static void
clientPackTermBound(String boundary, MemBuf * mb)
{
    mb->Printf("\r\n--" SQUIDSTRINGPH "--\r\n", SQUIDSTRINGPRINT(boundary));
    debugs(33, 6, "clientPackTermBound: buf offset: " << mb->size);
}

/** appends a "part" HTTP header (as in a multi-part/range reply) to the buffer */
static void
clientPackRangeHdr(const HttpReply * rep, const HttpHdrRangeSpec * spec, String boundary, MemBuf * mb)
{
    HttpHeader hdr(hoReply);
    Packer p;
    assert(rep);
    assert(spec);

    /* put boundary */
    debugs(33, 5, "clientPackRangeHdr: appending boundary: " << boundary);
    /* rfc2046 requires to _prepend_ boundary with <crlf>! */
    mb->Printf("\r\n--" SQUIDSTRINGPH "\r\n", SQUIDSTRINGPRINT(boundary));

    /* stuff the header with required entries and pack it */

    if (rep->header.has(HDR_CONTENT_TYPE))
        hdr.putStr(HDR_CONTENT_TYPE, rep->header.getStr(HDR_CONTENT_TYPE));

    httpHeaderAddContRange(&hdr, *spec, rep->content_length);

    packerToMemInit(&p, mb);

    hdr.packInto(&p);

    packerClean(&p);

    hdr.clean();

    /* append <crlf> (we packed a header, not a reply) */
    mb->Printf("\r\n");
}

/**
 * extracts a "range" from *buf and appends them to mb, updating
 * all offsets and such.
 */
void
ClientSocketContext::packRange(StoreIOBuffer const &source, MemBuf * mb)
{
    HttpHdrRangeIter * i = &http->range_iter;
    Range<int64_t> available (source.range());
    char const *buf = source.data;

    while (i->currentSpec() && available.size()) {
        const size_t copy_sz = lengthToSend(available);

        if (copy_sz) {
            /*
             * intersection of "have" and "need" ranges must not be empty
             */
            assert(http->out.offset < i->currentSpec()->offset + i->currentSpec()->length);
            assert(http->out.offset + available.size() > i->currentSpec()->offset);

            /*
             * put boundary and headers at the beginning of a range in a
             * multi-range
             */

            if (http->multipartRangeRequest() && i->debt() == i->currentSpec()->length) {
                assert(http->memObject());
                clientPackRangeHdr(
                    http->memObject()->getReply(),	/* original reply */
                    i->currentSpec(),		/* current range */
                    i->boundary,	/* boundary, the same for all */
                    mb);
            }

            /*
             * append content
             */
            debugs(33, 3, "clientPackRange: appending " << copy_sz << " bytes");

            noteSentBodyBytes (copy_sz);

            mb->append(buf, copy_sz);

            /*
             * update offsets
             */
            available.start += copy_sz;

            buf += copy_sz;

        }

        if (!canPackMoreRanges()) {
            debugs(33, 3, "clientPackRange: Returning because !canPackMoreRanges.");

            if (i->debt() == 0)
                /* put terminating boundary for multiparts */
                clientPackTermBound(i->boundary, mb);

            return;
        }

        int64_t nextOffset = getNextRangeOffset();

        assert (nextOffset >= http->out.offset);

        int64_t skip = nextOffset - http->out.offset;

        /* adjust for not to be transmitted bytes */
        http->out.offset = nextOffset;

        if (available.size() <= skip)
            return;

        available.start += skip;

        buf += skip;

        if (copy_sz == 0)
            return;
    }
}

/** returns expected content length for multi-range replies
 * note: assumes that httpHdrRangeCanonize has already been called
 * warning: assumes that HTTP headers for individual ranges at the
 *          time of the actuall assembly will be exactly the same as
 *          the headers when clientMRangeCLen() is called */
int
ClientHttpRequest::mRangeCLen()
{
    int64_t clen = 0;
    MemBuf mb;

    assert(memObject());

    mb.init();
    HttpHdrRange::iterator pos = request->range->begin();

    while (pos != request->range->end()) {
        /* account for headers for this range */
        mb.reset();
        clientPackRangeHdr(memObject()->getReply(),
                           *pos, range_iter.boundary, &mb);
        clen += mb.size;

        /* account for range content */
        clen += (*pos)->length;

        debugs(33, 6, "clientMRangeCLen: (clen += " << mb.size << " + " << (*pos)->length << ") == " << clen);
        ++pos;
    }

    /* account for the terminating boundary */
    mb.reset();

    clientPackTermBound(range_iter.boundary, &mb);

    clen += mb.size;

    mb.clean();

    return clen;
}

/**
 * returns true if If-Range specs match reply, false otherwise
 */
static int
clientIfRangeMatch(ClientHttpRequest * http, HttpReply * rep)
{
    const TimeOrTag spec = http->request->header.getTimeOrTag(HDR_IF_RANGE);
    /* check for parsing falure */

    if (!spec.valid)
        return 0;

    /* got an ETag? */
    if (spec.tag.str) {
        ETag rep_tag = rep->header.getETag(HDR_ETAG);
        debugs(33, 3, "clientIfRangeMatch: ETags: " << spec.tag.str << " and " <<
               (rep_tag.str ? rep_tag.str : "<none>"));

        if (!rep_tag.str)
            return 0;		/* entity has no etag to compare with! */

        if (spec.tag.weak || rep_tag.weak) {
            debugs(33, 1, "clientIfRangeMatch: Weak ETags are not allowed in If-Range: " << spec.tag.str << " ? " << rep_tag.str);
            return 0;		/* must use strong validator for sub-range requests */
        }

        return etagIsStrongEqual(rep_tag, spec.tag);
    }

    /* got modification time? */
    if (spec.time >= 0) {
        return http->storeEntry()->lastmod <= spec.time;
    }

    assert(0);			/* should not happen */
    return 0;
}

/**
 * generates a "unique" boundary string for multipart responses
 * the caller is responsible for cleaning the string */
String
ClientHttpRequest::rangeBoundaryStr() const
{
    assert(this);
    const char *key;
    String b(APP_FULLNAME);
    b.append(":",1);
    key = storeEntry()->getMD5Text();
    b.append(key, strlen(key));
    return b;
}

/** adds appropriate Range headers if needed */
void
ClientSocketContext::buildRangeHeader(HttpReply * rep)
{
    HttpHeader *hdr = rep ? &rep->header : 0;
    const char *range_err = NULL;
    HttpRequest *request = http->request;
    assert(request->range);
    /* check if we still want to do ranges */

    if (!rep)
        range_err = "no [parse-able] reply";
    else if ((rep->sline.status != HTTP_OK) && (rep->sline.status != HTTP_PARTIAL_CONTENT))
        range_err = "wrong status code";
    else if (hdr->has(HDR_CONTENT_RANGE))
        range_err = "origin server does ranges";
    else if (rep->content_length < 0)
        range_err = "unknown length";
    else if (rep->content_length != http->memObject()->getReply()->content_length)
        range_err = "INCONSISTENT length";	/* a bug? */

    /* hits only - upstream peer determines correct behaviour on misses, and client_side_reply determines
     * hits candidates
     */
    else if (logTypeIsATcpHit(http->logType) && http->request->header.has(HDR_IF_RANGE) && !clientIfRangeMatch(http, rep))
        range_err = "If-Range match failed";
    else if (!http->request->range->canonize(rep))
        range_err = "canonization failed";
    else if (http->request->range->isComplex())
        range_err = "too complex range header";
    else if (!logTypeIsATcpHit(http->logType) && http->request->range->offsetLimitExceeded())
        range_err = "range outside range_offset_limit";

    /* get rid of our range specs on error */
    if (range_err) {
        /* XXX We do this here because we need canonisation etc. However, this current
         * code will lead to incorrect store offset requests - the store will have the
         * offset data, but we won't be requesting it.
         * So, we can either re-request, or generate an error
         */
        debugs(33, 3, "clientBuildRangeHeader: will not do ranges: " << range_err << ".");
        delete http->request->range;
        http->request->range = NULL;
    } else {
        /* XXX: TODO: Review, this unconditional set may be wrong. - TODO: review. */
        httpStatusLineSet(&rep->sline, rep->sline.version,
                          HTTP_PARTIAL_CONTENT, NULL);
        // web server responded with a valid, but unexpected range.
        // will (try-to) forward as-is.
        //TODO: we should cope with multirange request/responses
        bool replyMatchRequest = rep->content_range != NULL ?
                                 request->range->contains(rep->content_range->spec) :
                                 true;
        const int spec_count = http->request->range->specs.count;
        int64_t actual_clen = -1;

        debugs(33, 3, "clientBuildRangeHeader: range spec count: " <<
               spec_count << " virgin clen: " << rep->content_length);
        assert(spec_count > 0);
        /* append appropriate header(s) */

        if (spec_count == 1) {
            if (!replyMatchRequest) {
                hdr->delById(HDR_CONTENT_RANGE);
                hdr->putContRange(rep->content_range);
                actual_clen = rep->content_length;
                //http->range_iter.pos = rep->content_range->spec.begin();
                (*http->range_iter.pos)->offset = rep->content_range->spec.offset;
                (*http->range_iter.pos)->length = rep->content_range->spec.length;

            } else {
                HttpHdrRange::iterator pos = http->request->range->begin();
                assert(*pos);
                /* append Content-Range */

                if (!hdr->has(HDR_CONTENT_RANGE)) {
                    /* No content range, so this was a full object we are
                     * sending parts of.
                     */
                    httpHeaderAddContRange(hdr, **pos, rep->content_length);
                }

                /* set new Content-Length to the actual number of bytes
                 * transmitted in the message-body */
                actual_clen = (*pos)->length;
            }
        } else {
            /* multipart! */
            /* generate boundary string */
            http->range_iter.boundary = http->rangeBoundaryStr();
            /* delete old Content-Type, add ours */
            hdr->delById(HDR_CONTENT_TYPE);
            httpHeaderPutStrf(hdr, HDR_CONTENT_TYPE,
                              "multipart/byteranges; boundary=\"" SQUIDSTRINGPH "\"",
                              SQUIDSTRINGPRINT(http->range_iter.boundary));
            /* Content-Length is not required in multipart responses
             * but it is always nice to have one */
            actual_clen = http->mRangeCLen();
            /* http->out needs to start where we want data at */
            http->out.offset = http->range_iter.currentSpec()->offset;
        }

        /* replace Content-Length header */
        assert(actual_clen >= 0);

        hdr->delById(HDR_CONTENT_LENGTH);

        hdr->putInt64(HDR_CONTENT_LENGTH, actual_clen);

        debugs(33, 3, "clientBuildRangeHeader: actual content length: " << actual_clen);

        /* And start the range iter off */
        http->range_iter.updateSpec();
    }
}

void
ClientSocketContext::prepareReply(HttpReply * rep)
{
    reply = rep;

    if (http->request->range)
        buildRangeHeader(rep);
}

void
ClientSocketContext::sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData)
{
    prepareReply(rep);
    assert (rep);
    MemBuf *mb = rep->pack();
    /* Save length of headers for persistent conn checks */
    http->out.headers_sz = mb->contentSize();
#if HEADERS_LOG

    headersLog(0, 0, http->request->method, rep);
#endif

    if (bodyData.data && bodyData.length) {
        if (!multipartRangeRequest()) {
            size_t length = lengthToSend(bodyData.range());
            noteSentBodyBytes (length);

            mb->append(bodyData.data, length);
        } else {
            packRange(bodyData, mb);
        }
    }

    /* write */
    debugs(33,7, HERE << "sendStartOfMessage schedules clientWriteComplete");
    AsyncCall::Pointer call = commCbCall(33, 5, "clientWriteComplete",
                                         CommIoCbPtrFun(clientWriteComplete, this));
    comm_write_mbuf(fd(), mb, call);

    delete mb;
}

/**
 * Write a chunk of data to a client socket. If the reply is present,
 * send the reply headers down the wire too, and clean them up when
 * finished.
 * Pre-condition:
 *   The request is one backed by a connection, not an internal request.
 *   data context is not NULL
 *   There are no more entries in the stream chain.
 */
static void
clientSocketRecipient(clientStreamNode * node, ClientHttpRequest * http,
                      HttpReply * rep, StoreIOBuffer receivedData)
{
    int fd;
    /* Test preconditions */
    assert(node != NULL);
    PROF_start(clientSocketRecipient);
    /* TODO: handle this rather than asserting
     * - it should only ever happen if we cause an abort and
     * the callback chain loops back to here, so we can simply return.
     * However, that itself shouldn't happen, so it stays as an assert for now.
     */
    assert(cbdataReferenceValid(node));
    assert(node->node.next == NULL);
    ClientSocketContext::Pointer context = dynamic_cast<ClientSocketContext *>(node->data.getRaw());
    assert(context != NULL);
    assert(connIsUsable(http->getConn()));
    fd = http->getConn()->fd;
    /* TODO: check offset is what we asked for */

    if (context != http->getConn()->getCurrentContext()) {
        context->deferRecipientForLater(node, rep, receivedData);
        PROF_stop(clientSocketRecipient);
        return;
    }

    if (responseFinishedOrFailed(rep, receivedData)) {
        context->writeComplete(fd, NULL, 0, COMM_OK);
        PROF_stop(clientSocketRecipient);
        return;
    }

    if (!context->startOfOutput())
        context->sendBody(rep, receivedData);
    else {
        assert(rep);
        http->al.reply = HTTPMSGLOCK(rep);
        context->sendStartOfMessage(rep, receivedData);
    }

    PROF_stop(clientSocketRecipient);
}

/**
 * Called when a downstream node is no longer interested in
 * our data. As we are a terminal node, this means on aborts
 * only
 */
void
clientSocketDetach(clientStreamNode * node, ClientHttpRequest * http)
{
    /* Test preconditions */
    assert(node != NULL);
    /* TODO: handle this rather than asserting
     * - it should only ever happen if we cause an abort and
     * the callback chain loops back to here, so we can simply return.
     * However, that itself shouldn't happen, so it stays as an assert for now.
     */
    assert(cbdataReferenceValid(node));
    /* Set null by ContextFree */
    assert(node->node.next == NULL);
    /* this is the assert discussed above */
    assert(NULL == dynamic_cast<ClientSocketContext *>(node->data.getRaw()));
    /* We are only called when the client socket shutsdown.
     * Tell the prev pipeline member we're finished
     */
    clientStreamDetach(node, http);
}

static void
clientWriteBodyComplete(int fd, char *buf, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    debugs(33,7, HERE << "clientWriteBodyComplete schedules clientWriteComplete");
    clientWriteComplete(fd, NULL, size, errflag, xerrno, data);
}

void
ConnStateData::readNextRequest()
{
    debugs(33, 5, "ConnStateData::readNextRequest: FD " << fd << " reading next req");

    fd_note(fd, "Waiting for next request");
    /**
     * Set the timeout BEFORE calling clientReadRequest().
     */
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5,
                                     TimeoutDialer, this, ConnStateData::requestTimeout);
    commSetTimeout(fd, Config.Timeout.persistent_request, timeoutCall);

    readSomeData();
    /** Please don't do anything with the FD past here! */
}

static void
ClientSocketContextPushDeferredIfNeeded(ClientSocketContext::Pointer deferredRequest, ConnStateData * conn)
{
    debugs(33, 2, "ClientSocketContextPushDeferredIfNeeded: FD " << conn->fd << " Sending next");

    /** If the client stream is waiting on a socket write to occur, then */

    if (deferredRequest->flags.deferred) {
        /** NO data is allowed to have been sent. */
        assert(deferredRequest->http->out.size == 0);
        /** defer now. */
        clientSocketRecipient(deferredRequest->deferredparams.node,
                              deferredRequest->http,
                              deferredRequest->deferredparams.rep,
                              deferredRequest->deferredparams.queuedBuffer);
    }

    /** otherwise, the request is still active in a callbacksomewhere,
     * and we are done
     */
}

void
ClientSocketContext::keepaliveNextRequest()
{
    ConnStateData * conn = http->getConn();
    bool do_next_read = false;

    debugs(33, 3, "ClientSocketContext::keepaliveNextRequest: FD " << conn->fd);
    connIsFinished();

    if (conn->pinning.pinned && conn->pinning.fd == -1) {
        debugs(33, 2, "clientKeepaliveNextRequest: FD " << conn->fd << " Connection was pinned but server side gone. Terminating client connection");
        comm_close(conn->fd);
        return;
    }

    /** \par
     * Attempt to parse a request from the request buffer.
     * If we've been fed a pipelined request it may already
     * be in our read buffer.
     *
     \par
     * This needs to fall through - if we're unlucky and parse the _last_ request
     * from our read buffer we may never re-register for another client read.
     */

    if (clientParseRequest(conn, do_next_read)) {
        debugs(33, 3, "clientSocketContext::keepaliveNextRequest: FD " << conn->fd << ": parsed next request from buffer");
    }

    /** \par
     * Either we need to kick-start another read or, if we have
     * a half-closed connection, kill it after the last request.
     * This saves waiting for half-closed connections to finished being
     * half-closed _AND_ then, sometimes, spending "Timeout" time in
     * the keepalive "Waiting for next request" state.
     */
    if (commIsHalfClosed(conn->fd) && (conn->getConcurrentRequestCount() == 0)) {
        debugs(33, 3, "ClientSocketContext::keepaliveNextRequest: half-closed client with no pending requests, closing");
        comm_close(conn->fd);
        return;
    }

    ClientSocketContext::Pointer deferredRequest;

    /** \par
     * At this point we either have a parsed request (which we've
     * kicked off the processing for) or not. If we have a deferred
     * request (parsed but deferred for pipeling processing reasons)
     * then look at processing it. If not, simply kickstart
     * another read.
     */

    if ((deferredRequest = conn->getCurrentContext()).getRaw()) {
        debugs(33, 3, "ClientSocketContext:: FD " << conn->fd << ": calling PushDeferredIfNeeded");
        ClientSocketContextPushDeferredIfNeeded(deferredRequest, conn);
    } else {
        debugs(33, 3, "ClientSocketContext:: FD " << conn->fd << ": calling conn->readNextRequest()");
        conn->readNextRequest();
    }
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

/**
 * increments iterator "i"
 * used by clientPackMoreRanges
 *
 \retval true    there is still data available to pack more ranges
 \retval false
 */
bool
ClientSocketContext::canPackMoreRanges() const
{
    /** first update iterator "i" if needed */

    if (!http->range_iter.debt()) {
        debugs(33, 5, "ClientSocketContext::canPackMoreRanges: At end of current range spec for FD " << fd());

        if (http->range_iter.pos.incrementable())
            ++http->range_iter.pos;

        http->range_iter.updateSpec();
    }

    assert(!http->range_iter.debt() == !http->range_iter.currentSpec());

    /* paranoid sync condition */
    /* continue condition: need_more_data */
    debugs(33, 5, "ClientSocketContext::canPackMoreRanges: returning " << (http->range_iter.currentSpec() ? true : false));
    return http->range_iter.currentSpec() ? true : false;
}

int64_t
ClientSocketContext::getNextRangeOffset() const
{
    if (http->request->range) {
        /* offset in range specs does not count the prefix of an http msg */
        debugs (33, 5, "ClientSocketContext::getNextRangeOffset: http offset " << http->out.offset);
        /* check: reply was parsed and range iterator was initialized */
        assert(http->range_iter.valid);
        /* filter out data according to range specs */
        assert (canPackMoreRanges());
        {
            int64_t start;		/* offset of still missing data */
            assert(http->range_iter.currentSpec());
            start = http->range_iter.currentSpec()->offset + http->range_iter.currentSpec()->length - http->range_iter.debt();
            debugs(33, 3, "clientPackMoreRanges: in:  offset: " << http->out.offset);
            debugs(33, 3, "clientPackMoreRanges: out:"
                   " start: " << start <<
                   " spec[" << http->range_iter.pos - http->request->range->begin() << "]:" <<
                   " [" << http->range_iter.currentSpec()->offset <<
                   ", " << http->range_iter.currentSpec()->offset + http->range_iter.currentSpec()->length << "),"
                   " len: " << http->range_iter.currentSpec()->length <<
                   " debt: " << http->range_iter.debt());
            if (http->range_iter.currentSpec()->length != -1)
                assert(http->out.offset <= start);	/* we did not miss it */

            return start;
        }

    } else if (reply && reply->content_range) {
        /* request does not have ranges, but reply does */
        /** \todo FIXME: should use range_iter_pos on reply, as soon as reply->content_range
         *        becomes HttpHdrRange rather than HttpHdrRangeSpec.
         */
        return http->out.offset + reply->content_range->spec.offset;
    }

    return http->out.offset;
}

void
ClientSocketContext::pullData()
{
    debugs(33, 5, "ClientSocketContext::pullData: FD " << fd() <<
           " attempting to pull upstream data");

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
                debugs(33, 5, HERE << "Range request at end of returnable " <<
                       "range sequence on FD " << fd());

                if (http->request->flags.proxy_keepalive)
                    return STREAM_COMPLETE;
                else
                    return STREAM_UNPLANNED_COMPLETE;
            }
        } else if (reply && reply->content_range) {
            /* reply has content-range, but Squid is not managing ranges */
            const int64_t &bytesSent = http->out.offset;
            const int64_t &bytesExpected = reply->content_range->spec.length;

            debugs(33, 7, HERE << "body bytes sent vs. expected: " <<
                   bytesSent << " ? " << bytesExpected << " (+" <<
                   reply->content_range->spec.offset << ")");

            // did we get at least what we expected, based on range specs?

            if (bytesSent == bytesExpected) { // got everything
                if (http->request->flags.proxy_keepalive)
                    return STREAM_COMPLETE;
                else
                    return STREAM_UNPLANNED_COMPLETE;
            }

            // The logic below is not clear: If we got more than we
            // expected why would persistency matter? Should not this
            // always be an error?
            if (bytesSent > bytesExpected) { // got extra
                if (http->request->flags.proxy_keepalive)
                    return STREAM_COMPLETE;
                else
                    return STREAM_UNPLANNED_COMPLETE;
            }

            // did not get enough yet, expecting more
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

/**
 * A write has just completed to the client, or we have just realised there is
 * no more data to send.
 */
void
clientWriteComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    ClientSocketContext *context = (ClientSocketContext *)data;
    context->writeComplete (fd, bufnotused, size, errflag);
}

void
ClientSocketContext::doClose()
{
    comm_close(fd());
}

/** Called to initiate (and possibly complete) closing of the context.
 * The underlying socket may be already closed */
void
ClientSocketContext::initiateClose(const char *reason)
{
    debugs(33, 5, HERE << "initiateClose: closing for " << reason);

    if (http != NULL) {
        ConnStateData * conn = http->getConn();

        if (conn != NULL) {
            if (const int64_t expecting = conn->bodySizeLeft()) {
                debugs(33, 5, HERE << "ClientSocketContext::initiateClose: " <<
                       "closing, but first " << conn << " needs to read " <<
                       expecting << " request body bytes with " <<
                       conn->in.notYetUsed << " notYetUsed");

                if (conn->closing()) {
                    debugs(33, 2, HERE << "avoiding double-closing " << conn);
                    return;
                }

                /*
                * XXX We assume the reply fits in the TCP transmit
                * window.  If not the connection may stall while sending
                * the reply (before reaching here) if the client does not
                * try to read the response while sending the request body.
                * As of yet we have not received any complaints indicating
                * this may be an issue.
                */
                conn->startClosing(reason);

                return;
            }
        }
    }

    doClose();
}

void
ClientSocketContext::writeComplete(int aFileDescriptor, char *bufnotused, size_t size, comm_err_t errflag)
{
    StoreEntry *entry = http->storeEntry();
    http->out.size += size;
    assert(aFileDescriptor > -1);
    debugs(33, 5, "clientWriteComplete: FD " << aFileDescriptor << ", sz " << size <<
           ", err " << errflag << ", off " << http->out.size << ", len " <<
           entry ? entry->objectLen() : 0);
    clientUpdateSocketStats(http->logType, size);
    assert (this->fd() == aFileDescriptor);

    /* Bail out quickly on COMM_ERR_CLOSING - close handlers will tidy up */

    if (errflag == COMM_ERR_CLOSING)
        return;

    if (errflag || clientHttpRequestStatus(aFileDescriptor, http)) {
        initiateClose("failure or true request status");
        /* Do we leak here ? */
        return;
    }

    switch (socketState()) {

    case STREAM_NONE:
        pullData();
        break;

    case STREAM_COMPLETE:
        debugs(33, 5, "clientWriteComplete: FD " << aFileDescriptor << " Keeping Alive");
        keepaliveNextRequest();
        return;

    case STREAM_UNPLANNED_COMPLETE:
        initiateClose("STREAM_UNPLANNED_COMPLETE");
        return;

    case STREAM_FAILED:
        initiateClose("STREAM_FAILED");
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
    ClientHttpRequest *http;
    ClientSocketContext *context;
    StoreIOBuffer tempBuffer;
    http = new ClientHttpRequest(conn);
    http->req_sz = conn->in.notYetUsed;
    http->uri = xstrdup(uri);
    setLogUri (http, uri);
    context = ClientSocketContextNew(http);
    tempBuffer.data = context->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, new clientReplyContext(http), clientSocketRecipient,
                     clientSocketDetach, context, tempBuffer);
    return context;
}

char *
skipLeadingSpace(char *aString)
{
    char *result = aString;

    while (xisspace(*aString))
        ++aString;

    return result;
}

/**
 * 'end' defaults to NULL for backwards compatibility
 * remove default value if we ever get rid of NULL-terminated
 * request buffers.
 */
const char *
findTrailingHTTPVersion(const char *uriAndHTTPVersion, const char *end)
{
    if (NULL == end) {
        end = uriAndHTTPVersion + strcspn(uriAndHTTPVersion, "\r\n");
        assert(end);
    }

    for (; end > uriAndHTTPVersion; end--) {
        if (*end == '\n' || *end == '\r')
            continue;

        if (xisspace(*end)) {
            if (strncasecmp(end + 1, "HTTP/", 5) == 0)
                return end + 1;
            else
                break;
        }
    }

    return NULL;
}

void
setLogUri(ClientHttpRequest * http, char const *uri, bool cleanUrl)
{
    safe_free(http->log_uri);

    if (!cleanUrl)
        // The uri is already clean just dump it.
        http->log_uri = xstrndup(uri, MAX_URL);
    else {
        int flags = 0;
        switch (Config.uri_whitespace) {
        case URI_WHITESPACE_ALLOW:
            flags |= RFC1738_ESCAPE_NOSPACE;

        case URI_WHITESPACE_ENCODE:
            flags |= RFC1738_ESCAPE_UNESCAPED;
            http->log_uri = xstrndup(rfc1738_do_escape(uri, flags), MAX_URL);
            break;

        case URI_WHITESPACE_CHOP: {
            flags |= RFC1738_ESCAPE_NOSPACE;
            flags |= RFC1738_ESCAPE_UNESCAPED;
            http->log_uri = xstrndup(rfc1738_do_escape(uri, flags), MAX_URL);
            int pos = strcspn(http->log_uri, w_space);
            http->log_uri[pos] = '\0';
        }
        break;

        case URI_WHITESPACE_DENY:
        case URI_WHITESPACE_STRIP:
        default: {
            const char *t;
            char *tmp_uri = static_cast<char*>(xmalloc(strlen(uri) + 1));
            char *q = tmp_uri;
            t = uri;
            while (*t) {
                if (!xisspace(*t))
                    *q++ = *t;
                t++;
            }
            *q = '\0';
            http->log_uri = xstrndup(rfc1738_escape_unescaped(tmp_uri), MAX_URL);
            xfree(tmp_uri);
        }
        break;
        }
    }
}

static void
prepareAcceleratedURL(ConnStateData * conn, ClientHttpRequest *http, char *url, const char *req_hdr)
{
    int vhost = conn->port->vhost;
    int vport = conn->port->vport;
    char *host;
    char ipbuf[MAX_IPSTRLEN];

    http->flags.accel = 1;

    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */

    if (strncasecmp(url, "cache_object://", 15) == 0)
        return; /* already in good shape */

    if (*url != '/') {
        if (conn->port->vhost)
            return; /* already in good shape */

        /* else we need to ignore the host name */
        url = strstr(url, "//");

#if SHOULD_REJECT_UNKNOWN_URLS

        if (!url)
            return parseHttpRequestAbort(conn, "error:invalid-request");

#endif

        if (url)
            url = strchr(url + 2, '/');

        if (!url)
            url = (char *) "/";
    }

    if (internalCheck(url)) {
        /* prepend our name & port */
        http->uri = xstrdup(internalLocalUri(NULL, url));
        return;
    }

    if (vport < 0)
        vport = http->getConn()->me.GetPort();

    const bool switchedToHttps = conn->switchedToHttps();
    const bool tryHostHeader = vhost || switchedToHttps;
    if (tryHostHeader && (host = mime_get_header(req_hdr, "Host")) != NULL) {
        debugs(33, 5, "ACCEL VHOST REWRITE: vhost=" << host << " + vport=" << vport);
        char thost[256];
        if (vport > 0) {
            thost[0] = '\0';
            char *t = NULL;
            if (host[strlen(host)] != ']' && (t = strrchr(host,':')) != NULL) {
                strncpy(thost, host, (t-host));
                snprintf(thost+(t-host), sizeof(thost)-(t-host), ":%d", vport);
                host = thost;
            } else if (!t) {
                snprintf(thost, sizeof(thost), "%s:%d",host, vport);
                host = thost;
            }
        } // else nothing to alter port-wise.
        int url_sz = strlen(url) + 32 + Config.appendDomainLen +
                     strlen(host);
        http->uri = (char *)xcalloc(url_sz, 1);
        const char *protocol = switchedToHttps ?
                               "https" : conn->port->protocol;
        snprintf(http->uri, url_sz, "%s://%s%s", protocol, host, url);
        debugs(33, 5, "ACCEL VHOST REWRITE: '" << http->uri << "'");
    } else if (conn->port->defaultsite /* && !vhost */) {
        debugs(33, 5, "ACCEL DEFAULTSITE REWRITE: defaultsite=" << conn->port->defaultsite << " + vport=" << vport);
        int url_sz = strlen(url) + 32 + Config.appendDomainLen +
                     strlen(conn->port->defaultsite);
        http->uri = (char *)xcalloc(url_sz, 1);
        char vportStr[32];
        vportStr[0] = '\0';
        if (vport > 0) {
            snprintf(vportStr, sizeof(vportStr),":%d",vport);
        }
        snprintf(http->uri, url_sz, "%s://%s%s%s",
                 conn->port->protocol, conn->port->defaultsite, vportStr, url);
        debugs(33, 5, "ACCEL DEFAULTSITE REWRITE: '" << http->uri <<"'");
    } else if (vport > 0 /* && (!vhost || no Host:) */) {
        debugs(33, 5, "ACCEL VPORT REWRITE: http_port IP + vport=" << vport);
        /* Put the local socket IP address as the hostname, with whatever vport we found  */
        int url_sz = strlen(url) + 32 + Config.appendDomainLen;
        http->uri = (char *)xcalloc(url_sz, 1);
        http->getConn()->me.ToHostname(ipbuf,MAX_IPSTRLEN);
        snprintf(http->uri, url_sz, "%s://%s:%d%s",
                 http->getConn()->port->protocol,
                 ipbuf, vport, url);
        debugs(33, 5, "ACCEL VPORT REWRITE: '" << http->uri << "'");
    }
}

static void
prepareTransparentURL(ConnStateData * conn, ClientHttpRequest *http, char *url, const char *req_hdr)
{
    char *host;
    char ipbuf[MAX_IPSTRLEN];

    if (*url != '/')
        return; /* already in good shape */

    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */
    // BUG 2976: Squid only accepts intercepted HTTP.

    if ((host = mime_get_header(req_hdr, "Host")) != NULL) {
        int url_sz = strlen(url) + 32 + Config.appendDomainLen +
                     strlen(host);
        http->uri = (char *)xcalloc(url_sz, 1);
        snprintf(http->uri, url_sz, "http://%s%s", /*conn->port->protocol,*/ host, url);
        debugs(33, 5, "TRANSPARENT HOST REWRITE: '" << http->uri <<"'");
    } else {
        /* Put the local socket IP address as the hostname.  */
        int url_sz = strlen(url) + 32 + Config.appendDomainLen;
        http->uri = (char *)xcalloc(url_sz, 1);
        http->getConn()->me.ToHostname(ipbuf,MAX_IPSTRLEN),
        snprintf(http->uri, url_sz, "http://%s:%d%s",
                 // http->getConn()->port->protocol,
                 ipbuf, http->getConn()->me.GetPort(), url);
        debugs(33, 5, "TRANSPARENT REWRITE: '" << http->uri << "'");
    }
}

// Temporary hack helper: determine whether the request is chunked, expensive
static bool
isChunkedRequest(const HttpParser *hp)
{
    HttpRequest request;
    if (!request.parseHeader(HttpParserHdrBuf(hp), HttpParserHdrSz(hp)))
        return false;

    return request.header.chunked();
}


/**
 *  parseHttpRequest()
 *
 *  Returns
 *  NULL on incomplete requests
 *  a ClientSocketContext structure on success or failure.
 *  Sets result->flags.parsed_ok to 0 if failed to parse the request.
 *  Sets result->flags.parsed_ok to 1 if we have a good request.
 */
static ClientSocketContext *
parseHttpRequest(ConnStateData *conn, HttpParser *hp, HttpRequestMethod * method_p, HttpVersion *http_ver)
{
    char *req_hdr = NULL;
    char *end;
    size_t req_sz;
    ClientHttpRequest *http;
    ClientSocketContext *result;
    StoreIOBuffer tempBuffer;
    int r;

    /* pre-set these values to make aborting simpler */
    *method_p = METHOD_NONE;

    /* NP: don't be tempted to move this down or remove again.
     * It's the only DDoS protection old-String has against long URL */
    if ( hp->bufsiz <= 0) {
        debugs(33, 5, "Incomplete request, waiting for end of request line");
        return NULL;
    } else if ( (size_t)hp->bufsiz >= Config.maxRequestHeaderSize && headersEnd(hp->buf, Config.maxRequestHeaderSize) == 0) {
        debugs(33, 5, "parseHttpRequest: Too large request");
        return parseHttpRequestAbort(conn, "error:request-too-large");
    }

    /* Attempt to parse the first line; this'll define the method, url, version and header begin */
    r = HttpParserParseReqLine(hp);

    if (r == 0) {
        debugs(33, 5, "Incomplete request, waiting for end of request line");
        return NULL;
    }

    if (r == -1) {
        return parseHttpRequestAbort(conn, "error:invalid-request");
    }

    /* Request line is valid here .. */
    *http_ver = HttpVersion(hp->v_maj, hp->v_min);

    /* This call scans the entire request, not just the headers */
    if (hp->v_maj > 0) {
        if ((req_sz = headersEnd(hp->buf, hp->bufsiz)) == 0) {
            debugs(33, 5, "Incomplete request, waiting for end of headers");
            return NULL;
        }
    } else {
        debugs(33, 3, "parseHttpRequest: Missing HTTP identifier");
        req_sz = HttpParserReqSz(hp);
    }

    /* We know the whole request is in hp->buf now */

    assert(req_sz <= (size_t) hp->bufsiz);

    /* Will the following be true with HTTP/0.9 requests? probably not .. */
    /* So the rest of the code will need to deal with '0'-byte headers (ie, none, so don't try parsing em) */
    assert(req_sz > 0);

    hp->hdr_end = req_sz - 1;

    hp->hdr_start = hp->req_end + 1;

    /* Enforce max_request_size */
    if (req_sz >= Config.maxRequestHeaderSize) {
        debugs(33, 5, "parseHttpRequest: Too large request");
        return parseHttpRequestAbort(conn, "error:request-too-large");
    }

    /* Set method_p */
    *method_p = HttpRequestMethod(&hp->buf[hp->m_start], &hp->buf[hp->m_end]+1);

    /* deny CONNECT via accelerated ports */
    if (*method_p == METHOD_CONNECT && conn && conn->port && conn->port->accel) {
        debugs(33, DBG_IMPORTANT, "WARNING: CONNECT method received on " << conn->port->protocol << " Accelerator port " << conn->port->s.GetPort() );
        /* XXX need a way to say "this many character length string" */
        debugs(33, DBG_IMPORTANT, "WARNING: for request: " << hp->buf);
        /* XXX need some way to set 405 status on the error reply */
        return parseHttpRequestAbort(conn, "error:method-not-allowed");
    }

    if (*method_p == METHOD_NONE) {
        /* XXX need a way to say "this many character length string" */
        debugs(33, 1, "clientParseRequestMethod: Unsupported method in request '" << hp->buf << "'");

        /* XXX where's the method set for this error? */
        return parseHttpRequestAbort(conn, "error:unsupported-request-method");
    }

    /*
     * Process headers after request line
     * TODO: Use httpRequestParse here.
     */
    /* XXX this code should be modified to take a const char * later! */
    req_hdr = (char *) hp->buf + hp->req_end + 1;

    debugs(33, 3, "parseHttpRequest: req_hdr = {" << req_hdr << "}");

    end = (char *) hp->buf + hp->hdr_end;

    debugs(33, 3, "parseHttpRequest: end = {" << end << "}");

    /*
     * Check that the headers don't have double-CR.
     * NP: strnstr is required so we don't search any possible binary body blobs.
     */
    if ( squid_strnstr(req_hdr, "\r\r\n", req_sz) ) {
        debugs(33, 1, "WARNING: suspicious HTTP request contains double CR");
        return parseHttpRequestAbort(conn, "error:double-CR");
    }

    debugs(33, 3, "parseHttpRequest: prefix_sz = " <<
           (int) HttpParserRequestLen(hp) << ", req_line_sz = " <<
           HttpParserReqSz(hp));

    // Temporary hack: We might receive a chunked body from a broken HTTP/1.1
    // client that sends chunked requests to HTTP/1.0 Squid. If the request
    // might have a chunked body, parse the headers early to look for the
    // "Transfer-Encoding: chunked" header. If we find it, wait until the
    // entire body is available so that we can set the content length and
    // forward the request without chunks. The primary reason for this is
    // to avoid forwarding a chunked request because the server side lacks
    // logic to determine when it is valid to do so.
    // FUTURE_CODE_TO_SUPPORT_CHUNKED_REQUESTS below will replace this hack.
    if (hp->v_min == 1 && hp->v_maj == 1 && // broken client, may send chunks
            Config.maxChunkedRequestBodySize > 0 && // configured to dechunk
            (*method_p == METHOD_PUT || *method_p == METHOD_POST)) {

        // check only once per request because isChunkedRequest is expensive
        if (conn->in.dechunkingState == ConnStateData::chunkUnknown) {
            if (isChunkedRequest(hp))
                conn->startDechunkingRequest(hp);
            else
                conn->in.dechunkingState = ConnStateData::chunkNone;
        }

        if (conn->in.dechunkingState == ConnStateData::chunkParsing) {
            if (conn->parseRequestChunks(hp)) // parses newly read chunks
                return NULL; // wait for more data
            debugs(33, 5, HERE << "Got complete chunked request or err.");
            assert(conn->in.dechunkingState != ConnStateData::chunkParsing);
        }
    }

    /* Ok, all headers are received */
    http = new ClientHttpRequest(conn);

    http->req_sz = HttpParserRequestLen(hp);
    result = ClientSocketContextNew(http);
    tempBuffer.data = result->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;

    ClientStreamData newServer = new clientReplyContext(http);
    ClientStreamData newClient = result;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, newServer, clientSocketRecipient,
                     clientSocketDetach, newClient, tempBuffer);

    debugs(33, 5, "parseHttpRequest: Request Header is\n" <<(hp->buf) + hp->hdr_start);

    /* set url */
    /*
     * XXX this should eventually not use a malloc'ed buffer; the transformation code
     * below needs to be modified to not expect a mutable nul-terminated string.
     */
    char *url = (char *)xmalloc(hp->u_end - hp->u_start + 16);

    memcpy(url, hp->buf + hp->u_start, hp->u_end - hp->u_start + 1);

    url[hp->u_end - hp->u_start + 1] = '\0';

#if THIS_VIOLATES_HTTP_SPECS_ON_URL_TRANSFORMATION

    if ((t = strchr(url, '#')))	/* remove HTML anchors */
        *t = '\0';

#endif

    debugs(33,5, HERE << "repare absolute URL from " << (conn->transparent()?"intercept":(conn->port->accel ? "accel":"")));
    /* Rewrite the URL in transparent or accelerator mode */
    /* NP: there are several cases to traverse here:
     *  - standard mode (forward proxy)
     *  - transparent mode (TPROXY)
     *  - transparent mode with failures
     *  - intercept mode (NAT)
     *  - intercept mode with failures
     *  - accelerator mode (reverse proxy)
     *  - internal URL
     *  - mixed combos of the above with internal URL
     */
    if (conn->transparent()) {
        /* intercept or transparent mode, properly working with no failures */
        http->flags.intercepted = conn->port->intercepted;
        http->flags.spoof_client_ip = conn->port->spoof_client_ip;
        prepareTransparentURL(conn, http, url, req_hdr);

    } else if (conn->port->intercepted || conn->port->spoof_client_ip) {
        /* transparent or intercept mode with failures */
        prepareTransparentURL(conn, http, url, req_hdr);

    } else if (conn->port->accel || conn->switchedToHttps()) {
        /* accelerator mode */
        prepareAcceleratedURL(conn, http, url, req_hdr);

    } else if (internalCheck(url)) {
        /* internal URL mode */
        /* prepend our name & port */
        http->uri = xstrdup(internalLocalUri(NULL, url));
        http->flags.accel = 1;
    }

    if (!http->uri) {
        /* No special rewrites have been applied above, use the
         * requested url. may be rewritten later, so make extra room */
        int url_sz = strlen(url) + Config.appendDomainLen + 5;
        http->uri = (char *)xcalloc(url_sz, 1);
        strcpy(http->uri, url);
    }

    debugs(33, 5, "parseHttpRequest: Complete request received");
    result->flags.parsed_ok = 1;
    xfree(url);
    return result;
}

int
ConnStateData::getAvailableBufferLength() const
{
    int result = in.allocatedSize - in.notYetUsed - 1;
    assert (result >= 0);
    return result;
}

bool
ConnStateData::maybeMakeSpaceAvailable()
{
    if (getAvailableBufferLength() < 2) {
        size_t newSize;
        if (in.allocatedSize >= Config.maxRequestBufferSize) {
            debugs(33, 4, "request buffer full: client_request_buffer_max_size=" << Config.maxRequestBufferSize);
            return false;
        }
        if ((newSize=in.allocatedSize * 2) > Config.maxRequestBufferSize) {
            newSize=Config.maxRequestBufferSize;
        }
        in.buf = (char *)memReallocBuf(in.buf, newSize, &in.allocatedSize);
        debugs(33, 2, "growing request buffer: notYetUsed=" << in.notYetUsed << " size=" << in.allocatedSize);
    }
    return true;
}

void
ConnStateData::addContextToQueue(ClientSocketContext * context)
{
    ClientSocketContext::Pointer *S;

    for (S = (ClientSocketContext::Pointer *) & currentobject; S->getRaw();
            S = &(*S)->next);
    *S = context;

    ++nrequests;
}

int
ConnStateData::getConcurrentRequestCount() const
{
    int result = 0;
    ClientSocketContext::Pointer *T;

    for (T = (ClientSocketContext::Pointer *) &currentobject;
            T->getRaw(); T = &(*T)->next, ++result);
    return result;
}

int
ConnStateData::connReadWasError(comm_err_t flag, int size, int xerrno)
{
    if (flag != COMM_OK) {
        debugs(33, 2, "connReadWasError: FD " << fd << ": got flag " << flag);
        return 1;
    }

    if (size < 0) {
        if (!ignoreErrno(xerrno)) {
            debugs(33, 2, "connReadWasError: FD " << fd << ": " << xstrerr(xerrno));
            return 1;
        } else if (in.notYetUsed == 0) {
            debugs(33, 2, "connReadWasError: FD " << fd << ": no data to process (" << xstrerr(xerrno) << ")");
        }
    }

    return 0;
}

int
ConnStateData::connFinishedWithConn(int size)
{
    if (size == 0) {
        if (getConcurrentRequestCount() == 0 && in.notYetUsed == 0) {
            /* no current or pending requests */
            debugs(33, 4, "connFinishedWithConn: FD " << fd << " closed");
            return 1;
        } else if (!Config.onoff.half_closed_clients) {
            /* admin doesn't want to support half-closed client sockets */
            debugs(33, 3, "connFinishedWithConn: FD " << fd << " aborted (half_closed_clients disabled)");
            return 1;
        }
    }

    return 0;
}

void
connNoteUseOfBuffer(ConnStateData* conn, size_t byteCount)
{
    assert(byteCount > 0 && byteCount <= conn->in.notYetUsed);
    conn->in.notYetUsed -= byteCount;
    debugs(33, 5, HERE << "conn->in.notYetUsed = " << conn->in.notYetUsed);
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
    // when we read chunked requests, the entire body is buffered
    // XXX: this check ignores header size and its limits.
    if (conn->in.dechunkingState == ConnStateData::chunkParsing)
        return ((int64_t)conn->in.notYetUsed) < Config.maxChunkedRequestBodySize;

    return conn->in.notYetUsed >= Config.maxRequestHeaderSize ? 0 : 1;
}

void
connCancelIncompleteRequests(ConnStateData * conn)
{
    ClientSocketContext *context = parseHttpRequestAbort(conn, "error:request-too-large");
    clientStreamNode *node = context->getClientReplyContext();
    assert(!connKeepReadingIncompleteRequest(conn));
    if (conn->in.dechunkingState == ConnStateData::chunkParsing) {
        debugs(33, 1, "Chunked request is too large (" << conn->in.notYetUsed << " bytes)");
        debugs(33, 1, "Config 'chunked_request_body_max_size'= " << Config.maxChunkedRequestBodySize << " bytes.");
    } else {
        debugs(33, 1, "Request header is too large (" << conn->in.notYetUsed << " bytes)");
        debugs(33, 1, "Config 'request_header_max_size'= " << Config.maxRequestHeaderSize << " bytes.");
    }
    clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
    assert (repContext);
    repContext->setReplyToError(ERR_TOO_BIG,
                                HTTP_REQUEST_ENTITY_TOO_LARGE, METHOD_NONE, NULL,
                                conn->peer, NULL, NULL, NULL);
    context->registerWithConn();
    context->pullData();
}

void
ConnStateData::clientMaybeReadData(int do_next_read)
{
    if (do_next_read) {
        flags.readMoreRequests = true;
        readSomeData();
    }
}

void
ConnStateData::clientAfterReadingRequests(int do_next_read)
{
    /*
     * If (1) we are reading a message body, (2) and the connection
     * is half-closed, and (3) we didn't get the entire HTTP request
     * yet, then close this connection.
     */

    if (fd_table[fd].flags.socket_eof) {
        if ((int64_t)in.notYetUsed < bodySizeLeft()) {
            /* Partial request received. Abort client connection! */
            debugs(33, 3, "clientAfterReadingRequests: FD " << fd << " aborted, partial request");
            comm_close(fd);
            return;
        }
    }

    clientMaybeReadData (do_next_read);
}

static void
clientProcessRequest(ConnStateData *conn, HttpParser *hp, ClientSocketContext *context, const HttpRequestMethod& method, HttpVersion http_ver)
{
    ClientHttpRequest *http = context->http;
    HttpRequest *request = NULL;
    bool notedUseOfBuffer = false;
    bool tePresent = false;
    bool deChunked = false;
    bool mustReplyToOptions = false;
    bool unsupportedTe = false;

    /* We have an initial client stream in place should it be needed */
    /* setup our private context */
    context->registerWithConn();

    if (context->flags.parsed_ok == 0) {
        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 2, "clientProcessRequest: Invalid Request");
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_INVALID_REQ, HTTP_BAD_REQUEST, method, NULL, conn->peer, NULL, conn->in.buf, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        conn->flags.readMoreRequests = false;
        goto finish;
    }

    if ((request = HttpRequest::CreateFromUrlAndMethod(http->uri, method)) == NULL) {
        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 5, "Invalid URL: " << http->uri);
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_INVALID_URL, HTTP_BAD_REQUEST, method, http->uri, conn->peer, NULL, NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        conn->flags.readMoreRequests = false;
        goto finish;
    }

    /* RFC 2616 section 10.5.6 : handle unsupported HTTP versions cleanly. */
    /* We currently only accept 0.9, 1.0, 1.1 */
    if ( (http_ver.major == 0 && http_ver.minor != 9) ||
            (http_ver.major == 1 && http_ver.minor > 1 ) ||
            (http_ver.major > 1) ) {

        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 5, "Unsupported HTTP version discovered. :\n" << HttpParserHdrBuf(hp));
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_UNSUP_HTTPVERSION, HTTP_HTTP_VERSION_NOT_SUPPORTED, method, http->uri, conn->peer, NULL, HttpParserHdrBuf(hp), NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        conn->flags.readMoreRequests = false;
        goto finish;
    }

    /* compile headers */
    /* we should skip request line! */
    /* XXX should actually know the damned buffer size here */
    if (http_ver.major >= 1 && !request->parseHeader(HttpParserHdrBuf(hp), HttpParserHdrSz(hp))) {
        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 5, "Failed to parse request headers:\n" << HttpParserHdrBuf(hp));
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_INVALID_REQ, HTTP_BAD_REQUEST, method, http->uri, conn->peer, NULL, NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        conn->flags.readMoreRequests = false;
        goto finish;
    }

    request->flags.accelerated = http->flags.accel;
    request->flags.sslBumped = conn->switchedToHttps();
    request->flags.ignore_cc = conn->port->ignore_cc;
    request->flags.no_direct = request->flags.accelerated ? !conn->port->allow_direct : 0;

    /** \par
     * If transparent or interception mode is working clone the transparent and interception flags
     * from the port settings to the request.
     */
    if (IpInterceptor.InterceptActive()) {
        request->flags.intercepted = http->flags.intercepted;
    }
    if (IpInterceptor.TransparentActive()) {
        request->flags.spoof_client_ip = conn->port->spoof_client_ip;
    }

    if (internalCheck(request->urlpath.termedBuf())) {
        if (internalHostnameIs(request->GetHost()) &&
                request->port == getMyPort()) {
            http->flags.internal = 1;
        } else if (Config.onoff.global_internal_static && internalStaticCheck(request->urlpath.termedBuf())) {
            request->SetHost(internalHostname());
            request->port = getMyPort();
            http->flags.internal = 1;
        }
    }

    if (http->flags.internal) {
        request->protocol = PROTO_HTTP;
        request->login[0] = '\0';
    }

    request->flags.internal = http->flags.internal;
    setLogUri (http, urlCanonicalClean(request));
    request->client_addr = conn->peer;
#if FOLLOW_X_FORWARDED_FOR
    request->indirect_client_addr = conn->peer;
#endif /* FOLLOW_X_FORWARDED_FOR */
    request->my_addr = conn->me;
    request->myportname = conn->port->name;
    request->http_ver = http_ver;

    tePresent = request->header.has(HDR_TRANSFER_ENCODING);
    deChunked = conn->in.dechunkingState == ConnStateData::chunkReady;
    if (deChunked) {
        assert(tePresent);
        request->setContentLength(conn->in.dechunked.contentSize());
        request->header.delById(HDR_TRANSFER_ENCODING);
        conn->finishDechunkingRequest(hp);
    } else
        conn->cleanDechunkingRequest();

    mustReplyToOptions = (method == METHOD_OPTIONS) &&
                         (request->header.getInt64(HDR_MAX_FORWARDS) == 0);
    unsupportedTe = tePresent && !deChunked;
    if (!urlCheckRequest(request) || mustReplyToOptions || unsupportedTe) {
        clientStreamNode *node = context->getClientReplyContext();
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_UNSUP_REQ,
                                    HTTP_NOT_IMPLEMENTED, request->method, NULL,
                                    conn->peer, request, NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        conn->flags.readMoreRequests = false;
        goto finish;
    }


    if (!clientIsContentLengthValid(request)) {
        clientStreamNode *node = context->getClientReplyContext();
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_INVALID_REQ,
                                    HTTP_LENGTH_REQUIRED, request->method, NULL,
                                    conn->peer, request, NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        conn->flags.readMoreRequests = false;
        goto finish;
    }

    if (request->header.has(HDR_EXPECT)) {
        int ignore = 0;
#if HTTP_VIOLATIONS
        if (Config.onoff.ignore_expect_100) {
            String expect = request->header.getList(HDR_EXPECT);
            if (expect.caseCmp("100-continue") == 0)
                ignore = 1;
            expect.clean();
        }
#endif
        if (!ignore) {
            clientStreamNode *node = context->getClientReplyContext();
            clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
            assert (repContext);
            repContext->setReplyToError(ERR_INVALID_REQ, HTTP_EXPECTATION_FAILED, request->method, http->uri, conn->peer, request, NULL, NULL);
            assert(context->http->out.offset == 0);
            context->pullData();
            goto finish;
        }
    }

    http->request = HTTPMSGLOCK(request);
    clientSetKeepaliveFlag(http);

    /* If this is a CONNECT, don't schedule a read - ssl.c will handle it */
    if (http->request->method == METHOD_CONNECT)
        context->mayUseConnection(true);

    /* Do we expect a request-body? */
    if (!context->mayUseConnection() && request->content_length > 0) {
        request->body_pipe = conn->expectRequestBody(request->content_length);

        // consume header early so that body pipe gets just the body
        connNoteUseOfBuffer(conn, http->req_sz);
        notedUseOfBuffer = true;

        conn->handleRequestBodyData(); // may comm_close and stop producing

        /* Is it too large? */

        if (!clientIsRequestBodyValid(request->content_length) ||
                clientIsRequestBodyTooLargeForPolicy(request->content_length)) {
            clientStreamNode *node = context->getClientReplyContext();
            clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
            assert (repContext);
            repContext->setReplyToError(ERR_TOO_BIG,
                                        HTTP_REQUEST_ENTITY_TOO_LARGE, METHOD_NONE, NULL,
                                        conn->peer, http->request, NULL, NULL);
            assert(context->http->out.offset == 0);
            context->pullData();
            goto finish;
        }

        if (!request->body_pipe->productionEnded())
            conn->readSomeData();

        context->mayUseConnection(!request->body_pipe->productionEnded());
    }

    http->calloutContext = new ClientRequestContext(http);

    http->doCallouts();

finish:
    if (!notedUseOfBuffer)
        connNoteUseOfBuffer(conn, http->req_sz);

    /*
     * DPW 2007-05-18
     * Moved the TCP_RESET feature from clientReplyContext::sendMoreData
     * to here because calling comm_reset_close() causes http to
     * be freed and the above connNoteUseOfBuffer() would hit an
     * assertion, not to mention that we were accessing freed memory.
     */
    if (http->request->flags.resetTCP() && conn->fd > -1) {
        debugs(33, 3, HERE << "Sending TCP RST on FD " << conn->fd);
        conn->flags.readMoreRequests = false;
        comm_reset_close(conn->fd);
        return;
    }
}

static void
connStripBufferWhitespace (ConnStateData * conn)
{
    while (conn->in.notYetUsed > 0 && xisspace(conn->in.buf[0])) {
        xmemmove(conn->in.buf, conn->in.buf + 1, conn->in.notYetUsed - 1);
        --conn->in.notYetUsed;
    }
}

static int
connOkToAddRequest(ConnStateData * conn)
{
    int result = conn->getConcurrentRequestCount() < (Config.onoff.pipeline_prefetch ? 2 : 1);

    if (!result) {
        debugs(33, 3, "connOkToAddRequest: FD " << conn->fd <<
               " max concurrent requests reached");
        debugs(33, 5, "connOkToAddRequest: FD " << conn->fd <<
               " defering new request until one is done");
    }

    return result;
}

/**
 * bodySizeLeft
 *
 * Report on the number of bytes of body content that we
 * know are yet to be read on this connection.
 */
int64_t
ConnStateData::bodySizeLeft()
{
    // XXX: this logic will not work for chunked requests with unknown sizes

    if (bodyPipe != NULL)
        return bodyPipe->unproducedSize();

    return 0;
}

/**
 * Attempt to parse one or more requests from the input buffer.
 * If a request is successfully parsed, even if the next request
 * is only partially parsed, it will return TRUE.
 * do_next_read is updated to indicate whether a read should be
 * scheduled.
 */
static bool
clientParseRequest(ConnStateData * conn, bool &do_next_read)
{
    HttpRequestMethod method;
    ClientSocketContext *context;
    bool parsed_req = false;
    HttpVersion http_ver;
    HttpParser hp;

    debugs(33, 5, "clientParseRequest: FD " << conn->fd << ": attempting to parse");

    while (conn->in.notYetUsed > 0 && conn->bodySizeLeft() == 0) {
        connStripBufferWhitespace (conn);

        /* Don't try to parse if the buffer is empty */

        if (conn->in.notYetUsed == 0)
            break;

        /* Limit the number of concurrent requests to 2 */

        if (!connOkToAddRequest(conn)) {
            break;
        }

        /* Should not be needed anymore */
        /* Terminate the string */
        conn->in.buf[conn->in.notYetUsed] = '\0';

        /* Begin the parsing */
        HttpParserInit(&hp, conn->in.buf, conn->in.notYetUsed);

        /* Process request */
        PROF_start(parseHttpRequest);

        context = parseHttpRequest(conn, &hp, &method, &http_ver);

        PROF_stop(parseHttpRequest);

        /* partial or incomplete request */
        if (!context) {

            if (!connKeepReadingIncompleteRequest(conn))
                connCancelIncompleteRequests(conn);

            break;
        }

        /* status -1 or 1 */
        if (context) {
            debugs(33, 5, "clientParseRequest: FD " << conn->fd << ": parsed a request");
            commSetTimeout(conn->fd, Config.Timeout.lifetime, clientLifetimeTimeout,
                           context->http);

            clientProcessRequest(conn, &hp, context, method, http_ver);

            parsed_req = true;

            if (context->mayUseConnection()) {
                debugs(33, 3, "clientParseRequest: Not reading, as this request may need the connection");
                do_next_read = 0;
                break;
            }

            if (!conn->flags.readMoreRequests) {
                conn->flags.readMoreRequests = true;
                break;
            }

            continue;		/* while offset > 0 && conn->bodySizeLeft() == 0 */
        }
    }				/* while offset > 0 && conn->bodySizeLeft() == 0 */

    /* XXX where to 'finish' the parsing pass? */

    return parsed_req;
}

void
ConnStateData::clientReadRequest(const CommIoCbParams &io)
{
    debugs(33,5,HERE << "clientReadRequest FD " << io.fd << " size " << io.size);
    Must(reading());
    reader = NULL;
    bool do_next_read = 1; /* the default _is_ to read data! - adrian */

    assert (io.fd == fd);

    /* Bail out quickly on COMM_ERR_CLOSING - close handlers will tidy up */

    if (io.flag == COMM_ERR_CLOSING) {
        debugs(33,5, HERE  << " FD " << fd << " closing Bailout.");
        return;
    }

    /*
     * Don't reset the timeout value here.  The timeout value will be
     * set to Config.Timeout.request by httpAccept() and
     * clientWriteComplete(), and should apply to the request as a
     * whole, not individual read() calls.  Plus, it breaks our
     * lame half-close detection
     */
    if (connReadWasError(io.flag, io.size, io.xerrno)) {
        comm_close(fd);
        return;
    }

    if (io.flag == COMM_OK) {
        if (io.size > 0) {
            kb_incr(&statCounter.client_http.kbytes_in, io.size);

            handleReadData(io.buf, io.size);

            /* The above may close the connection under our feets */
            if (!isOpen())
                return;

        } else if (io.size == 0) {
            debugs(33, 5, "clientReadRequest: FD " << fd << " closed?");

            if (connFinishedWithConn(io.size)) {
                comm_close(fd);
                return;
            }

            /* It might be half-closed, we can't tell */
            fd_table[fd].flags.socket_eof = 1;

            commMarkHalfClosed(fd);

            do_next_read = 0;

            fd_note(fd, "half-closed");

            /* There is one more close check at the end, to detect aborted
             * (partial) requests. At this point we can't tell if the request
             * is partial.
             */
            /* Continue to process previously read data */
        }
    }

    /* Process next request */
    if (getConcurrentRequestCount() == 0)
        fd_note(fd, "Reading next request");

    if (! clientParseRequest(this, do_next_read)) {
        if (!isOpen())
            return;
        /*
         * If the client here is half closed and we failed
         * to parse a request, close the connection.
         * The above check with connFinishedWithConn() only
         * succeeds _if_ the buffer is empty which it won't
         * be if we have an incomplete request.
         * XXX: This duplicates ClientSocketContext::keepaliveNextRequest
         */
        if (getConcurrentRequestCount() == 0 && commIsHalfClosed(fd)) {
            debugs(33, 5, "clientReadRequest: FD " << fd << ": half-closed connection, no completed request parsed, connection closing.");
            comm_close(fd);
            return;
        }
    }

    if (!isOpen())
        return;

    clientAfterReadingRequests(do_next_read);
}

/**
 * called when new request data has been read from the socket
 */
void
ConnStateData::handleReadData(char *buf, size_t size)
{
    char *current_buf = in.addressToReadInto();

    if (buf != current_buf)
        xmemmove(current_buf, buf, size);

    in.notYetUsed += size;

    in.buf[in.notYetUsed] = '\0'; /* Terminate the string */

    // if we are reading a body, stuff data into the body pipe
    if (bodyPipe != NULL)
        handleRequestBodyData();
}

/**
 * called when new request body data has been buffered in in.buf
 * may close the connection if we were closing and piped everything out
 */
bool
ConnStateData::handleRequestBodyData()
{
    assert(bodyPipe != NULL);

    size_t putSize = 0;

#if FUTURE_CODE_TO_SUPPORT_CHUNKED_REQUESTS
    // The code below works, in principle, but we cannot do dechunking
    // on-the-fly because that would mean sending chunked requests to
    // the next hop. Squid lacks logic to determine which servers can
    // receive chunk requests. Squid v3.0 code cannot even handle chunked
    // responses which we may encourage by sending chunked requests.
    // The error generation code probably needs more work.
    if (in.bodyParser) { // chunked body
        debugs(33,5, HERE << "handling chunked request body for FD " << fd);
        bool malformedChunks = false;

        MemBuf raw; // ChunkedCodingParser only works with MemBufs
        raw.init(in.notYetUsed, in.notYetUsed);
        raw.append(in.buf, in.notYetUsed);
        try { // the parser will throw on errors
            const mb_size_t wasContentSize = raw.contentSize();
            BodyPipeCheckout bpc(*bodyPipe);
            const bool parsed = in.bodyParser->parse(&raw, &bpc.buf);
            bpc.checkIn();
            putSize = wasContentSize - raw.contentSize();

            if (parsed) {
                stopProducingFor(bodyPipe, true); // this makes bodySize known
            } else {
                // parser needy state must imply body pipe needy state
                if (in.bodyParser->needsMoreData() &&
                        !bodyPipe->mayNeedMoreData())
                    malformedChunks = true;
                // XXX: if bodyParser->needsMoreSpace, how can we guarantee it?
            }
        } catch (...) { // XXX: be more specific
            malformedChunks = true;
        }

        if (malformedChunks) {
            if (bodyPipe != NULL)
                stopProducingFor(bodyPipe, false);

            ClientSocketContext::Pointer context = getCurrentContext();
            if (!context->http->out.offset) {
                clientStreamNode *node = context->getClientReplyContext();
                clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
                assert (repContext);
                repContext->setReplyToError(ERR_INVALID_REQ, HTTP_BAD_REQUEST,
                                            METHOD_NONE, NULL, &peer.sin_addr,
                                            NULL, NULL, NULL);
                context->pullData();
            }
            flags.readMoreRequests = false;
            return; // XXX: is that sufficient to generate an error?
        }
    } else // identity encoding
#endif
    {
        debugs(33,5, HERE << "handling plain request body for FD " << fd);
        putSize = bodyPipe->putMoreData(in.buf, in.notYetUsed);
        if (!bodyPipe->mayNeedMoreData()) {
            // BodyPipe will clear us automagically when we produced everything
            bodyPipe = NULL;
        }
    }

    if (putSize > 0)
        connNoteUseOfBuffer(this, putSize);

    if (!bodyPipe) {
        debugs(33,5, HERE << "produced entire request body for FD " << fd);

        if (closing()) {
            /* we've finished reading like good clients,
             * now do the close that initiateClose initiated.
             *
             * XXX: do we have to close? why not check keepalive et.
             *
             * XXX: To support chunked requests safely, we need to handle
             * the case of an endless request. This if-statement does not,
             * because mayNeedMoreData is true if request size is not known.
             */
            comm_close(fd);
            return false;
        }
    }
    return true;
}

void
ConnStateData::noteMoreBodySpaceAvailable(BodyPipe::Pointer )
{
    if (!handleRequestBodyData())
        return;

    // too late to read more body
    if (!isOpen() || closing())
        return;

    readSomeData();
}

void
ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer )
{
    if (!closing())
        startClosing("body consumer aborted");
}

/** general lifetime handler for HTTP requests */
void
ConnStateData::requestTimeout(const CommTimeoutCbParams &io)
{
#if THIS_CONFUSES_PERSISTENT_CONNECTION_AWARE_BROWSERS_AND_USERS
    debugs(33, 3, "requestTimeout: FD " << io.fd << ": lifetime is expired.");

    if (COMMIO_FD_WRITECB(io.fd)->active) {
        /* FIXME: If this code is reinstated, check the conn counters,
         * not the fd table state
         */
        /*
         * Some data has been sent to the client, just close the FD
         */
        comm_close(io.fd);
    } else if (nrequests) {
        /*
         * assume its a persistent connection; just close it
         */
        comm_close(io.fd);
    } else {
        /*
         * Generate an error
         */
        ClientHttpRequest **H;
        clientStreamNode *node;
        ClientHttpRequest *http =
            parseHttpRequestAbort(this, "error:Connection%20lifetime%20expired");
        node = http->client_stream.tail->prev->data;
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_LIFETIME_EXP,
                                    HTTP_REQUEST_TIMEOUT, METHOD_NONE, "N/A", &peer.sin_addr,
                                    NULL, NULL, NULL);
        /* No requests can be outstanded */
        assert(chr == NULL);
        /* add to the client request queue */

        for (H = &chr; *H; H = &(*H)->next);
        *H = http;

        clientStreamRead(http->client_stream.tail->data, http, 0,
                         HTTP_REQBUF_SZ, context->reqbuf);

        /*
         * if we don't close() here, we still need a timeout handler!
         */
        typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                          TimeoutDialer, this, ConnStateData::requestTimeout);
        commSetTimeout(io.fd, 30, timeoutCall);

        /*
         * Aha, but we don't want a read handler!
         */
        commSetSelect(io.fd, COMM_SELECT_READ, NULL, NULL, 0);
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
    debugs(33, 3, "requestTimeout: FD " << io.fd << ": lifetime is expired.");

    comm_close(io.fd);

#endif
}



static void
clientLifetimeTimeout(int fd, void *data)
{
    ClientHttpRequest *http = (ClientHttpRequest *)data;
    debugs(33, 1, "WARNING: Closing client " << http->getConn()->peer << " connection due to lifetime timeout");
    debugs(33, 1, "\t" << http->uri);
    comm_close(fd);
}

static bool
okToAccept()
{
    static time_t last_warn = 0;

    if (fdNFree() >= RESERVED_FD)
        return true;

    if (last_warn + 15 < squid_curtime) {
        debugs(33, 0, HERE << "WARNING! Your cache is running out of filedescriptors");
        last_warn = squid_curtime;
    }

    return false;
}

ConnStateData *
connStateCreate(const IpAddress &peer, const IpAddress &me, int fd, http_port_list *port)
{
    ConnStateData *result = new ConnStateData;

    result->peer = peer;
    result->log_addr = peer;
    result->log_addr.ApplyMask(Config.Addrs.client_netmask);
    result->me = me;
    result->fd = fd;
    result->in.buf = (char *)memAllocBuf(CLIENT_REQ_BUF_SZ, &result->in.allocatedSize);
    result->port = cbdataReference(port);

    if (port->intercepted || port->spoof_client_ip) {
        IpAddress client, dst;

        if (IpInterceptor.NatLookup(fd, me, peer, client, dst) == 0) {
            result->me = client;
            result->peer = dst;
            result->transparent(true);
        }
    }

    if (port->disable_pmtu_discovery != DISABLE_PMTU_OFF &&
            (result->transparent() || port->disable_pmtu_discovery == DISABLE_PMTU_ALWAYS)) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
        int i = IP_PMTUDISC_DONT;
        setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &i, sizeof i);

#else

        static int reported = 0;

        if (!reported) {
            debugs(33, 1, "Notice: httpd_accel_no_pmtu_disc not supported on your platform");
            reported = 1;
        }

#endif

    }

    result->flags.readMoreRequests = true;
    return result;
}

/** Handle a new connection on HTTP socket. */
void
httpAccept(int sock, int newfd, ConnectionDetail *details,
           comm_err_t flag, int xerrno, void *data)
{
    http_port_list *s = (http_port_list *)data;
    ConnStateData *connState = NULL;

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    if (!okToAccept())
        AcceptLimiter::Instance().defer (sock, httpAccept, data);
    else
        /* kick off another one for later */
        comm_accept(sock, httpAccept, data);

    if (flag != COMM_OK) {
        debugs(33, 1, "httpAccept: FD " << sock << ": accept failure: " << xstrerr(xerrno));
        return;
    }

    debugs(33, 4, "httpAccept: FD " << newfd << ": accepted");
    fd_note(newfd, "client http connect");
    connState = connStateCreate(&details->peer, &details->me, newfd, s);

    typedef CommCbMemFunT<ConnStateData, CommCloseCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5,
                                          Dialer, connState, ConnStateData::connStateClosed);
    comm_add_close_handler(newfd, call);

    if (Config.onoff.log_fqdn)
        fqdncache_gethostbyaddr(details->peer, FQDN_LOOKUP_IF_MISS);

    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, connState, ConnStateData::requestTimeout);
    commSetTimeout(newfd, Config.Timeout.read, timeoutCall);

#if USE_IDENT
    if (Ident::TheConfig.identLookup) {
        ACLFilledChecklist identChecklist(Ident::TheConfig.identLookup, NULL, NULL);
        identChecklist.src_addr = details->peer;
        identChecklist.my_addr = details->me;
        if (identChecklist.fastCheck())
            Ident::Start(details->me, details->peer, clientIdentDone, connState);
    }
#endif

    if (s->tcp_keepalive.enabled) {
        commSetTcpKeepalive(newfd, s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);
    }

    connState->readSomeData();

    clientdbEstablished(details->peer, 1);

    incoming_sockets_accepted++;
}

#if USE_SSL

/** Create SSL connection structure and update fd_table */
static SSL *
httpsCreate(int newfd, ConnectionDetail *details, SSL_CTX *sslContext)
{
    SSL *ssl = SSL_new(sslContext);

    if (!ssl) {
        const int ssl_error = ERR_get_error();
        debugs(83, 1, "httpsAccept: Error allocating handle: " << ERR_error_string(ssl_error, NULL)  );
        comm_close(newfd);
        return NULL;
    }

    SSL_set_fd(ssl, newfd);
    fd_table[newfd].ssl = ssl;
    fd_table[newfd].read_method = &ssl_read_method;
    fd_table[newfd].write_method = &ssl_write_method;

    debugs(33, 5, "httpsCreate: will negotate SSL on FD " << newfd);
    fd_note(newfd, "client https start");

    return ssl;
}

/** negotiate an SSL connection */
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

        case SSL_ERROR_SYSCALL:

            if (ret == 0) {
                debugs(83, 2, "clientNegotiateSSL: Error negotiating SSL connection on FD " << fd << ": Aborted by client");
                comm_close(fd);
                return;
            } else {
                int hard = 1;

                if (errno == ECONNRESET)
                    hard = 0;

                debugs(83, hard ? 1 : 2, "clientNegotiateSSL: Error negotiating SSL connection on FD " <<
                       fd << ": " << strerror(errno) << " (" << errno << ")");

                comm_close(fd);

                return;
            }

        case SSL_ERROR_ZERO_RETURN:
            debugs(83, 1, "clientNegotiateSSL: Error negotiating SSL connection on FD " << fd << ": Closed by client");
            comm_close(fd);
            return;

        default:
            debugs(83, 1, "clientNegotiateSSL: Error negotiating SSL connection on FD " <<
                   fd << ": " << ERR_error_string(ERR_get_error(), NULL) <<
                   " (" << ssl_error << "/" << ret << ")");
            comm_close(fd);
            return;
        }

        /* NOTREACHED */
    }

    if (SSL_session_reused(ssl)) {
        debugs(83, 2, "clientNegotiateSSL: Session " << SSL_get_session(ssl) <<
               " reused on FD " << fd << " (" << fd_table[fd].ipaddr << ":" << (int)fd_table[fd].remote_port << ")");
    } else {
        if (do_debug(83, 4)) {
            /* Write out the SSL session details.. actually the call below, but
             * OpenSSL headers do strange typecasts confusing GCC.. */
            /* PEM_write_SSL_SESSION(debug_log, SSL_get_session(ssl)); */
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x00908000L
            PEM_ASN1_write((i2d_of_void *)i2d_SSL_SESSION, PEM_STRING_SSL_SESSION, debug_log, (char *)SSL_get_session(ssl), NULL,NULL,0,NULL,NULL);

#elif (ALLOW_ALWAYS_SSL_SESSION_DETAIL == 1)

            /* When using gcc 3.3.x and OpenSSL 0.9.7x sometimes a compile error can occur here.
            * This is caused by an unpredicatble gcc behaviour on a cast of the first argument
            * of PEM_ASN1_write(). For this reason this code section is disabled. To enable it,
            * define ALLOW_ALWAYS_SSL_SESSION_DETAIL=1.
            * Because there are two possible usable cast, if you get an error here, try the other
            * commented line. */

            PEM_ASN1_write((int(*)())i2d_SSL_SESSION, PEM_STRING_SSL_SESSION, debug_log, (char *)SSL_get_session(ssl), NULL,NULL,0,NULL,NULL);
            /* PEM_ASN1_write((int(*)(...))i2d_SSL_SESSION, PEM_STRING_SSL_SESSION, debug_log, (char *)SSL_get_session(ssl), NULL,NULL,0,NULL,NULL); */

#else

            debugs(83, 4, "With " OPENSSL_VERSION_TEXT ", session details are available only defining ALLOW_ALWAYS_SSL_SESSION_DETAIL=1 in the source." );

#endif
            /* Note: This does not automatically fflush the log file.. */
        }

        debugs(83, 2, "clientNegotiateSSL: New session " <<
               SSL_get_session(ssl) << " on FD " << fd << " (" <<
               fd_table[fd].ipaddr << ":" << (int)fd_table[fd].remote_port <<
               ")");
    }

    debugs(83, 3, "clientNegotiateSSL: FD " << fd << " negotiated cipher " <<
           SSL_get_cipher(ssl));

    client_cert = SSL_get_peer_certificate(ssl);

    if (client_cert != NULL) {
        debugs(83, 3, "clientNegotiateSSL: FD " << fd <<
               " client certificate: subject: " <<
               X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0));

        debugs(83, 3, "clientNegotiateSSL: FD " << fd <<
               " client certificate: issuer: " <<
               X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0));


        X509_free(client_cert);
    } else {
        debugs(83, 5, "clientNegotiateSSL: FD " << fd <<
               " has no certificate.");
    }

    conn->readSomeData();
}

/** handle a new HTTPS connection */
static void
httpsAccept(int sock, int newfd, ConnectionDetail *details,
            comm_err_t flag, int xerrno, void *data)
{
    https_port_list *s = (https_port_list *)data;
    SSL_CTX *sslContext = s->staticSslContext.get();

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    if (!okToAccept())
        AcceptLimiter::Instance().defer (sock, httpsAccept, data);
    else
        /* kick off another one for later */
        comm_accept(sock, httpsAccept, data);

    if (flag != COMM_OK) {
        errno = xerrno;
        debugs(33, 1, "httpsAccept: FD " << sock << ": accept failure: " << xstrerr(xerrno));
        return;
    }

    SSL *ssl = NULL;
    if (!(ssl = httpsCreate(newfd, details, sslContext)))
        return;

    debugs(33, 5, "httpsAccept: FD " << newfd << " accepted, starting SSL negotiation.");
    fd_note(newfd, "client https connect");
    ConnStateData *connState = connStateCreate(details->peer, details->me,
                               newfd, &s->http);
    typedef CommCbMemFunT<ConnStateData, CommCloseCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5,
                                          Dialer, connState, ConnStateData::connStateClosed);
    comm_add_close_handler(newfd, call);

    if (Config.onoff.log_fqdn)
        fqdncache_gethostbyaddr(details->peer, FQDN_LOOKUP_IF_MISS);

    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, connState, ConnStateData::requestTimeout);
    commSetTimeout(newfd, Config.Timeout.request, timeoutCall);

#if USE_IDENT
    if (Ident::TheConfig.identLookup) {
        ACLFilledChecklist identChecklist(Ident::TheConfig.identLookup, NULL, NULL);
        identChecklist.src_addr = details->peer;
        identChecklist.my_addr = details->me;
        if (identChecklist.fastCheck())
            Ident::Start(details->me, details->peer, clientIdentDone, connState);
    }

#endif

    if (s->http.tcp_keepalive.enabled) {
        commSetTcpKeepalive(newfd, s->http.tcp_keepalive.idle, s->http.tcp_keepalive.interval, s->http.tcp_keepalive.timeout);
    }

    commSetSelect(newfd, COMM_SELECT_READ, clientNegotiateSSL, connState, 0);

    clientdbEstablished(details->peer, 1);

    incoming_sockets_accepted++;
}

void
ConnStateData::sslCrtdHandleReplyWrapper(void *data, char *reply)
{
    ConnStateData * state_data = (ConnStateData *)(data);
    state_data->sslCrtdHandleReply(reply);
}

void
ConnStateData::sslCrtdHandleReply(const char * reply)
{
    if (!reply) {
        debugs(1, 1, HERE << "\"ssl_crtd\" helper return <NULL> reply");
    } else {
        Ssl::CrtdMessage reply_message;
        if (reply_message.parse(reply, strlen(reply)) != Ssl::CrtdMessage::OK) {
            debugs(33, 5, HERE << "Reply from ssl_crtd for " << sslHostName << " is incorrect");
        } else {
            if (reply_message.getCode() != "OK") {
                debugs(33, 5, HERE << "Certificate for " << sslHostName << " cannot be generated. ssl_crtd response: " << reply_message.getBody());
            } else {
                debugs(33, 5, HERE << "Certificate for " << sslHostName << " was successfully recieved from ssl_crtd");
                getSslContextDone(Ssl::generateSslContextUsingPkeyAndCertFromMemory(reply_message.getBody().c_str()), true);
                return;
            }
        }
    }
    getSslContextDone(NULL);
}

bool
ConnStateData::getSslContextStart()
{
    char const * host = sslHostName.termedBuf();
    if (port->generateHostCertificates && host && strcmp(host, "") != 0) {
        debugs(33, 5, HERE << "Finding SSL certificate for " << host << " in cache");
        Ssl::LocalContextStorage & ssl_ctx_cache(Ssl::TheGlobalContextStorage.getLocalStorage(port->s));
        SSL_CTX * dynCtx = ssl_ctx_cache.find(host);
        if (dynCtx) {
            debugs(33, 5, HERE << "SSL certificate for " << host << " have found in cache");
            if (Ssl::verifySslCertificateDate(dynCtx)) {
                debugs(33, 5, HERE << "Cached SSL certificate for " << host << " is valid");
                return getSslContextDone(dynCtx);
            } else {
                debugs(33, 5, HERE << "Cached SSL certificate for " << host << " is out of date. Delete this certificate from cache");
                ssl_ctx_cache.remove(host);
            }
        } else {
            debugs(33, 5, HERE << "SSL certificate for " << host << " haven't found in cache");
        }

#ifdef USE_SSL_CRTD
        debugs(33, 5, HERE << "Generating SSL certificate for " << host << " using ssl_crtd.");
        Ssl::CrtdMessage request_message;
        request_message.setCode(Ssl::CrtdMessage::code_new_certificate);
        Ssl::CrtdMessage::BodyParams map;
        map.insert(std::make_pair(Ssl::CrtdMessage::param_host, host));
        std::string bufferToWrite;
        Ssl::writeCertAndPrivateKeyToMemory(port->signingCert, port->signPkey, bufferToWrite);
        request_message.composeBody(map, bufferToWrite);
        Ssl::Helper::GetInstance()->sslSubmit(request_message, sslCrtdHandleReplyWrapper, this);
        return true;
#else
        debugs(33, 5, HERE << "Generating SSL certificate for " << host);
        dynCtx = Ssl::generateSslContext(host, port->signingCert, port->signPkey);
        return getSslContextDone(dynCtx, true);
#endif //USE_SSL_CRTD
    }
    return getSslContextDone(NULL);
}

bool
ConnStateData::getSslContextDone(SSL_CTX * sslContext, bool isNew)
{
    // Try to add generated ssl context to storage.
    if (port->generateHostCertificates && isNew) {
        Ssl::LocalContextStorage & ssl_ctx_cache(Ssl::TheGlobalContextStorage.getLocalStorage(port->s));
        if (sslContext && sslHostName != "") {
            if (!ssl_ctx_cache.add(sslHostName.termedBuf(), sslContext)) {
                // If it is not in storage delete after using. Else storage deleted it.
                fd_table[fd].dynamicSslContext = sslContext;
            }
        } else {
            debugs(33, 2, HERE << "Failed to generate SSL cert for " << sslHostName);
        }
    }

    // If generated ssl context = NULL, try to use static ssl context.
    if (!sslContext) {
        if (!port->staticSslContext) {
            debugs(83, 1, "Closing SSL FD " << fd << " as lacking SSL context");
            comm_close(fd);
            return false;
        } else {
            debugs(33, 5, HERE << "Using static ssl context.");
            sslContext = port->staticSslContext.get();
        }
    }

    // fake a ConnectionDetail object; XXX: make ConnState a ConnectionDetail?
    ConnectionDetail detail;
    detail.me = me;
    detail.peer = peer;

    SSL *ssl = NULL;
    if (!(ssl = httpsCreate(fd, &detail, sslContext)))
        return false;

    // commSetTimeout() was called for this request before we switched.

    // Disable the client read handler until peer selection is complete
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);

    commSetSelect(fd, COMM_SELECT_READ, clientNegotiateSSL, this, 0);

    switchedToHttps_ = true;
    return true;
}

bool
ConnStateData::switchToHttps(const char *host)
{
    assert(!switchedToHttps_);

    sslHostName = host;

    //HTTPMSGLOCK(currentobject->http->request);
    assert(areAllContextsForThisConnection());
    freeAllContexts();
    //currentobject->connIsFinished();
    // We are going to read new request
    flags.readMoreRequests = true;
    debugs(33, 5, HERE << "converting FD " << fd << " to SSL");

    return getSslContextStart();
}

#endif /* USE_SSL */


static void
clientHttpConnectionsOpen(void)
{
    http_port_list *s = NULL;
    int fd = -1;
#if USE_SSL
    int bumpCount = 0; // counts http_ports with sslBump option
#endif

    for (s = Config.Sockaddr.http; s; s = s->next) {
        if (MAXHTTPPORTS == NHttpSockets) {
            debugs(1, 1, "WARNING: You have too many 'http_port' lines.");
            debugs(1, 1, "         The limit is " << MAXHTTPPORTS);
            continue;
        }

#if USE_SSL
        if (s->sslBump &&
                !s->staticSslContext && !s->generateHostCertificates) {
            debugs(1, 1, "Will not bump SSL at http_port " <<
                   s->http.s << " due to SSL initialization failure.");
            s->sslBump = 0;
        }
        if (s->sslBump) {
            ++bumpCount;
            // Create ssl_ctx cache for this port.
            Ssl::TheGlobalContextStorage.addLocalStorage(s->s, s->dynamicCertMemCacheSize == std::numeric_limits<size_t>::max() ? 4194304 : s->dynamicCertMemCacheSize);
        }
#endif
#if USE_SSL_CRTD
        Ssl::Helper::GetInstance();
#endif //USE_SSL_CRTD

        enter_suid();

        if (s->spoof_client_ip) {
            fd = comm_open_listener(SOCK_STREAM, IPPROTO_TCP, s->s, (COMM_NONBLOCKING|COMM_TRANSPARENT), "HTTP Socket");
        } else {
            fd = comm_open_listener(SOCK_STREAM, IPPROTO_TCP, s->s, COMM_NONBLOCKING, "HTTP Socket");
        }

        leave_suid();

        if (fd < 0)
            continue;

        comm_listen(fd);

        comm_accept(fd, httpAccept, s);

        debugs(1, 1, "Accepting " <<
               (s->intercepted ? " intercepted" : "") <<
               (s->spoof_client_ip ? " spoofing" : "") <<
               (s->sslBump ? " bumpy" : "") <<
               (s->accel ? " accelerated" : "")
               << " HTTP connections at " << s->s
               << ", FD " << fd << "." );

        HttpSockets[NHttpSockets++] = fd;
    }

#if USE_SSL
    if (bumpCount && !Config.accessList.ssl_bump)
        debugs(33, 1, "WARNING: http_port(s) with SslBump found, but no " <<
               std::endl << "\tssl_bump ACL configured. No requests will be " <<
               "bumped.");
#endif
}

#if USE_SSL
static void
clientHttpsConnectionsOpen(void)
{
    https_port_list *s;
    int fd;

    for (s = Config.Sockaddr.https; s; s = (https_port_list *)s->http.next) {
        if (MAXHTTPPORTS == NHttpSockets) {
            debugs(1, 1, "Ignoring 'https_port' lines exceeding the limit.");
            debugs(1, 1, "The limit is " << MAXHTTPPORTS << " HTTPS ports.");
            continue;
        }

        if (!s->staticSslContext) {
            debugs(1, 1, "Ignoring https_port " << s->http.s <<
                   " due to SSL initialization failure.");
            continue;
        }

        enter_suid();
        fd = comm_open_listener(SOCK_STREAM,
                                IPPROTO_TCP,
                                s->http.s,
                                COMM_NONBLOCKING, "HTTPS Socket");
        leave_suid();

        if (fd < 0)
            continue;

        comm_listen(fd);

        comm_accept(fd, httpsAccept, s);

        debugs(1, 1, "Accepting HTTPS connections at " << s->http.s << ", FD " << fd << ".");

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
            debugs(1, 1, "FD " << HttpSockets[i] <<
                   " Closing HTTP connection");
            comm_close(HttpSockets[i]);
            HttpSockets[i] = -1;
        }
    }

    NHttpSockets = 0;
}

int
varyEvaluateMatch(StoreEntry * entry, HttpRequest * request)
{
    const char *vary = request->vary_headers;
    int has_vary = entry->getReply()->header.has(HDR_VARY);
#if X_ACCELERATOR_VARY

    has_vary |=
        entry->getReply()->header.has(HDR_X_ACCELERATOR_VARY);
#endif

    if (!has_vary || !entry->mem_obj->vary_headers) {
        if (vary) {
            /* Oops... something odd is going on here.. */
            debugs(33, 1, "varyEvaluateMatch: Oops. Not a Vary object on second attempt, '" <<
                   entry->mem_obj->url << "' '" << vary << "'");
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
            debugs(33, 1, "varyEvaluateMatch: Oops. Not a Vary match on second attempt, '" <<
                   entry->mem_obj->url << "' '" << vary << "'");
            return VARY_CANCEL;
        }
    }
}

ACLFilledChecklist *
clientAclChecklistCreate(const acl_access * acl, ClientHttpRequest * http)
{
    ConnStateData * conn = http->getConn();
    ACLFilledChecklist *ch = new ACLFilledChecklist(acl, http->request,
            cbdataReferenceValid(conn) && conn != NULL ? conn->rfc931 : dash_str);

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

    if (conn != NULL)
        ch->conn(conn);	/* unreferenced in FilledCheckList.cc */

    return ch;
}

CBDATA_CLASS_INIT(ConnStateData);

ConnStateData::ConnStateData() :AsyncJob("ConnStateData"), transparent_ (false), closing_ (false), switchedToHttps_(false)
{
    pinning.fd = -1;
    pinning.pinned = false;
    pinning.auth = false;
}

bool
ConnStateData::transparent() const
{
    return transparent_;
}

void
ConnStateData::transparent(bool const anInt)
{
    transparent_ = anInt;
}

bool
ConnStateData::reading() const
{
    return reader != NULL;
}

void
ConnStateData::stopReading()
{
    if (reading()) {
        comm_read_cancel(fd, reader);
        reader = NULL;
    }
}


BodyPipe::Pointer
ConnStateData::expectRequestBody(int64_t size)
{
    bodyPipe = new BodyPipe(this);
    bodyPipe->setBodySize(size);
    return bodyPipe;
}

bool
ConnStateData::closing() const
{
    return closing_;
}

/**
 * Called by ClientSocketContext to give the connection a chance to read
 * the entire body before closing the socket.
 */
void
ConnStateData::startClosing(const char *reason)
{
    debugs(33, 5, HERE << "startClosing " << this << " for " << reason);
    assert(!closing());
    closing_ = true;

    assert(bodyPipe != NULL);
    assert(bodySizeLeft() > 0);

    // We do not have to abort the body pipeline because we are going to
    // read the entire body anyway.
    // Perhaps an ICAP server wants to log the complete request.

    // If a consumer abort have caused this closing, we may get stuck
    // as nobody is consuming our data. Allow auto-consumption.
    bodyPipe->enableAutoConsumption();
}

void
ConnStateData::expectNoForwarding()
{
    if (bodyPipe != NULL) {
        debugs(33, 4, HERE << "no consumer for virgin body " << bodyPipe->status());
        bodyPipe->expectNoConsumption();
    }
}

// initialize dechunking state
void
ConnStateData::startDechunkingRequest(HttpParser *hp)
{
    debugs(33, 5, HERE << "start dechunking at " << HttpParserRequestLen(hp));
    assert(in.dechunkingState == chunkUnknown);
    assert(!in.bodyParser);
    in.bodyParser = new ChunkedCodingParser;
    in.chunkedSeen = HttpParserRequestLen(hp); // skip headers when dechunking
    in.chunked.init();  // TODO: should we have a smaller-than-default limit?
    in.dechunked.init();
    in.dechunkingState = chunkParsing;
}

// put parsed content into input buffer and clean up
void
ConnStateData::finishDechunkingRequest(HttpParser *hp)
{
    debugs(33, 5, HERE << "finish dechunking; content: " << in.dechunked.contentSize());

    assert(in.dechunkingState == chunkReady);

    const mb_size_t headerSize = HttpParserRequestLen(hp);

    // dechunking cannot make data bigger
    assert(headerSize + in.dechunked.contentSize() + in.chunked.contentSize()
           <= static_cast<mb_size_t>(in.notYetUsed));
    assert(in.notYetUsed <= in.allocatedSize);

    // copy dechunked content
    char *end = in.buf + headerSize;
    xmemmove(end, in.dechunked.content(), in.dechunked.contentSize());
    end += in.dechunked.contentSize();

    // copy post-chunks leftovers, if any, caused by request pipelining?
    if (in.chunked.contentSize()) {
        xmemmove(end, in.chunked.content(), in.chunked.contentSize());
        end += in.chunked.contentSize();
    }

    in.notYetUsed = end - in.buf;

    cleanDechunkingRequest();
}

/// cleanup dechunking state, get ready for the next request
void
ConnStateData::cleanDechunkingRequest()
{
    if (in.dechunkingState > chunkNone) {
        delete in.bodyParser;
        in.bodyParser = NULL;
        in.chunked.clean();
        in.dechunked.clean();
    }
    in.dechunkingState = chunkUnknown;
}

// parse newly read request chunks and buffer them for finishDechunkingRequest
// returns true iff needs more data
bool
ConnStateData::parseRequestChunks(HttpParser *)
{
    debugs(33,5, HERE << "parsing chunked request body at " <<
           in.chunkedSeen << " < " << in.notYetUsed);
    assert(in.bodyParser);
    assert(in.dechunkingState == chunkParsing);

    assert(in.chunkedSeen <= in.notYetUsed);
    const mb_size_t fresh = in.notYetUsed - in.chunkedSeen;

    // be safe: count some chunked coding metadata towards the total body size
    if (fresh + in.dechunked.contentSize() > Config.maxChunkedRequestBodySize) {
        debugs(33,3, HERE << "chunked body (" << fresh << " + " <<
               in.dechunked.contentSize() << " may exceed " <<
               "chunked_request_body_max_size=" <<
               Config.maxChunkedRequestBodySize);
        in.dechunkingState = chunkError;
        return false;
    }

    if (fresh > in.chunked.potentialSpaceSize()) {
        // should not happen if Config.maxChunkedRequestBodySize is reasonable
        debugs(33,1, HERE << "request_body_max_size exceeds chunked buffer " <<
               "size: " << fresh << " + " << in.chunked.contentSize() << " > " <<
               in.chunked.potentialSpaceSize() << " with " <<
               "chunked_request_body_max_size=" <<
               Config.maxChunkedRequestBodySize);
        in.dechunkingState = chunkError;
        return false;
    }
    in.chunked.append(in.buf + in.chunkedSeen, fresh);
    in.chunkedSeen += fresh;

    try { // the parser will throw on errors
        if (in.bodyParser->parse(&in.chunked, &in.dechunked))
            in.dechunkingState = chunkReady; // successfully parsed all chunks
        else
            return true; // need more, keep the same state
    } catch (...) {
        debugs(33,3, HERE << "chunk parsing error");
        in.dechunkingState = chunkError;
    }
    return false; // error, unsupported, or done
}

char *
ConnStateData::In::addressToReadInto() const
{
    return buf + notYetUsed;
}

ConnStateData::In::In() : bodyParser(NULL),
        buf (NULL), notYetUsed (0), allocatedSize (0),
        dechunkingState(ConnStateData::chunkUnknown)
{}

ConnStateData::In::~In()
{
    if (allocatedSize)
        memFreeBuf(allocatedSize, buf);
    if (bodyParser)
        delete bodyParser; // TODO: pool
}

/* This is a comm call normally scheduled by comm_close() */
void
ConnStateData::clientPinnedConnectionClosed(const CommCloseCbParams &io)
{
    pinning.fd = -1;
    if (pinning.peer) {
        cbdataReferenceDone(pinning.peer);
    }
    safe_free(pinning.host);
    /* NOTE: pinning.pinned should be kept. This combined with fd == -1 at the end of a request indicates that the host
     * connection has gone away */
}

void ConnStateData::pinConnection(int pinning_fd, HttpRequest *request, struct peer *aPeer, bool auth)
{
    fde *f;
    char desc[FD_DESC_SZ];

    if (pinning.fd == pinning_fd)
        return;
    else if (pinning.fd != -1)
        comm_close(pinning.fd);

    if (pinning.host)
        safe_free(pinning.host);

    pinning.fd = pinning_fd;
    pinning.host = xstrdup(request->GetHost());
    pinning.port = request->port;
    pinning.pinned = true;
    if (pinning.peer)
        cbdataReferenceDone(pinning.peer);
    if (aPeer)
        pinning.peer = cbdataReference(aPeer);
    pinning.auth = auth;
    f = &fd_table[fd];
    snprintf(desc, FD_DESC_SZ, "%s pinned connection for %s:%d (%d)",
             (auth || !aPeer) ? request->GetHost() : aPeer->name, f->ipaddr, (int) f->remote_port, fd);
    fd_note(pinning_fd, desc);

    typedef CommCbMemFunT<ConnStateData, CommCloseCbParams> Dialer;
    pinning.closeHandler = JobCallback(33, 5,
                                       Dialer, this, ConnStateData::clientPinnedConnectionClosed);
    comm_add_close_handler(pinning_fd, pinning.closeHandler);

}

int ConnStateData::validatePinnedConnection(HttpRequest *request, const struct peer *aPeer)
{
    bool valid = true;
    if (pinning.fd < 0)
        return -1;

    if (pinning.auth && request && strcasecmp(pinning.host, request->GetHost()) != 0) {
        valid = false;
    }
    if (request && pinning.port != request->port) {
        valid = false;
    }
    if (pinning.peer && !cbdataReferenceValid(pinning.peer)) {
        valid = false;
    }
    if (aPeer != pinning.peer) {
        valid = false;
    }

    if (!valid) {
        int pinning_fd=pinning.fd;
        /* The pinning info is not safe, remove any pinning info*/
        unpinConnection();

        /* also close the server side socket, we should not use it for invalid/unauthenticated
           requests...
         */
        comm_close(pinning_fd);
        return -1;
    }

    return pinning.fd;
}

void ConnStateData::unpinConnection()
{
    if (pinning.peer)
        cbdataReferenceDone(pinning.peer);

    if (pinning.closeHandler != NULL) {
        comm_remove_close_handler(pinning.fd, pinning.closeHandler);
        pinning.closeHandler = NULL;
    }
    pinning.fd = -1;
    safe_free(pinning.host);
}
