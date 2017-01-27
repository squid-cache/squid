/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

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
 * ConnStateData::kick() will then detect the presence of data in
 * the next ClientHttpRequest, and will send it, restablishing the
 * data flow.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "anyp/PortCfg.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "CachePeer.h"
#include "client_db.h"
#include "client_side.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "ClientRequestContext.h"
#include "clientStream.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/Read.h"
#include "comm/TcpAcceptor.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "fqdncache.h"
#include "FwdState.h"
#include "globals.h"
#include "helper.h"
#include "helper/Reply.h"
#include "http.h"
#include "http/one/RequestParser.h"
#include "http/one/TeChunkedParser.h"
#include "http/Stream.h"
#include "HttpHdrContRange.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ident/Config.h"
#include "ident/Ident.h"
#include "internal.h"
#include "ipc/FdNotes.h"
#include "ipc/StartListening.h"
#include "log/access_log.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mime_header.h"
#include "parser/Tokenizer.h"
#include "profiler/Profiler.h"
#include "rfc1738.h"
#include "security/NegotiationHistory.h"
#include "servers/forward.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"
#include "TimeOrTag.h"
#include "tools.h"
#include "URL.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "ClientInfo.h"
#endif
#if USE_OPENSSL
#include "ssl/bio.h"
#include "ssl/context_storage.h"
#include "ssl/gadgets.h"
#include "ssl/helper.h"
#include "ssl/ProxyCerts.h"
#include "ssl/ServerBump.h"
#include "ssl/support.h"
#endif

// for tvSubUsec() which should be in SquidTime.h
#include "util.h"

#include <climits>
#include <cmath>
#include <limits>

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

/// dials clientListenerConnectionOpened call
class ListeningStartedDialer: public CallDialer, public Ipc::StartListeningCb
{
public:
    typedef void (*Handler)(AnyP::PortCfgPointer &portCfg, const Ipc::FdNoteId note, const Subscription::Pointer &sub);
    ListeningStartedDialer(Handler aHandler, AnyP::PortCfgPointer &aPortCfg, const Ipc::FdNoteId note, const Subscription::Pointer &aSub):
        handler(aHandler), portCfg(aPortCfg), portTypeNote(note), sub(aSub) {}

    virtual void print(std::ostream &os) const {
        startPrint(os) <<
                       ", " << FdNote(portTypeNote) << " port=" << (void*)&portCfg << ')';
    }

    virtual bool canDial(AsyncCall &) const { return true; }
    virtual void dial(AsyncCall &) { (handler)(portCfg, portTypeNote, sub); }

public:
    Handler handler;

private:
    AnyP::PortCfgPointer portCfg;   ///< from HttpPortList
    Ipc::FdNoteId portTypeNote;    ///< Type of IPC socket being opened
    Subscription::Pointer sub; ///< The handler to be subscribed for this connetion listener
};

static void clientListenerConnectionOpened(AnyP::PortCfgPointer &s, const Ipc::FdNoteId portTypeNote, const Subscription::Pointer &sub);

static IOACB httpAccept;
#if USE_OPENSSL
static IOACB httpsAccept;
#endif
static CTCB clientLifetimeTimeout;
#if USE_IDENT
static IDCB clientIdentDone;
#endif
static int clientIsContentLengthValid(HttpRequest * r);
static int clientIsRequestBodyTooLargeForPolicy(int64_t bodyLength);

static void clientUpdateStatHistCounters(const LogTags &logType, int svc_time);
static void clientUpdateStatCounters(const LogTags &logType);
static void clientUpdateHierCounters(HierarchyLogEntry *);
static bool clientPingHasFinished(ping_data const *aPing);
void prepareLogWithRequestDetails(HttpRequest *, AccessLogEntry::Pointer &);
static void ClientSocketContextPushDeferredIfNeeded(Http::StreamPointer deferredRequest, ConnStateData * conn);

char *skipLeadingSpace(char *aString);

#if USE_IDENT
static void
clientIdentDone(const char *ident, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    xstrncpy(conn->clientConnection->rfc931, ident ? ident : dash_str, USER_IDENT_SZ);
}
#endif

void
clientUpdateStatCounters(const LogTags &logType)
{
    ++statCounter.client_http.requests;

    if (logType.isTcpHit())
        ++statCounter.client_http.hits;

    if (logType.oldType == LOG_TCP_HIT)
        ++statCounter.client_http.disk_hits;
    else if (logType.oldType == LOG_TCP_MEM_HIT)
        ++statCounter.client_http.mem_hits;
}

void
clientUpdateStatHistCounters(const LogTags &logType, int svc_time)
{
    statCounter.client_http.allSvcTime.count(svc_time);
    /**
     * The idea here is not to be complete, but to get service times
     * for only well-defined types.  For example, we don't include
     * LOG_TCP_REFRESH_FAIL because its not really a cache hit
     * (we *tried* to validate it, but failed).
     */

    switch (logType.oldType) {

    case LOG_TCP_REFRESH_UNMODIFIED:
        statCounter.client_http.nearHitSvcTime.count(svc_time);
        break;

    case LOG_TCP_INM_HIT:
    case LOG_TCP_IMS_HIT:
        statCounter.client_http.nearMissSvcTime.count(svc_time);
        break;

    case LOG_TCP_HIT:

    case LOG_TCP_MEM_HIT:

    case LOG_TCP_OFFLINE_HIT:
        statCounter.client_http.hitSvcTime.count(svc_time);
        break;

    case LOG_TCP_MISS:

    case LOG_TCP_CLIENT_REFRESH_MISS:
        statCounter.client_http.missSvcTime.count(svc_time);
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
        ++ statCounter.cd.times_used;
        break;
#endif

    case SIBLING_HIT:

    case PARENT_HIT:

    case FIRST_PARENT_MISS:

    case CLOSEST_PARENT_MISS:
        ++ statCounter.icp.times_used;
        i = &someEntry->ping;

        if (clientPingHasFinished(i))
            statCounter.icp.querySvcTime.count(tvSubUsec(i->start, i->stop));

        if (i->timeout)
            ++ statCounter.icp.query_timeouts;

        break;

    case CLOSEST_PARENT:

    case CLOSEST_DIRECT:
        ++ statCounter.netdb.times_used;

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
        ++ statCounter.client_http.errors;

    clientUpdateStatHistCounters(logType,
                                 tvSubMsec(al->cache.start_time, current_time));

    clientUpdateHierCounters(&request->hier);
}

void
prepareLogWithRequestDetails(HttpRequest * request, AccessLogEntry::Pointer &aLogEntry)
{
    assert(request);
    assert(aLogEntry != NULL);

    if (Config.onoff.log_mime_hdrs) {
        MemBuf mb;
        mb.init();
        request->header.packInto(&mb);
        //This is the request after adaptation or redirection
        aLogEntry->headers.adapted_request = xstrdup(mb.buf);

        // the virgin request is saved to aLogEntry->request
        if (aLogEntry->request) {
            mb.reset();
            aLogEntry->request->header.packInto(&mb);
            aLogEntry->headers.request = xstrdup(mb.buf);
        }

#if USE_ADAPTATION
        const Adaptation::History::Pointer ah = request->adaptLogHistory();
        if (ah != NULL) {
            mb.reset();
            ah->lastMeta.packInto(&mb);
            aLogEntry->adapt.last_meta = xstrdup(mb.buf);
        }
#endif

        mb.clean();
    }

#if ICAP_CLIENT
    const Adaptation::Icap::History::Pointer ih = request->icapHistory();
    if (ih != NULL)
        ih->processingTime(aLogEntry->icap.processingTime);
#endif

    aLogEntry->http.method = request->method;
    aLogEntry->http.version = request->http_ver;
    aLogEntry->hier = request->hier;
    aLogEntry->cache.extuser = request->extacl_user.termedBuf();

    // Adapted request, if any, inherits and then collects all the stats, but
    // the virgin request gets logged instead; copy the stats to log them.
    // TODO: avoid losses by keeping these stats in a shared history object?
    if (aLogEntry->request) {
        aLogEntry->request->dnsWait = request->dnsWait;
        aLogEntry->request->errType = request->errType;
        aLogEntry->request->errDetail = request->errDetail;
    }
}

void
ClientHttpRequest::logRequest()
{
    if (!out.size && logType.oldType == LOG_TAG_NONE)
        debugs(33, 5, "logging half-baked transaction: " << log_uri);

    al->icp.opcode = ICP_INVALID;
    al->url = log_uri;
    debugs(33, 9, "clientLogRequest: al.url='" << al->url << "'");

    if (al->reply) {
        al->http.code = al->reply->sline.status();
        al->http.content_type = al->reply->content_type.termedBuf();
    } else if (loggingEntry() && loggingEntry()->mem_obj) {
        al->http.code = loggingEntry()->mem_obj->getReply()->sline.status();
        al->http.content_type = loggingEntry()->mem_obj->getReply()->content_type.termedBuf();
    }

    debugs(33, 9, "clientLogRequest: http.code='" << al->http.code << "'");

    if (loggingEntry() && loggingEntry()->mem_obj && loggingEntry()->objectLen() >= 0)
        al->cache.objectSize = loggingEntry()->contentLen(); // payload duplicate ?? with or without TE ?

    al->http.clientRequestSz.header = req_sz;
    // the virgin request is saved to al->request
    if (al->request && al->request->body_pipe)
        al->http.clientRequestSz.payloadData = al->request->body_pipe->producedSize();
    al->http.clientReplySz.header = out.headers_sz;
    // XXX: calculate without payload encoding or headers !!
    al->http.clientReplySz.payloadData = out.size - out.headers_sz; // pretend its all un-encoded data for now.

    al->cache.highOffset = out.offset;

    al->cache.code = logType;

    tvSub(al->cache.trTime, al->cache.start_time, current_time);

    if (request)
        prepareLogWithRequestDetails(request, al);

    if (getConn() != NULL && getConn()->clientConnection != NULL && getConn()->clientConnection->rfc931[0])
        al->cache.rfc931 = getConn()->clientConnection->rfc931;

#if USE_OPENSSL && 0

    /* This is broken. Fails if the connection has been closed. Needs
     * to snarf the ssl details some place earlier..
     */
    if (getConn() != NULL)
        al->cache.ssluser = sslGetUserEmail(fd_table[getConn()->fd].ssl);

#endif

    /* Add notes (if we have a request to annotate) */
    if (request) {
        // The al->notes and request->notes must point to the same object.
        (void)SyncNotes(*al, *request);
        for (auto i = Config.notes.begin(); i != Config.notes.end(); ++i) {
            if (const char *value = (*i)->match(request, al->reply, NULL)) {
                NotePairs &notes = SyncNotes(*al, *request);
                notes.add((*i)->key.termedBuf(), value);
                debugs(33, 3, (*i)->key.termedBuf() << " " << value);
            }
        }
    }

    ACLFilledChecklist checklist(NULL, request, NULL);
    if (al->reply) {
        checklist.reply = al->reply;
        HTTPMSGLOCK(checklist.reply);
    }

    if (request) {
        HTTPMSGUNLOCK(al->adapted_request);
        al->adapted_request = request;
        HTTPMSGLOCK(al->adapted_request);
    }
    accessLogLog(al, &checklist);

    bool updatePerformanceCounters = true;
    if (Config.accessList.stats_collection) {
        ACLFilledChecklist statsCheck(Config.accessList.stats_collection, request, NULL);
        if (al->reply) {
            statsCheck.reply = al->reply;
            HTTPMSGLOCK(statsCheck.reply);
        }
        updatePerformanceCounters = (statsCheck.fastCheck() == ACCESS_ALLOWED);
    }

    if (updatePerformanceCounters) {
        if (request)
            updateCounters();

        if (getConn() != NULL && getConn()->clientConnection != NULL)
            clientdbUpdate(getConn()->clientConnection->remote, logType, AnyP::PROTO_HTTP, out.size);
    }
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

/* This is a handler normally called by comm_close() */
void ConnStateData::connStateClosed(const CommCloseCbParams &)
{
    deleteThis("ConnStateData::connStateClosed");
}

#if USE_AUTH
void
ConnStateData::setAuth(const Auth::UserRequest::Pointer &aur, const char *by)
{
    if (auth_ == NULL) {
        if (aur != NULL) {
            debugs(33, 2, "Adding connection-auth to " << clientConnection << " from " << by);
            auth_ = aur;
        }
        return;
    }

    // clobered with self-pointer
    // NP: something nasty is going on in Squid, but harmless.
    if (aur == auth_) {
        debugs(33, 2, "WARNING: Ignoring duplicate connection-auth for " << clientConnection << " from " << by);
        return;
    }

    /*
     * Connection-auth relies on a single set of credentials being preserved
     * for all requests on a connection once they have been setup.
     * There are several things which need to happen to preserve security
     * when connection-auth credentials change unexpectedly or are unset.
     *
     * 1) auth helper released from any active state
     *
     * They can only be reserved by a handshake process which this
     * connection can now never complete.
     * This prevents helpers hanging when their connections close.
     *
     * 2) pinning is expected to be removed and server conn closed
     *
     * The upstream link is authenticated with the same credentials.
     * Expecting the same level of consistency we should have received.
     * This prevents upstream being faced with multiple or missing
     * credentials after authentication.
     * NP: un-pin is left to the cleanup in ConnStateData::swanSong()
     *     we just trigger that cleanup here via comm_reset_close() or
     *     ConnStateData::stopReceiving()
     *
     * 3) the connection needs to close.
     *
     * This prevents attackers injecting requests into a connection,
     * or gateways wrongly multiplexing users into a single connection.
     *
     * When credentials are missing closure needs to follow an auth
     * challenge for best recovery by the client.
     *
     * When credentials change there is nothing we can do but abort as
     * fast as possible. Sending TCP RST instead of an HTTP response
     * is the best-case action.
     */

    // clobbered with nul-pointer
    if (aur == NULL) {
        debugs(33, 2, "WARNING: Graceful closure on " << clientConnection << " due to connection-auth erase from " << by);
        auth_->releaseAuthServer();
        auth_ = NULL;
        // XXX: need to test whether the connection re-auth challenge is sent. If not, how to trigger it from here.
        // NP: the current situation seems to fix challenge loops in Safari without visible issues in others.
        // we stop receiving more traffic but can leave the Job running to terminate after the error or challenge is delivered.
        stopReceiving("connection-auth removed");
        return;
    }

    // clobbered with alternative credentials
    if (aur != auth_) {
        debugs(33, 2, "ERROR: Closing " << clientConnection << " due to change of connection-auth from " << by);
        auth_->releaseAuthServer();
        auth_ = NULL;
        // this is a fatal type of problem.
        // Close the connection immediately with TCP RST to abort all traffic flow
        comm_reset_close(clientConnection);
        return;
    }

    /* NOT REACHABLE */
}
#endif

// cleans up before destructor is called
void
ConnStateData::swanSong()
{
    debugs(33, 2, HERE << clientConnection);
    checkLogging();

    flags.readMore = false;
    clientdbEstablished(clientConnection->remote, -1);  /* decrement */
    pipeline.terminateAll(0);

    unpinConnection(true);

    Server::swanSong(); // closes the client connection

#if USE_AUTH
    // NP: do this bit after closing the connections to avoid side effects from unwanted TCP RST
    setAuth(NULL, "ConnStateData::SwanSong cleanup");
#endif

    flags.swanSang = true;
}

bool
ConnStateData::isOpen() const
{
    return cbdataReferenceValid(this) && // XXX: checking "this" in a method
           Comm::IsConnOpen(clientConnection) &&
           !fd_table[clientConnection->fd].closing();
}

ConnStateData::~ConnStateData()
{
    debugs(33, 3, HERE << clientConnection);

    if (isOpen())
        debugs(33, DBG_IMPORTANT, "BUG: ConnStateData did not close " << clientConnection);

    if (!flags.swanSang)
        debugs(33, DBG_IMPORTANT, "BUG: ConnStateData was not destroyed properly; " << clientConnection);

    if (bodyPipe != NULL)
        stopProducingFor(bodyPipe, false);

    delete bodyParser; // TODO: pool

#if USE_OPENSSL
    delete sslServerBump;
#endif
}

/**
 * clientSetKeepaliveFlag() sets request->flags.proxyKeepalive.
 * This is the client-side persistent connection flag.  We need
 * to set this relatively early in the request processing
 * to handle hacks for broken servers and clients.
 */
void
clientSetKeepaliveFlag(ClientHttpRequest * http)
{
    HttpRequest *request = http->request;

    debugs(33, 3, "http_ver = " << request->http_ver);
    debugs(33, 3, "method = " << request->method);

    // TODO: move to HttpRequest::hdrCacheInit, just like HttpReply.
    request->flags.proxyKeepalive = request->persistent();
}

/// checks body length of non-chunked requests
static int
clientIsContentLengthValid(HttpRequest * r)
{
    // No Content-Length means this request just has no body, but conflicting
    // Content-Lengths mean a message framing error (RFC 7230 Section 3.3.3 #4).
    if (r->header.conflictingContentLength())
        return 0;

    switch (r->method.id()) {

    case Http::METHOD_GET:

    case Http::METHOD_HEAD:
        /* We do not want to see a request entity on GET/HEAD requests */
        return (r->content_length <= 0 || Config.onoff.request_entities);

    default:
        /* For other types of requests we don't care */
        return 1;
    }

    /* NOT REACHED */
}

int
clientIsRequestBodyTooLargeForPolicy(int64_t bodyLength)
{
    if (Config.maxRequestBodySize &&
            bodyLength > Config.maxRequestBodySize)
        return 1;       /* too large */

    return 0;
}

bool
ClientHttpRequest::multipartRangeRequest() const
{
    return request->multipartRangeRequest();
}

void
clientPackTermBound(String boundary, MemBuf *mb)
{
    mb->appendf("\r\n--" SQUIDSTRINGPH "--\r\n", SQUIDSTRINGPRINT(boundary));
    debugs(33, 6, "buf offset: " << mb->size);
}

void
clientPackRangeHdr(const HttpReply * rep, const HttpHdrRangeSpec * spec, String boundary, MemBuf * mb)
{
    HttpHeader hdr(hoReply);
    assert(rep);
    assert(spec);

    /* put boundary */
    debugs(33, 5, "appending boundary: " << boundary);
    /* rfc2046 requires to _prepend_ boundary with <crlf>! */
    mb->appendf("\r\n--" SQUIDSTRINGPH "\r\n", SQUIDSTRINGPRINT(boundary));

    /* stuff the header with required entries and pack it */

    if (rep->header.has(Http::HdrType::CONTENT_TYPE))
        hdr.putStr(Http::HdrType::CONTENT_TYPE, rep->header.getStr(Http::HdrType::CONTENT_TYPE));

    httpHeaderAddContRange(&hdr, *spec, rep->content_length);

    hdr.packInto(mb);
    hdr.clean();

    /* append <crlf> (we packed a header, not a reply) */
    mb->append("\r\n", 2);
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
 * generates a "unique" boundary string for multipart responses
 * the caller is responsible for cleaning the string */
String
ClientHttpRequest::rangeBoundaryStr() const
{
    const char *key;
    String b(APP_FULLNAME);
    b.append(":",1);
    key = storeEntry()->getMD5Text();
    b.append(key, strlen(key));
    return b;
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
void
clientSocketRecipient(clientStreamNode * node, ClientHttpRequest * http,
                      HttpReply * rep, StoreIOBuffer receivedData)
{
    // dont tryt to deliver if client already ABORTED
    if (!http->getConn() || !cbdataReferenceValid(http->getConn()) || !Comm::IsConnOpen(http->getConn()->clientConnection))
        return;

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
    Http::StreamPointer context = dynamic_cast<Http::Stream *>(node->data.getRaw());
    assert(context != NULL);

    /* TODO: check offset is what we asked for */

    // TODO: enforces HTTP/1 MUST on pipeline order, but is irrelevant to HTTP/2
    if (context != http->getConn()->pipeline.front())
        context->deferRecipientForLater(node, rep, receivedData);
    else if (http->getConn()->cbControlMsgSent) // 1xx to the user is pending
        context->deferRecipientForLater(node, rep, receivedData);
    else
        http->getConn()->handleReply(rep, receivedData);

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
    assert(NULL == dynamic_cast<Http::Stream *>(node->data.getRaw()));
    /* We are only called when the client socket shutsdown.
     * Tell the prev pipeline member we're finished
     */
    clientStreamDetach(node, http);
}

void
ConnStateData::readNextRequest()
{
    debugs(33, 5, HERE << clientConnection << " reading next req");

    fd_note(clientConnection->fd, "Idle client: Waiting for next request");
    /**
     * Set the timeout BEFORE calling readSomeData().
     */
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5,
                                     TimeoutDialer, this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, clientConnection->timeLeft(idleTimeout()), timeoutCall);

    readSomeData();
    /** Please don't do anything with the FD past here! */
}

static void
ClientSocketContextPushDeferredIfNeeded(Http::StreamPointer deferredRequest, ConnStateData * conn)
{
    debugs(33, 2, HERE << conn->clientConnection << " Sending next");

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
ConnStateData::kick()
{
    if (!Comm::IsConnOpen(clientConnection)) {
        debugs(33, 2, clientConnection << " Connection was closed");
        return;
    }

    if (pinning.pinned && !Comm::IsConnOpen(pinning.serverConnection)) {
        debugs(33, 2, clientConnection << " Connection was pinned but server side gone. Terminating client connection");
        clientConnection->close();
        return;
    }

    /** \par
     * We are done with the response, and we are either still receiving request
     * body (early response!) or have already stopped receiving anything.
     *
     * If we are still receiving, then clientParseRequest() below will fail.
     * (XXX: but then we will call readNextRequest() which may succeed and
     * execute a smuggled request as we are not done with the current request).
     *
     * If we stopped because we got everything, then try the next request.
     *
     * If we stopped receiving because of an error, then close now to avoid
     * getting stuck and to prevent accidental request smuggling.
     */

    if (const char *reason = stoppedReceiving()) {
        debugs(33, 3, "closing for earlier request error: " << reason);
        clientConnection->close();
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

    if (clientParseRequests()) {
        debugs(33, 3, clientConnection << ": parsed next request from buffer");
    }

    /** \par
     * Either we need to kick-start another read or, if we have
     * a half-closed connection, kill it after the last request.
     * This saves waiting for half-closed connections to finished being
     * half-closed _AND_ then, sometimes, spending "Timeout" time in
     * the keepalive "Waiting for next request" state.
     */
    if (commIsHalfClosed(clientConnection->fd) && pipeline.empty()) {
        debugs(33, 3, "half-closed client with no pending requests, closing");
        clientConnection->close();
        return;
    }

    /** \par
     * At this point we either have a parsed request (which we've
     * kicked off the processing for) or not. If we have a deferred
     * request (parsed but deferred for pipeling processing reasons)
     * then look at processing it. If not, simply kickstart
     * another read.
     */
    Http::StreamPointer deferredRequest = pipeline.front();
    if (deferredRequest != nullptr) {
        debugs(33, 3, clientConnection << ": calling PushDeferredIfNeeded");
        ClientSocketContextPushDeferredIfNeeded(deferredRequest, this);
    } else if (flags.readMore) {
        debugs(33, 3, clientConnection << ": calling readNextRequest()");
        readNextRequest();
    } else {
        // XXX: Can this happen? CONNECT tunnels have deferredRequest set.
        debugs(33, DBG_IMPORTANT, MYNAME << "abandoning " << clientConnection);
    }
}

void
ConnStateData::stopSending(const char *error)
{
    debugs(33, 4, HERE << "sending error (" << clientConnection << "): " << error <<
           "; old receiving error: " <<
           (stoppedReceiving() ? stoppedReceiving_ : "none"));

    if (const char *oldError = stoppedSending()) {
        debugs(33, 3, HERE << "already stopped sending: " << oldError);
        return; // nothing has changed as far as this connection is concerned
    }
    stoppedSending_ = error;

    if (!stoppedReceiving()) {
        if (const int64_t expecting = mayNeedToReadMoreBody()) {
            debugs(33, 5, HERE << "must still read " << expecting <<
                   " request body bytes with " << inBuf.length() << " unused");
            return; // wait for the request receiver to finish reading
        }
    }

    clientConnection->close();
}

void
ConnStateData::afterClientWrite(size_t size)
{
    if (pipeline.empty())
        return;

    auto ctx = pipeline.front();
    if (size) {
        statCounter.client_http.kbytes_out += size;
        if (ctx->http->logType.isTcpHit())
            statCounter.client_http.hit_kbytes_out += size;
    }
    ctx->writeComplete(size);
}

Http::Stream *
ConnStateData::abortRequestParsing(const char *const uri)
{
    ClientHttpRequest *http = new ClientHttpRequest(this);
    http->req_sz = inBuf.length();
    http->uri = xstrdup(uri);
    setLogUri (http, uri);
    auto *context = new Http::Stream(clientConnection, http);
    StoreIOBuffer tempBuffer;
    tempBuffer.data = context->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, new clientReplyContext(http), clientSocketRecipient,
                     clientSocketDetach, context, tempBuffer);
    return context;
}

void
ConnStateData::startShutdown()
{
    // RegisteredRunner API callback - Squid has been shut down

    // if connection is idle terminate it now,
    // otherwise wait for grace period to end
    if (pipeline.empty())
        endingShutdown();
}

void
ConnStateData::endingShutdown()
{
    // RegisteredRunner API callback - Squid shutdown grace period is over

    // force the client connection to close immediately
    // swanSong() in the close handler will cleanup.
    if (Comm::IsConnOpen(clientConnection))
        clientConnection->close();
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

    for (; end > uriAndHTTPVersion; --end) {
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
                if (!xisspace(*t)) {
                    *q = *t;
                    ++q;
                }
                ++t;
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
prepareAcceleratedURL(ConnStateData * conn, ClientHttpRequest *http, const Http1::RequestParserPointer &hp)
{
    int vhost = conn->port->vhost;
    int vport = conn->port->vport;
    static char ipbuf[MAX_IPSTRLEN];

    http->flags.accel = true;

    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */

    static const SBuf cache_object("cache_object://");
    if (hp->requestUri().startsWith(cache_object))
        return; /* already in good shape */

    // XXX: re-use proper URL parser for this
    SBuf url = hp->requestUri(); // use full provided URI if we abort
    do { // use a loop so we can break out of it
        ::Parser::Tokenizer tok(url);
        if (tok.skip('/')) // origin-form URL already.
            break;

        if (conn->port->vhost)
            return; /* already in good shape */

        // skip the URI scheme
        static const CharacterSet uriScheme = CharacterSet("URI-scheme","+-.") + CharacterSet::ALPHA + CharacterSet::DIGIT;
        static const SBuf uriSchemeEnd("://");
        if (!tok.skipAll(uriScheme) || !tok.skip(uriSchemeEnd))
            break;

        // skip the authority segment
        // RFC 3986 complex nested ABNF for "authority" boils down to this:
        static const CharacterSet authority = CharacterSet("authority","-._~%:@[]!$&'()*+,;=") +
                                              CharacterSet::HEXDIG + CharacterSet::ALPHA + CharacterSet::DIGIT;
        if (!tok.skipAll(authority))
            break;

        static const SBuf slashUri("/");
        const SBuf t = tok.remaining();
        if (t.isEmpty())
            url = slashUri;
        else if (t[0]=='/') // looks like path
            url = t;
        else if (t[0]=='?' || t[0]=='#') { // looks like query or fragment. fix '/'
            url = slashUri;
            url.append(t);
        } // else do nothing. invalid path

    } while(false);

#if SHOULD_REJECT_UNKNOWN_URLS
    // reject URI which are not well-formed even after the processing above
    if (url.isEmpty() || url[0] != '/') {
        hp->parseStatusCode = Http::scBadRequest;
        return conn->abortRequestParsing("error:invalid-request");
    }
#endif

    if (vport < 0)
        vport = http->getConn()->clientConnection->local.port();

    const bool switchedToHttps = conn->switchedToHttps();
    const bool tryHostHeader = vhost || switchedToHttps;
    char *host = NULL;
    if (tryHostHeader && (host = hp->getHeaderField("Host"))) {
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
        const int url_sz = hp->requestUri().length() + 32 + Config.appendDomainLen + strlen(host);
        http->uri = (char *)xcalloc(url_sz, 1);
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        snprintf(http->uri, url_sz, SQUIDSBUFPH "://%s" SQUIDSBUFPH, SQUIDSBUFPRINT(scheme), host, SQUIDSBUFPRINT(url));
        debugs(33, 5, "ACCEL VHOST REWRITE: " << http->uri);
    } else if (conn->port->defaultsite /* && !vhost */) {
        debugs(33, 5, "ACCEL DEFAULTSITE REWRITE: defaultsite=" << conn->port->defaultsite << " + vport=" << vport);
        const int url_sz = hp->requestUri().length() + 32 + Config.appendDomainLen +
                           strlen(conn->port->defaultsite);
        http->uri = (char *)xcalloc(url_sz, 1);
        char vportStr[32];
        vportStr[0] = '\0';
        if (vport > 0) {
            snprintf(vportStr, sizeof(vportStr),":%d",vport);
        }
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        snprintf(http->uri, url_sz, SQUIDSBUFPH "://%s%s" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme), conn->port->defaultsite, vportStr, SQUIDSBUFPRINT(url));
        debugs(33, 5, "ACCEL DEFAULTSITE REWRITE: " << http->uri);
    } else if (vport > 0 /* && (!vhost || no Host:) */) {
        debugs(33, 5, "ACCEL VPORT REWRITE: *_port IP + vport=" << vport);
        /* Put the local socket IP address as the hostname, with whatever vport we found  */
        const int url_sz = hp->requestUri().length() + 32 + Config.appendDomainLen;
        http->uri = (char *)xcalloc(url_sz, 1);
        http->getConn()->clientConnection->local.toHostStr(ipbuf,MAX_IPSTRLEN);
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        snprintf(http->uri, url_sz, SQUIDSBUFPH "://%s:%d" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme), ipbuf, vport, SQUIDSBUFPRINT(url));
        debugs(33, 5, "ACCEL VPORT REWRITE: " << http->uri);
    }
}

static void
prepareTransparentURL(ConnStateData * conn, ClientHttpRequest *http, const Http1::RequestParserPointer &hp)
{
    // TODO Must() on URI !empty when the parser supports throw. For now avoid assert().
    if (!hp->requestUri().isEmpty() && hp->requestUri()[0] != '/')
        return; /* already in good shape */

    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */

    if (const char *host = hp->getHeaderField("Host")) {
        const int url_sz = hp->requestUri().length() + 32 + Config.appendDomainLen +
                           strlen(host);
        http->uri = (char *)xcalloc(url_sz, 1);
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        snprintf(http->uri, url_sz, SQUIDSBUFPH "://%s" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme), host, SQUIDSBUFPRINT(hp->requestUri()));
        debugs(33, 5, "TRANSPARENT HOST REWRITE: " << http->uri);
    } else {
        /* Put the local socket IP address as the hostname.  */
        const int url_sz = hp->requestUri().length() + 32 + Config.appendDomainLen;
        http->uri = (char *)xcalloc(url_sz, 1);
        static char ipbuf[MAX_IPSTRLEN];
        http->getConn()->clientConnection->local.toHostStr(ipbuf,MAX_IPSTRLEN);
        const SBuf &scheme = AnyP::UriScheme(http->getConn()->transferProtocol.protocol).image();
        snprintf(http->uri, url_sz, SQUIDSBUFPH "://%s:%d" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme),
                 ipbuf, http->getConn()->clientConnection->local.port(), SQUIDSBUFPRINT(hp->requestUri()));
        debugs(33, 5, "TRANSPARENT REWRITE: " << http->uri);
    }
}

/** Parse an HTTP request
 *
 *  \note Sets result->flags.parsed_ok to 0 if failed to parse the request,
 *          to 1 if the request was correctly parsed.
 *  \param[in] csd a ConnStateData. The caller must make sure it is not null
 *  \param[in] hp an Http1::RequestParser
 *  \param[out] mehtod_p will be set as a side-effect of the parsing.
 *          Pointed-to value will be set to Http::METHOD_NONE in case of
 *          parsing failure
 *  \param[out] http_ver will be set as a side-effect of the parsing
 *  \return NULL on incomplete requests,
 *          a Http::Stream on success or failure.
 */
Http::Stream *
parseHttpRequest(ConnStateData *csd, const Http1::RequestParserPointer &hp)
{
    /* Attempt to parse the first line; this will define where the method, url, version and header begin */
    {
        const bool parsedOk = hp->parse(csd->inBuf);

        // sync the buffers after parsing.
        csd->inBuf = hp->remaining();

        if (hp->needsMoreData()) {
            debugs(33, 5, "Incomplete request, waiting for end of request line");
            return NULL;
        }

        if (csd->mayTunnelUnsupportedProto()) {
            csd->preservedClientData = hp->parsed();
            csd->preservedClientData.append(csd->inBuf);
        }

        if (!parsedOk) {
            const bool tooBig =
                hp->parseStatusCode == Http::scRequestHeaderFieldsTooLarge ||
                hp->parseStatusCode == Http::scUriTooLong;
            auto result = csd->abortRequestParsing(
                              tooBig ? "error:request-too-large" : "error:invalid-request");
            // assume that remaining leftovers belong to this bad request
            if (!csd->inBuf.isEmpty())
                csd->consumeInput(csd->inBuf.length());
            return result;
        }
    }

    /* We know the whole request is in parser now */
    debugs(11, 2, "HTTP Client " << csd->clientConnection);
    debugs(11, 2, "HTTP Client REQUEST:\n---------\n" <<
           hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol() << "\n" <<
           hp->mimeHeader() <<
           "\n----------");

    /* deny CONNECT via accelerated ports */
    if (hp->method() == Http::METHOD_CONNECT && csd->port != NULL && csd->port->flags.accelSurrogate) {
        debugs(33, DBG_IMPORTANT, "WARNING: CONNECT method received on " << csd->transferProtocol << " Accelerator port " << csd->port->s.port());
        debugs(33, DBG_IMPORTANT, "WARNING: for request: " << hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol());
        hp->parseStatusCode = Http::scMethodNotAllowed;
        return csd->abortRequestParsing("error:method-not-allowed");
    }

    /* RFC 7540 section 11.6 registers the method PRI as HTTP/2 specific
     * Deny "PRI" method if used in HTTP/1.x or 0.9 versions.
     * If seen it signals a broken client or proxy has corrupted the traffic.
     */
    if (hp->method() == Http::METHOD_PRI && hp->messageProtocol() < Http::ProtocolVersion(2,0)) {
        debugs(33, DBG_IMPORTANT, "WARNING: PRI method received on " << csd->transferProtocol << " port " << csd->port->s.port());
        debugs(33, DBG_IMPORTANT, "WARNING: for request: " << hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol());
        hp->parseStatusCode = Http::scMethodNotAllowed;
        return csd->abortRequestParsing("error:method-not-allowed");
    }

    if (hp->method() == Http::METHOD_NONE) {
        debugs(33, DBG_IMPORTANT, "WARNING: Unsupported method: " << hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol());
        hp->parseStatusCode = Http::scMethodNotAllowed;
        return csd->abortRequestParsing("error:unsupported-request-method");
    }

    // Process headers after request line
    debugs(33, 3, "complete request received. " <<
           "prefix_sz = " << hp->messageHeaderSize() <<
           ", request-line-size=" << hp->firstLineSize() <<
           ", mime-header-size=" << hp->headerBlockSize() <<
           ", mime header block:\n" << hp->mimeHeader() << "\n----------");

    /* Ok, all headers are received */
    ClientHttpRequest *http = new ClientHttpRequest(csd);

    http->req_sz = hp->messageHeaderSize();
    Http::Stream *result = new Http::Stream(csd->clientConnection, http);

    StoreIOBuffer tempBuffer;
    tempBuffer.data = result->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;

    ClientStreamData newServer = new clientReplyContext(http);
    ClientStreamData newClient = result;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, newServer, clientSocketRecipient,
                     clientSocketDetach, newClient, tempBuffer);

    /* set url */
    debugs(33,5, "Prepare absolute URL from " <<
           (csd->transparent()?"intercept":(csd->port->flags.accelSurrogate ? "accel":"")));
    /* Rewrite the URL in transparent or accelerator mode */
    /* NP: there are several cases to traverse here:
     *  - standard mode (forward proxy)
     *  - transparent mode (TPROXY)
     *  - transparent mode with failures
     *  - intercept mode (NAT)
     *  - intercept mode with failures
     *  - accelerator mode (reverse proxy)
     *  - internal relative-URL
     *  - mixed combos of the above with internal URL
     *  - remote interception with PROXY protocol
     *  - remote reverse-proxy with PROXY protocol
     */
    if (csd->transparent()) {
        /* intercept or transparent mode, properly working with no failures */
        prepareTransparentURL(csd, http, hp);

    } else if (internalCheck(hp->requestUri())) { // NP: only matches relative-URI
        /* internal URL mode */
        /* prepend our name & port */
        http->uri = xstrdup(internalLocalUri(NULL, hp->requestUri()));
        // We just re-wrote the URL. Must replace the Host: header.
        //  But have not parsed there yet!! flag for local-only handling.
        http->flags.internal = true;

    } else if (csd->port->flags.accelSurrogate || csd->switchedToHttps()) {
        /* accelerator mode */
        prepareAcceleratedURL(csd, http, hp);
    }

    if (!http->uri) {
        /* No special rewrites have been applied above, use the
         * requested url. may be rewritten later, so make extra room */
        int url_sz = hp->requestUri().length() + Config.appendDomainLen + 5;
        http->uri = (char *)xcalloc(url_sz, 1);
        SBufToCstring(http->uri, hp->requestUri());
    }

    result->flags.parsed_ok = 1;
    return result;
}

bool
ConnStateData::connFinishedWithConn(int size)
{
    if (size == 0) {
        if (pipeline.empty() && inBuf.isEmpty()) {
            /* no current or pending requests */
            debugs(33, 4, HERE << clientConnection << " closed");
            return true;
        } else if (!Config.onoff.half_closed_clients) {
            /* admin doesn't want to support half-closed client sockets */
            debugs(33, 3, HERE << clientConnection << " aborted (half_closed_clients disabled)");
            pipeline.terminateAll(0);
            return true;
        }
    }

    return false;
}

void
ConnStateData::consumeInput(const size_t byteCount)
{
    assert(byteCount > 0 && byteCount <= inBuf.length());
    inBuf.consume(byteCount);
    debugs(33, 5, "inBuf has " << inBuf.length() << " unused bytes");
}

void
ConnStateData::clientAfterReadingRequests()
{
    // Were we expecting to read more request body from half-closed connection?
    if (mayNeedToReadMoreBody() && commIsHalfClosed(clientConnection->fd)) {
        debugs(33, 3, HERE << "truncated body: closing half-closed " << clientConnection);
        clientConnection->close();
        return;
    }

    if (flags.readMore)
        readSomeData();
}

void
ConnStateData::quitAfterError(HttpRequest *request)
{
    // From HTTP p.o.v., we do not have to close after every error detected
    // at the client-side, but many such errors do require closure and the
    // client-side code is bad at handling errors so we play it safe.
    if (request)
        request->flags.proxyKeepalive = false;
    flags.readMore = false;
    debugs(33,4, HERE << "Will close after error: " << clientConnection);
}

#if USE_OPENSSL
bool ConnStateData::serveDelayedError(Http::Stream *context)
{
    ClientHttpRequest *http = context->http;

    if (!sslServerBump)
        return false;

    assert(sslServerBump->entry);
    // Did we create an error entry while processing CONNECT?
    if (!sslServerBump->entry->isEmpty()) {
        quitAfterError(http->request);

        // Get the saved error entry and send it to the client by replacing the
        // ClientHttpRequest store entry with it.
        clientStreamNode *node = context->getClientReplyContext();
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert(repContext);
        debugs(33, 5, "Responding with delated error for " << http->uri);
        repContext->setReplyToStoreEntry(sslServerBump->entry, "delayed SslBump error");

        // save the original request for logging purposes
        if (!context->http->al->request) {
            context->http->al->request = http->request;
            HTTPMSGLOCK(context->http->al->request);
        }

        // Get error details from the fake certificate-peeking request.
        http->request->detailError(sslServerBump->request->errType, sslServerBump->request->errDetail);
        context->pullData();
        return true;
    }

    // In bump-server-first mode, we have not necessarily seen the intended
    // server name at certificate-peeking time. Check for domain mismatch now,
    // when we can extract the intended name from the bumped HTTP request.
    if (const Security::CertPointer &srvCert = sslServerBump->serverCert) {
        HttpRequest *request = http->request;
        if (!Ssl::checkX509ServerValidity(srvCert.get(), request->url.host())) {
            debugs(33, 2, "SQUID_X509_V_ERR_DOMAIN_MISMATCH: Certificate " <<
                   "does not match domainname " << request->url.host());

            bool allowDomainMismatch = false;
            if (Config.ssl_client.cert_error) {
                ACLFilledChecklist check(Config.ssl_client.cert_error, request, dash_str);
                check.sslErrors = new Security::CertErrors(Security::CertError(SQUID_X509_V_ERR_DOMAIN_MISMATCH, srvCert));
                allowDomainMismatch = (check.fastCheck() == ACCESS_ALLOWED);
                delete check.sslErrors;
                check.sslErrors = NULL;
            }

            if (!allowDomainMismatch) {
                quitAfterError(request);

                clientStreamNode *node = context->getClientReplyContext();
                clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
                assert (repContext);

                // Fill the server IP and hostname for error page generation.
                HttpRequest::Pointer const & peekerRequest = sslServerBump->request;
                request->hier.note(peekerRequest->hier.tcpServer, request->url.host());

                // Create an error object and fill it
                ErrorState *err = new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scServiceUnavailable, request);
                err->src_addr = clientConnection->remote;
                Ssl::ErrorDetail *errDetail = new Ssl::ErrorDetail(
                    SQUID_X509_V_ERR_DOMAIN_MISMATCH,
                    srvCert.get(), nullptr);
                err->detail = errDetail;
                // Save the original request for logging purposes.
                if (!context->http->al->request) {
                    context->http->al->request = request;
                    HTTPMSGLOCK(context->http->al->request);
                }
                repContext->setReplyToError(request->method, err);
                assert(context->http->out.offset == 0);
                context->pullData();
                return true;
            }
        }
    }

    return false;
}
#endif // USE_OPENSSL

/**
 * Check on_unsupported_protocol checklist and return true if tunnel mode selected
 * or false otherwise
 */
bool
clientTunnelOnError(ConnStateData *conn, Http::StreamPointer &context, HttpRequest::Pointer &request, const HttpRequestMethod& method, err_type requestError)
{
    if (conn->mayTunnelUnsupportedProto()) {
        ACLFilledChecklist checklist(Config.accessList.on_unsupported_protocol, request.getRaw(), nullptr);
        checklist.requestErrorType = requestError;
        checklist.src_addr = conn->clientConnection->remote;
        checklist.my_addr = conn->clientConnection->local;
        checklist.conn(conn);
        allow_t answer = checklist.fastCheck();
        if (answer == ACCESS_ALLOWED && answer.kind == 1) {
            debugs(33, 3, "Request will be tunneled to server");
            if (context) {
                assert(conn->pipeline.front() == context); // XXX: still assumes HTTP/1 semantics
                context->finished(); // Will remove from conn->pipeline queue
            }
            Comm::SetSelect(conn->clientConnection->fd, COMM_SELECT_READ, NULL, NULL, 0);
            return conn->initiateTunneledRequest(request, Http::METHOD_NONE, "unknown-protocol", conn->preservedClientData);
        } else {
            debugs(33, 3, "Continue with returning the error: " << requestError);
        }
    }

    return false;
}

void
clientProcessRequestFinished(ConnStateData *conn, const HttpRequest::Pointer &request)
{
    /*
     * DPW 2007-05-18
     * Moved the TCP_RESET feature from clientReplyContext::sendMoreData
     * to here because calling comm_reset_close() causes http to
     * be freed before accessing.
     */
    if (request != NULL && request->flags.resetTcp && Comm::IsConnOpen(conn->clientConnection)) {
        debugs(33, 3, HERE << "Sending TCP RST on " << conn->clientConnection);
        conn->flags.readMore = false;
        comm_reset_close(conn->clientConnection);
    }
}

void
clientProcessRequest(ConnStateData *conn, const Http1::RequestParserPointer &hp, Http::Stream *context)
{
    ClientHttpRequest *http = context->http;
    bool chunked = false;
    bool mustReplyToOptions = false;
    bool unsupportedTe = false;
    bool expectBody = false;

    // We already have the request parsed and checked, so we
    // only need to go through the final body/conn setup to doCallouts().
    assert(http->request);
    HttpRequest::Pointer request = http->request;

    // temporary hack to avoid splitting this huge function with sensitive code
    const bool isFtp = !hp;

    // Some blobs below are still HTTP-specific, but we would have to rewrite
    // this entire function to remove them from the FTP code path. Connection
    // setup and body_pipe preparation blobs are needed for FTP.

    request->clientConnectionManager = conn;

    request->flags.accelerated = http->flags.accel;
    request->flags.sslBumped=conn->switchedToHttps();
    request->flags.ignoreCc = conn->port->ignore_cc;
    // TODO: decouple http->flags.accel from request->flags.sslBumped
    request->flags.noDirect = (request->flags.accelerated && !request->flags.sslBumped) ?
                              !conn->port->allow_direct : 0;
    request->sources |= isFtp ? HttpMsg::srcFtp :
                        ((request->flags.sslBumped || conn->port->transport.protocol == AnyP::PROTO_HTTPS) ? HttpMsg::srcHttps : HttpMsg::srcHttp);
#if USE_AUTH
    if (request->flags.sslBumped) {
        if (conn->getAuth() != NULL)
            request->auth_user_request = conn->getAuth();
    }
#endif

    /** \par
     * If transparent or interception mode is working clone the transparent and interception flags
     * from the port settings to the request.
     */
    if (http->clientConnection != NULL) {
        request->flags.intercepted = ((http->clientConnection->flags & COMM_INTERCEPTION) != 0);
        request->flags.interceptTproxy = ((http->clientConnection->flags & COMM_TRANSPARENT) != 0 ) ;
        static const bool proxyProtocolPort = (conn->port != NULL) ? conn->port->flags.proxySurrogate : false;
        if (request->flags.interceptTproxy && !proxyProtocolPort) {
            if (Config.accessList.spoof_client_ip) {
                ACLFilledChecklist *checklist = clientAclChecklistCreate(Config.accessList.spoof_client_ip, http);
                request->flags.spoofClientIp = (checklist->fastCheck() == ACCESS_ALLOWED);
                delete checklist;
            } else
                request->flags.spoofClientIp = true;
        } else
            request->flags.spoofClientIp = false;
    }

    if (internalCheck(request->url.path())) {
        if (internalHostnameIs(request->url.host()) && request->url.port() == getMyPort()) {
            debugs(33, 2, "internal URL found: " << request->url.getScheme() << "://" << request->url.authority(true));
            http->flags.internal = true;
        } else if (Config.onoff.global_internal_static && internalStaticCheck(request->url.path())) {
            debugs(33, 2, "internal URL found: " << request->url.getScheme() << "://" << request->url.authority(true) << " (global_internal_static on)");
            request->url.setScheme(AnyP::PROTO_HTTP, "http");
            request->url.host(internalHostname());
            request->url.port(getMyPort());
            http->flags.internal = true;
        } else
            debugs(33, 2, "internal URL found: " << request->url.getScheme() << "://" << request->url.authority(true) << " (not this proxy)");
    }

    request->flags.internal = http->flags.internal;
    setLogUri (http, urlCanonicalClean(request.getRaw()));
    request->client_addr = conn->clientConnection->remote; // XXX: remove request->client_addr member.
#if FOLLOW_X_FORWARDED_FOR
    // indirect client gets stored here because it is an HTTP header result (from X-Forwarded-For:)
    // not details about the TCP connection itself
    request->indirect_client_addr = conn->clientConnection->remote;
#endif /* FOLLOW_X_FORWARDED_FOR */
    request->my_addr = conn->clientConnection->local;
    request->myportname = conn->port->name;

    if (!isFtp) {
        // XXX: for non-HTTP messages instantiate a different HttpMsg child type
        // for now Squid only supports HTTP requests
        const AnyP::ProtocolVersion &http_ver = hp->messageProtocol();
        assert(request->http_ver.protocol == http_ver.protocol);
        request->http_ver.major = http_ver.major;
        request->http_ver.minor = http_ver.minor;
    }

    // Link this HttpRequest to ConnStateData relatively early so the following complex handling can use it
    // TODO: this effectively obsoletes a lot of conn->FOO copying. That needs cleaning up later.
    request->clientConnectionManager = conn;

    if (request->header.chunked()) {
        chunked = true;
    } else if (request->header.has(Http::HdrType::TRANSFER_ENCODING)) {
        const String te = request->header.getList(Http::HdrType::TRANSFER_ENCODING);
        // HTTP/1.1 requires chunking to be the last encoding if there is one
        unsupportedTe = te.size() && te != "identity";
    } // else implied identity coding

    mustReplyToOptions = (request->method == Http::METHOD_OPTIONS) &&
                         (request->header.getInt64(Http::HdrType::MAX_FORWARDS) == 0);
    if (!urlCheckRequest(request.getRaw()) || mustReplyToOptions || unsupportedTe) {
        clientStreamNode *node = context->getClientReplyContext();
        conn->quitAfterError(request.getRaw());
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_UNSUP_REQ, Http::scNotImplemented, request->method, NULL,
                                    conn->clientConnection->remote, request.getRaw(), NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        clientProcessRequestFinished(conn, request);
        return;
    }

    if (!chunked && !clientIsContentLengthValid(request.getRaw())) {
        clientStreamNode *node = context->getClientReplyContext();
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        conn->quitAfterError(request.getRaw());
        repContext->setReplyToError(ERR_INVALID_REQ,
                                    Http::scLengthRequired, request->method, NULL,
                                    conn->clientConnection->remote, request.getRaw(), NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        clientProcessRequestFinished(conn, request);
        return;
    }

    clientSetKeepaliveFlag(http);
    // Let tunneling code be fully responsible for CONNECT requests
    if (http->request->method == Http::METHOD_CONNECT) {
        context->mayUseConnection(true);
        conn->flags.readMore = false;
    }

#if USE_OPENSSL
    if (conn->switchedToHttps() && conn->serveDelayedError(context)) {
        clientProcessRequestFinished(conn, request);
        return;
    }
#endif

    /* Do we expect a request-body? */
    expectBody = chunked || request->content_length > 0;
    if (!context->mayUseConnection() && expectBody) {
        request->body_pipe = conn->expectRequestBody(
                                 chunked ? -1 : request->content_length);

        /* Is it too large? */
        if (!chunked && // if chunked, we will check as we accumulate
                clientIsRequestBodyTooLargeForPolicy(request->content_length)) {
            clientStreamNode *node = context->getClientReplyContext();
            clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
            assert (repContext);
            conn->quitAfterError(request.getRaw());
            repContext->setReplyToError(ERR_TOO_BIG,
                                        Http::scPayloadTooLarge, Http::METHOD_NONE, NULL,
                                        conn->clientConnection->remote, http->request, NULL, NULL);
            assert(context->http->out.offset == 0);
            context->pullData();
            clientProcessRequestFinished(conn, request);
            return;
        }

        if (!isFtp) {
            // We may stop producing, comm_close, and/or call setReplyToError()
            // below, so quit on errors to avoid http->doCallouts()
            if (!conn->handleRequestBodyData()) {
                clientProcessRequestFinished(conn, request);
                return;
            }

            if (!request->body_pipe->productionEnded()) {
                debugs(33, 5, "need more request body");
                context->mayUseConnection(true);
                assert(conn->flags.readMore);
            }
        }
    }

    http->calloutContext = new ClientRequestContext(http);

    http->doCallouts();

    clientProcessRequestFinished(conn, request);
}

int
ConnStateData::pipelinePrefetchMax() const
{
    // TODO: Support pipelined requests through pinned connections.
    if (pinning.pinned)
        return 0;
    return Config.pipeline_max_prefetch;
}

/**
 * Limit the number of concurrent requests.
 * \return true  when there are available position(s) in the pipeline queue for another request.
 * \return false when the pipeline queue is full or disabled.
 */
bool
ConnStateData::concurrentRequestQueueFilled() const
{
    const int existingRequestCount = pipeline.count();

    // default to the configured pipeline size.
    // add 1 because the head of pipeline is counted in concurrent requests and not prefetch queue
#if USE_OPENSSL
    const int internalRequest = (transparent() && sslBumpMode == Ssl::bumpSplice) ? 1 : 0;
#else
    const int internalRequest = 0;
#endif
    const int concurrentRequestLimit = pipelinePrefetchMax() + 1 + internalRequest;

    // when queue filled already we cant add more.
    if (existingRequestCount >= concurrentRequestLimit) {
        debugs(33, 3, clientConnection << " max concurrent requests reached (" << concurrentRequestLimit << ")");
        debugs(33, 5, clientConnection << " deferring new request until one is done");
        return true;
    }

    return false;
}

/**
 * Perform proxy_protocol_access ACL tests on the client which
 * connected to PROXY protocol port to see if we trust the
 * sender enough to accept their PROXY header claim.
 */
bool
ConnStateData::proxyProtocolValidateClient()
{
    if (!Config.accessList.proxyProtocol)
        return proxyProtocolError("PROXY client not permitted by default ACL");

    ACLFilledChecklist ch(Config.accessList.proxyProtocol, NULL, clientConnection->rfc931);
    ch.src_addr = clientConnection->remote;
    ch.my_addr = clientConnection->local;
    ch.conn(this);

    if (ch.fastCheck() != ACCESS_ALLOWED)
        return proxyProtocolError("PROXY client not permitted by ACLs");

    return true;
}

/**
 * Perform cleanup on PROXY protocol errors.
 * If header parsing hits a fatal error terminate the connection,
 * otherwise wait for more data.
 */
bool
ConnStateData::proxyProtocolError(const char *msg)
{
    if (msg) {
        // This is important to know, but maybe not so much that flooding the log is okay.
#if QUIET_PROXY_PROTOCOL
        // display the first of every 32 occurances at level 1, the others at level 2.
        static uint8_t hide = 0;
        debugs(33, (hide++ % 32 == 0 ? DBG_IMPORTANT : 2), msg << " from " << clientConnection);
#else
        debugs(33, DBG_IMPORTANT, msg << " from " << clientConnection);
#endif
        mustStop(msg);
    }
    return false;
}

/// magic octet prefix for PROXY protocol version 1
static const SBuf Proxy1p0magic("PROXY ", 6);

/// magic octet prefix for PROXY protocol version 2
static const SBuf Proxy2p0magic("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);

/**
 * Test the connection read buffer for PROXY protocol header.
 * Version 1 and 2 header currently supported.
 */
bool
ConnStateData::parseProxyProtocolHeader()
{
    // http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt

    // detect and parse PROXY/2.0 protocol header
    if (inBuf.startsWith(Proxy2p0magic))
        return parseProxy2p0();

    // detect and parse PROXY/1.0 protocol header
    if (inBuf.startsWith(Proxy1p0magic))
        return parseProxy1p0();

    // detect and terminate other protocols
    if (inBuf.length() >= Proxy2p0magic.length()) {
        // PROXY/1.0 magic is shorter, so we know that
        // the input does not start with any PROXY magic
        return proxyProtocolError("PROXY protocol error: invalid header");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse yet.
    return false;
}

/// parse the PROXY/1.0 protocol header from the connection read buffer
bool
ConnStateData::parseProxy1p0()
{
    ::Parser::Tokenizer tok(inBuf);
    tok.skip(Proxy1p0magic);

    // skip to first LF (assumes it is part of CRLF)
    static const CharacterSet lineContent = CharacterSet::LF.complement("non-LF");
    SBuf line;
    if (tok.prefix(line, lineContent, 107-Proxy1p0magic.length())) {
        if (tok.skip('\n')) {
            // found valid header
            inBuf = tok.remaining();
            needProxyProtocolHeader_ = false;
            // reset the tokenizer to work on found line only.
            tok.reset(line);
        } else
            return false; // no LF yet

    } else // protocol error only if there are more than 107 bytes prefix header
        return proxyProtocolError(inBuf.length() > 107? "PROXY/1.0 error: missing CRLF" : NULL);

    static const SBuf unknown("UNKNOWN"), tcpName("TCP");
    if (tok.skip(tcpName)) {

        // skip TCP/IP version number
        static const CharacterSet tcpVersions("TCP-version","46");
        if (!tok.skipOne(tcpVersions))
            return proxyProtocolError("PROXY/1.0 error: missing TCP version");

        // skip SP after protocol version
        if (!tok.skip(' '))
            return proxyProtocolError("PROXY/1.0 error: missing SP");

        SBuf ipa, ipb;
        int64_t porta, portb;
        static const CharacterSet ipChars = CharacterSet("IP Address",".:") + CharacterSet::HEXDIG;

        // parse:  src-IP SP dst-IP SP src-port SP dst-port CR
        // leave the LF until later.
        const bool correct = tok.prefix(ipa, ipChars) && tok.skip(' ') &&
                             tok.prefix(ipb, ipChars) && tok.skip(' ') &&
                             tok.int64(porta) && tok.skip(' ') &&
                             tok.int64(portb) &&
                             tok.skip('\r');
        if (!correct)
            return proxyProtocolError("PROXY/1.0 error: invalid syntax");

        // parse IP and port strings
        Ip::Address originalClient, originalDest;

        if (!originalClient.GetHostByName(ipa.c_str()))
            return proxyProtocolError("PROXY/1.0 error: invalid src-IP address");

        if (!originalDest.GetHostByName(ipb.c_str()))
            return proxyProtocolError("PROXY/1.0 error: invalid dst-IP address");

        if (porta > 0 && porta <= 0xFFFF) // max uint16_t
            originalClient.port(static_cast<uint16_t>(porta));
        else
            return proxyProtocolError("PROXY/1.0 error: invalid src port");

        if (portb > 0 && portb <= 0xFFFF) // max uint16_t
            originalDest.port(static_cast<uint16_t>(portb));
        else
            return proxyProtocolError("PROXY/1.0 error: invalid dst port");

        // we have original client and destination details now
        // replace the client connection values
        debugs(33, 5, "PROXY/1.0 protocol on connection " << clientConnection);
        clientConnection->local = originalDest;
        clientConnection->remote = originalClient;
        if ((clientConnection->flags & COMM_TRANSPARENT))
            clientConnection->flags ^= COMM_TRANSPARENT; // prevent TPROXY spoofing of this new IP.
        debugs(33, 5, "PROXY/1.0 upgrade: " << clientConnection);

        // repeat fetch ensuring the new client FQDN can be logged
        if (Config.onoff.log_fqdn)
            fqdncache_gethostbyaddr(clientConnection->remote, FQDN_LOOKUP_IF_MISS);

        return true;

    } else if (tok.skip(unknown)) {
        // found valid but unusable header
        return true;

    } else
        return proxyProtocolError("PROXY/1.0 error: invalid protocol family");

    return false;
}

/// parse the PROXY/2.0 protocol header from the connection read buffer
bool
ConnStateData::parseProxy2p0()
{
    static const SBuf::size_type prefixLen = Proxy2p0magic.length();
    if (inBuf.length() < prefixLen + 4)
        return false; // need more bytes

    if ((inBuf[prefixLen] & 0xF0) != 0x20) // version == 2 is mandatory
        return proxyProtocolError("PROXY/2.0 error: invalid version");

    const char command = (inBuf[prefixLen] & 0x0F);
    if ((command & 0xFE) != 0x00) // values other than 0x0-0x1 are invalid
        return proxyProtocolError("PROXY/2.0 error: invalid command");

    const char family = (inBuf[prefixLen+1] & 0xF0) >>4;
    if (family > 0x3) // values other than 0x0-0x3 are invalid
        return proxyProtocolError("PROXY/2.0 error: invalid family");

    const char proto = (inBuf[prefixLen+1] & 0x0F);
    if (proto > 0x2) // values other than 0x0-0x2 are invalid
        return proxyProtocolError("PROXY/2.0 error: invalid protocol type");

    const char *clen = inBuf.rawContent() + prefixLen + 2;
    uint16_t len;
    memcpy(&len, clen, sizeof(len));
    len = ntohs(len);

    if (inBuf.length() < prefixLen + 4 + len)
        return false; // need more bytes

    inBuf.consume(prefixLen + 4); // 4 being the extra bytes
    const SBuf extra = inBuf.consume(len);
    needProxyProtocolHeader_ = false; // found successfully

    // LOCAL connections do nothing with the extras
    if (command == 0x00/* LOCAL*/)
        return true;

    union pax {
        struct {        /* for TCP/UDP over IPv4, len = 12 */
            struct in_addr src_addr;
            struct in_addr dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ipv4_addr;
        struct {        /* for TCP/UDP over IPv6, len = 36 */
            struct in6_addr src_addr;
            struct in6_addr dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ipv6_addr;
#if NOT_SUPPORTED
        struct {        /* for AF_UNIX sockets, len = 216 */
            uint8_t src_addr[108];
            uint8_t dst_addr[108];
        } unix_addr;
#endif
    };

    pax ipu;
    memcpy(&ipu, extra.rawContent(), sizeof(pax));

    // replace the client connection values
    debugs(33, 5, "PROXY/2.0 protocol on connection " << clientConnection);
    switch (family) {
    case 0x1: // IPv4
        clientConnection->local = ipu.ipv4_addr.dst_addr;
        clientConnection->local.port(ntohs(ipu.ipv4_addr.dst_port));
        clientConnection->remote = ipu.ipv4_addr.src_addr;
        clientConnection->remote.port(ntohs(ipu.ipv4_addr.src_port));
        if ((clientConnection->flags & COMM_TRANSPARENT))
            clientConnection->flags ^= COMM_TRANSPARENT; // prevent TPROXY spoofing of this new IP.
        break;
    case 0x2: // IPv6
        clientConnection->local = ipu.ipv6_addr.dst_addr;
        clientConnection->local.port(ntohs(ipu.ipv6_addr.dst_port));
        clientConnection->remote = ipu.ipv6_addr.src_addr;
        clientConnection->remote.port(ntohs(ipu.ipv6_addr.src_port));
        if ((clientConnection->flags & COMM_TRANSPARENT))
            clientConnection->flags ^= COMM_TRANSPARENT; // prevent TPROXY spoofing of this new IP.
        break;
    default: // do nothing
        break;
    }
    debugs(33, 5, "PROXY/2.0 upgrade: " << clientConnection);

    // repeat fetch ensuring the new client FQDN can be logged
    if (Config.onoff.log_fqdn)
        fqdncache_gethostbyaddr(clientConnection->remote, FQDN_LOOKUP_IF_MISS);

    return true;
}

void
ConnStateData::receivedFirstByte()
{
    if (receivedFirstByte_)
        return;

    receivedFirstByte_ = true;
    // Set timeout to Config.Timeout.request
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.request, timeoutCall);
}

/**
 * Attempt to parse one or more requests from the input buffer.
 * Returns true after completing parsing of at least one request [header]. That
 * includes cases where parsing ended with an error (e.g., a huge request).
 */
bool
ConnStateData::clientParseRequests()
{
    bool parsed_req = false;

    debugs(33, 5, HERE << clientConnection << ": attempting to parse");

    // Loop while we have read bytes that are not needed for producing the body
    // On errors, bodyPipe may become nil, but readMore will be cleared
    while (!inBuf.isEmpty() && !bodyPipe && flags.readMore) {

        /* Limit the number of concurrent requests */
        if (concurrentRequestQueueFilled())
            break;

        // try to parse the PROXY protocol header magic bytes
        if (needProxyProtocolHeader_ && !parseProxyProtocolHeader())
            break;

        if (Http::StreamPointer context = parseOneRequest()) {
            debugs(33, 5, clientConnection << ": done parsing a request");

            AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "clientLifetimeTimeout",
                                             CommTimeoutCbPtrFun(clientLifetimeTimeout, context->http));
            commSetConnTimeout(clientConnection, Config.Timeout.lifetime, timeoutCall);

            context->registerWithConn();

            processParsedRequest(context);

            parsed_req = true; // XXX: do we really need to parse everything right NOW ?

            if (context->mayUseConnection()) {
                debugs(33, 3, HERE << "Not parsing new requests, as this request may need the connection");
                break;
            }
        } else {
            debugs(33, 5, clientConnection << ": not enough request data: " <<
                   inBuf.length() << " < " << Config.maxRequestHeaderSize);
            Must(inBuf.length() < Config.maxRequestHeaderSize);
            break;
        }
    }

    /* XXX where to 'finish' the parsing pass? */
    return parsed_req;
}

void
ConnStateData::afterClientRead()
{
#if USE_OPENSSL
    if (parsingTlsHandshake) {
        parseTlsHandshake();
        return;
    }
#endif

    /* Process next request */
    if (pipeline.empty())
        fd_note(clientConnection->fd, "Reading next request");

    if (!clientParseRequests()) {
        if (!isOpen())
            return;
        /*
         * If the client here is half closed and we failed
         * to parse a request, close the connection.
         * The above check with connFinishedWithConn() only
         * succeeds _if_ the buffer is empty which it won't
         * be if we have an incomplete request.
         * XXX: This duplicates ConnStateData::kick
         */
        if (pipeline.empty() && commIsHalfClosed(clientConnection->fd)) {
            debugs(33, 5, clientConnection << ": half-closed connection, no completed request parsed, connection closing.");
            clientConnection->close();
            return;
        }
    }

    if (!isOpen())
        return;

    clientAfterReadingRequests();
}

/**
 * called when new request data has been read from the socket
 *
 * \retval false called comm_close or setReplyToError (the caller should bail)
 * \retval true  we did not call comm_close or setReplyToError
 */
bool
ConnStateData::handleReadData()
{
    // if we are reading a body, stuff data into the body pipe
    if (bodyPipe != NULL)
        return handleRequestBodyData();
    return true;
}

/**
 * called when new request body data has been buffered in inBuf
 * may close the connection if we were closing and piped everything out
 *
 * \retval false called comm_close or setReplyToError (the caller should bail)
 * \retval true  we did not call comm_close or setReplyToError
 */
bool
ConnStateData::handleRequestBodyData()
{
    assert(bodyPipe != NULL);

    if (bodyParser) { // chunked encoding
        if (const err_type error = handleChunkedRequestBody()) {
            abortChunkedRequestBody(error);
            return false;
        }
    } else { // identity encoding
        debugs(33,5, HERE << "handling plain request body for " << clientConnection);
        const size_t putSize = bodyPipe->putMoreData(inBuf.c_str(), inBuf.length());
        if (putSize > 0)
            consumeInput(putSize);

        if (!bodyPipe->mayNeedMoreData()) {
            // BodyPipe will clear us automagically when we produced everything
            bodyPipe = NULL;
        }
    }

    if (!bodyPipe) {
        debugs(33,5, HERE << "produced entire request body for " << clientConnection);

        if (const char *reason = stoppedSending()) {
            /* we've finished reading like good clients,
             * now do the close that initiateClose initiated.
             */
            debugs(33, 3, HERE << "closing for earlier sending error: " << reason);
            clientConnection->close();
            return false;
        }
    }

    return true;
}

/// parses available chunked encoded body bytes, checks size, returns errors
err_type
ConnStateData::handleChunkedRequestBody()
{
    debugs(33, 7, "chunked from " << clientConnection << ": " << inBuf.length());

    try { // the parser will throw on errors

        if (inBuf.isEmpty()) // nothing to do
            return ERR_NONE;

        BodyPipeCheckout bpc(*bodyPipe);
        bodyParser->setPayloadBuffer(&bpc.buf);
        const bool parsed = bodyParser->parse(inBuf);
        inBuf = bodyParser->remaining(); // sync buffers
        bpc.checkIn();

        // dechunk then check: the size limit applies to _dechunked_ content
        if (clientIsRequestBodyTooLargeForPolicy(bodyPipe->producedSize()))
            return ERR_TOO_BIG;

        if (parsed) {
            finishDechunkingRequest(true);
            Must(!bodyPipe);
            return ERR_NONE; // nil bodyPipe implies body end for the caller
        }

        // if chunk parser needs data, then the body pipe must need it too
        Must(!bodyParser->needsMoreData() || bodyPipe->mayNeedMoreData());

        // if parser needs more space and we can consume nothing, we will stall
        Must(!bodyParser->needsMoreSpace() || bodyPipe->buf().hasContent());
    } catch (...) { // TODO: be more specific
        debugs(33, 3, HERE << "malformed chunks" << bodyPipe->status());
        return ERR_INVALID_REQ;
    }

    debugs(33, 7, HERE << "need more chunked data" << *bodyPipe->status());
    return ERR_NONE;
}

/// quit on errors related to chunked request body handling
void
ConnStateData::abortChunkedRequestBody(const err_type error)
{
    finishDechunkingRequest(false);

    // XXX: The code below works if we fail during initial request parsing,
    // but if we fail when the server connection is used already, the server may send
    // us its response too, causing various assertions. How to prevent that?
#if WE_KNOW_HOW_TO_SEND_ERRORS
    Http::StreamPointer context = pipeline.front();
    if (context != NULL && !context->http->out.offset) { // output nothing yet
        clientStreamNode *node = context->getClientReplyContext();
        clientReplyContext *repContext = dynamic_cast<clientReplyContext*>(node->data.getRaw());
        assert(repContext);
        const Http::StatusCode scode = (error == ERR_TOO_BIG) ?
                                       Http::scPayloadTooLarge : HTTP_BAD_REQUEST;
        repContext->setReplyToError(error, scode,
                                    repContext->http->request->method,
                                    repContext->http->uri,
                                    CachePeer,
                                    repContext->http->request,
                                    inBuf, NULL);
        context->pullData();
    } else {
        // close or otherwise we may get stuck as nobody will notice the error?
        comm_reset_close(clientConnection);
    }
#else
    debugs(33, 3, HERE << "aborting chunked request without error " << error);
    comm_reset_close(clientConnection);
#endif
    flags.readMore = false;
}

void
ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer )
{
    // request reader may get stuck waiting for space if nobody consumes body
    if (bodyPipe != NULL)
        bodyPipe->enableAutoConsumption();

    // kids extend
}

/** general lifetime handler for HTTP requests */
void
ConnStateData::requestTimeout(const CommTimeoutCbParams &io)
{
    if (!Comm::IsConnOpen(io.conn))
        return;

    if (mayTunnelUnsupportedProto() && !receivedFirstByte_) {
        Http::StreamPointer context = pipeline.front();
        Must(context && context->http);
        HttpRequest::Pointer request = context->http->request;
        if (clientTunnelOnError(this, context, request, HttpRequestMethod(), ERR_REQUEST_START_TIMEOUT))
            return;
    }
    /*
    * Just close the connection to not confuse browsers
    * using persistent connections. Some browsers open
    * a connection and then do not use it until much
    * later (presumeably because the request triggering
    * the open has already been completed on another
    * connection)
    */
    debugs(33, 3, "requestTimeout: FD " << io.fd << ": lifetime is expired.");
    io.conn->close();
}

static void
clientLifetimeTimeout(const CommTimeoutCbParams &io)
{
    ClientHttpRequest *http = static_cast<ClientHttpRequest *>(io.data);
    debugs(33, DBG_IMPORTANT, "WARNING: Closing client connection due to lifetime timeout");
    debugs(33, DBG_IMPORTANT, "\t" << http->uri);
    http->logType.err.timedout = true;
    if (Comm::IsConnOpen(io.conn))
        io.conn->close();
}

ConnStateData::ConnStateData(const MasterXaction::Pointer &xact) :
    AsyncJob("ConnStateData"), // kids overwrite
    Server(xact),
    bodyParser(nullptr),
#if USE_OPENSSL
    sslBumpMode(Ssl::bumpEnd),
#endif
    needProxyProtocolHeader_(false),
#if USE_OPENSSL
    switchedToHttps_(false),
    parsingTlsHandshake(false),
    sslServerBump(NULL),
    signAlgorithm(Ssl::algSignTrusted),
#endif
    stoppedSending_(NULL),
    stoppedReceiving_(NULL)
{
    flags.readMore = true; // kids may overwrite
    flags.swanSang = false;

    pinning.host = NULL;
    pinning.port = -1;
    pinning.pinned = false;
    pinning.auth = false;
    pinning.zeroReply = false;
    pinning.peer = NULL;

    // store the details required for creating more MasterXaction objects as new requests come in
    log_addr = xact->tcpClient->remote;
    log_addr.applyMask(Config.Addrs.client_netmask);

    // register to receive notice of Squid signal events
    // which may affect long persisting client connections
    registerRunner();
}

void
ConnStateData::start()
{
    BodyProducer::start();
    HttpControlMsgSink::start();

    if (port->disable_pmtu_discovery != DISABLE_PMTU_OFF &&
            (transparent() || port->disable_pmtu_discovery == DISABLE_PMTU_ALWAYS)) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
        int i = IP_PMTUDISC_DONT;
        if (setsockopt(clientConnection->fd, SOL_IP, IP_MTU_DISCOVER, &i, sizeof(i)) < 0) {
            int xerrno = errno;
            debugs(33, 2, "WARNING: Path MTU discovery disabling failed on " << clientConnection << " : " << xstrerr(xerrno));
        }
#else
        static bool reported = false;

        if (!reported) {
            debugs(33, DBG_IMPORTANT, "NOTICE: Path MTU discovery disabling is not supported on your platform.");
            reported = true;
        }
#endif
    }

    typedef CommCbMemFunT<ConnStateData, CommCloseCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, ConnStateData::connStateClosed);
    comm_add_close_handler(clientConnection->fd, call);

    if (Config.onoff.log_fqdn)
        fqdncache_gethostbyaddr(clientConnection->remote, FQDN_LOOKUP_IF_MISS);

#if USE_IDENT
    if (Ident::TheConfig.identLookup) {
        ACLFilledChecklist identChecklist(Ident::TheConfig.identLookup, NULL, NULL);
        identChecklist.src_addr = clientConnection->remote;
        identChecklist.my_addr = clientConnection->local;
        if (identChecklist.fastCheck() == ACCESS_ALLOWED)
            Ident::Start(clientConnection, clientIdentDone, this);
    }
#endif

    clientdbEstablished(clientConnection->remote, 1);

    needProxyProtocolHeader_ = port->flags.proxySurrogate;
    if (needProxyProtocolHeader_) {
        if (!proxyProtocolValidateClient()) // will close the connection on failure
            return;
    }

#if USE_DELAY_POOLS
    fd_table[clientConnection->fd].clientInfo = NULL;

    if (Config.onoff.client_db) {
        /* it was said several times that client write limiter does not work if client_db is disabled */

        ClientDelayPools& pools(Config.ClientDelay.pools);
        ACLFilledChecklist ch(NULL, NULL, NULL);

        // TODO: we check early to limit error response bandwith but we
        // should recheck when we can honor delay_pool_uses_indirect
        // TODO: we should also pass the port details for myportname here.
        ch.src_addr = clientConnection->remote;
        ch.my_addr = clientConnection->local;

        for (unsigned int pool = 0; pool < pools.size(); ++pool) {

            /* pools require explicit 'allow' to assign a client into them */
            if (pools[pool].access) {
                ch.changeAcl(pools[pool].access);
                allow_t answer = ch.fastCheck();
                if (answer == ACCESS_ALLOWED) {

                    /*  request client information from db after we did all checks
                        this will save hash lookup if client failed checks */
                    ClientInfo * cli = clientdbGetInfo(clientConnection->remote);
                    assert(cli);

                    /* put client info in FDE */
                    fd_table[clientConnection->fd].clientInfo = cli;

                    /* setup write limiter for this request */
                    const double burst = floor(0.5 +
                                               (pools[pool].highwatermark * Config.ClientDelay.initial)/100.0);
                    cli->setWriteLimiter(pools[pool].rate, burst, pools[pool].highwatermark);
                    break;
                } else {
                    debugs(83, 4, HERE << "Delay pool " << pool << " skipped because ACL " << answer);
                }
            }
        }
    }
#endif

    // kids must extend to actually start doing something (e.g., reading)
}

/** Handle a new connection on an HTTP socket. */
void
httpAccept(const CommAcceptCbParams &params)
{
    MasterXaction::Pointer xact = params.xaction;
    AnyP::PortCfgPointer s = xact->squidPort;

    // NP: it is possible the port was reconfigured when the call or accept() was queued.

    if (params.flag != Comm::OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, s->listenConn << ": accept failure: " << xstrerr(params.xerrno));
        return;
    }

    debugs(33, 4, params.conn << ": accepted");
    fd_note(params.conn->fd, "client http connect");

    if (s->tcp_keepalive.enabled)
        commSetTcpKeepalive(params.conn->fd, s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);

    ++incoming_sockets_accepted;

    // Socket is ready, setup the connection manager to start using it
    auto *srv = Http::NewServer(xact);
    AsyncJob::Start(srv); // usually async-calls readSomeData()
}

#if USE_OPENSSL

/** Create SSL connection structure and update fd_table */
static bool
httpsCreate(const Comm::ConnectionPointer &conn, const Security::ContextPointer &ctx)
{
    if (Ssl::CreateServer(ctx, conn, "client https start")) {
        debugs(33, 5, "will negotate SSL on " << conn);
        return true;
    }

    conn->close();
    return false;
}

/**
 *
 * \retval 1 on success
 * \retval 0 when needs more data
 * \retval -1 on error
 */
static int
Squid_SSL_accept(ConnStateData *conn, PF *callback)
{
    int fd = conn->clientConnection->fd;
    auto ssl = fd_table[fd].ssl.get();
    int ret;

    errno = 0;
    if ((ret = SSL_accept(ssl)) <= 0) {
        const int xerrno = errno;
        const int ssl_error = SSL_get_error(ssl, ret);

        switch (ssl_error) {

        case SSL_ERROR_WANT_READ:
            Comm::SetSelect(fd, COMM_SELECT_READ, callback, (callback != NULL ? conn : NULL), 0);
            return 0;

        case SSL_ERROR_WANT_WRITE:
            Comm::SetSelect(fd, COMM_SELECT_WRITE, callback, (callback != NULL ? conn : NULL), 0);
            return 0;

        case SSL_ERROR_SYSCALL:
            if (ret == 0) {
                debugs(83, 2, "Error negotiating SSL connection on FD " << fd << ": Aborted by client: " << ssl_error);
            } else {
                debugs(83, (xerrno == ECONNRESET) ? 1 : 2, "Error negotiating SSL connection on FD " << fd << ": " <<
                       (xerrno == 0 ? Security::ErrorString(ssl_error) : xstrerr(xerrno)));
            }
            return -1;

        case SSL_ERROR_ZERO_RETURN:
            debugs(83, DBG_IMPORTANT, "Error negotiating SSL connection on FD " << fd << ": Closed by client");
            return -1;

        default:
            debugs(83, DBG_IMPORTANT, "Error negotiating SSL connection on FD " <<
                   fd << ": " << Security::ErrorString(ERR_get_error()) <<
                   " (" << ssl_error << "/" << ret << ")");
            return -1;
        }

        /* NOTREACHED */
    }
    return 1;
}

/** negotiate an SSL connection */
static void
clientNegotiateSSL(int fd, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    int ret;
    if ((ret = Squid_SSL_accept(conn, clientNegotiateSSL)) <= 0) {
        if (ret < 0) // An error
            conn->clientConnection->close();
        return;
    }

    Security::SessionPointer session(fd_table[fd].ssl);
    if (Security::SessionIsResumed(session)) {
        debugs(83, 2, "Session " << SSL_get_session(session.get()) <<
               " reused on FD " << fd << " (" << fd_table[fd].ipaddr <<
               ":" << (int)fd_table[fd].remote_port << ")");
    } else {
        if (Debug::Enabled(83, 4)) {
            /* Write out the SSL session details.. actually the call below, but
             * OpenSSL headers do strange typecasts confusing GCC.. */
            /* PEM_write_SSL_SESSION(debug_log, SSL_get_session(ssl)); */
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x00908000L
            PEM_ASN1_write(reinterpret_cast<i2d_of_void *>(i2d_SSL_SESSION),
                           PEM_STRING_SSL_SESSION, debug_log,
                           reinterpret_cast<char *>(SSL_get_session(session.get())),
                           nullptr, nullptr, 0, nullptr, nullptr);

#elif (ALLOW_ALWAYS_SSL_SESSION_DETAIL == 1)

            /* When using gcc 3.3.x and OpenSSL 0.9.7x sometimes a compile error can occur here.
            * This is caused by an unpredicatble gcc behaviour on a cast of the first argument
            * of PEM_ASN1_write(). For this reason this code section is disabled. To enable it,
            * define ALLOW_ALWAYS_SSL_SESSION_DETAIL=1.
            * Because there are two possible usable cast, if you get an error here, try the other
            * commented line. */

            PEM_ASN1_write((int(*)())i2d_SSL_SESSION, PEM_STRING_SSL_SESSION,
                           debug_log,
                           reinterpret_cast<char *>(SSL_get_session(session.get())),
                           nullptr, nullptr, 0, nullptr, nullptr);
            /* PEM_ASN1_write((int(*)(...))i2d_SSL_SESSION, PEM_STRING_SSL_SESSION,
                           debug_log,
                           reinterpret_cast<char *>(SSL_get_session(session.get())),
                           nullptr, nullptr, 0, nullptr, nullptr);
             */
#else
            debugs(83, 4, "With " OPENSSL_VERSION_TEXT ", session details are available only defining ALLOW_ALWAYS_SSL_SESSION_DETAIL=1 in the source.");

#endif
            /* Note: This does not automatically fflush the log file.. */
        }

        debugs(83, 2, "New session " << SSL_get_session(session.get()) <<
               " on FD " << fd << " (" << fd_table[fd].ipaddr << ":" <<
               fd_table[fd].remote_port << ")");
    }

    // Connection established. Retrieve TLS connection parameters for logging.
    conn->clientConnection->tlsNegotiations()->retrieveNegotiatedInfo(session);

    X509 *client_cert = SSL_get_peer_certificate(session.get());

    if (client_cert) {
        debugs(83, 3, "FD " << fd << " client certificate: subject: " <<
               X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0));

        debugs(83, 3, "FD " << fd << " client certificate: issuer: " <<
               X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0));

        X509_free(client_cert);
    } else {
        debugs(83, 5, "FD " << fd << " has no certificate.");
    }

    conn->readSomeData();
}

/**
 * If Security::ContextPointer is given, starts reading the TLS handshake.
 * Otherwise, calls switchToHttps to generate a dynamic Security::ContextPointer.
 */
static void
httpsEstablish(ConnStateData *connState, const Security::ContextPointer &ctx)
{
    assert(connState);
    const Comm::ConnectionPointer &details = connState->clientConnection;

    if (!ctx || !httpsCreate(details, ctx))
        return;

    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5, TimeoutDialer,
                                     connState, ConnStateData::requestTimeout);
    commSetConnTimeout(details, Config.Timeout.request, timeoutCall);

    Comm::SetSelect(details->fd, COMM_SELECT_READ, clientNegotiateSSL, connState, 0);
}

/**
 * A callback function to use with the ACLFilledChecklist callback.
 * In the case of ACCESS_ALLOWED answer initializes a bumped SSL connection,
 * else reverts the connection to tunnel mode.
 */
static void
httpsSslBumpAccessCheckDone(allow_t answer, void *data)
{
    ConnStateData *connState = (ConnStateData *) data;

    // if the connection is closed or closing, just return.
    if (!connState->isOpen())
        return;

    // Require both a match and a positive bump mode to work around exceptional
    // cases where ACL code may return ACCESS_ALLOWED with zero answer.kind.
    if (answer == ACCESS_ALLOWED && answer.kind != Ssl::bumpNone) {
        debugs(33, 2, "sslBump needed for " << connState->clientConnection << " method " << answer.kind);
        connState->sslBumpMode = static_cast<Ssl::BumpMode>(answer.kind);
    } else {
        debugs(33, 2, HERE << "sslBump not needed for " << connState->clientConnection);
        connState->sslBumpMode = Ssl::bumpNone;
    }
    if (!connState->fakeAConnectRequest("ssl-bump", connState->inBuf))
        connState->clientConnection->close();
}

/** handle a new HTTPS connection */
static void
httpsAccept(const CommAcceptCbParams &params)
{
    MasterXaction::Pointer xact = params.xaction;
    const AnyP::PortCfgPointer s = xact->squidPort;

    // NP: it is possible the port was reconfigured when the call or accept() was queued.

    if (params.flag != Comm::OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, "httpsAccept: " << s->listenConn << ": accept failure: " << xstrerr(params.xerrno));
        return;
    }

    debugs(33, 4, HERE << params.conn << " accepted, starting SSL negotiation.");
    fd_note(params.conn->fd, "client https connect");

    if (s->tcp_keepalive.enabled) {
        commSetTcpKeepalive(params.conn->fd, s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);
    }
    ++incoming_sockets_accepted;

    // Socket is ready, setup the connection manager to start using it
    auto *srv = Https::NewServer(xact);
    AsyncJob::Start(srv); // usually async-calls postHttpsAccept()
}

void
ConnStateData::postHttpsAccept()
{
    if (port->flags.tunnelSslBumping) {
        debugs(33, 5, "accept transparent connection: " << clientConnection);

        if (!Config.accessList.ssl_bump) {
            httpsSslBumpAccessCheckDone(ACCESS_DENIED, this);
            return;
        }

        // Create a fake HTTP request for ssl_bump ACL check,
        // using tproxy/intercept provided destination IP and port.
        HttpRequest *request = new HttpRequest();
        static char ip[MAX_IPSTRLEN];
        assert(clientConnection->flags & (COMM_TRANSPARENT | COMM_INTERCEPTION));
        request->url.host(clientConnection->local.toStr(ip, sizeof(ip)));
        request->url.port(clientConnection->local.port());
        request->myportname = port->name;

        ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(Config.accessList.ssl_bump, request, NULL);
        acl_checklist->src_addr = clientConnection->remote;
        acl_checklist->my_addr = port->s;
        // Build a local AccessLogEntry to allow requiresAle() acls work
        acl_checklist->al = new AccessLogEntry;
        acl_checklist->al->cache.start_time = current_time;
        acl_checklist->al->tcpClient = clientConnection;
        acl_checklist->al->cache.port = port;
        acl_checklist->al->cache.caddr = log_addr;
        HTTPMSGUNLOCK(acl_checklist->al->request);
        acl_checklist->al->request = request;
        HTTPMSGLOCK(acl_checklist->al->request);
        acl_checklist->nonBlockingCheck(httpsSslBumpAccessCheckDone, this);
        return;
    } else {
        httpsEstablish(this, port->secure.staticContext);
    }
}

void
ConnStateData::sslCrtdHandleReplyWrapper(void *data, const Helper::Reply &reply)
{
    ConnStateData * state_data = (ConnStateData *)(data);
    state_data->sslCrtdHandleReply(reply);
}

void
ConnStateData::sslCrtdHandleReply(const Helper::Reply &reply)
{
    if (!isOpen()) {
        debugs(33, 3, "Connection gone while waiting for ssl_crtd helper reply; helper reply:" << reply);
        return;
    }

    if (reply.result == Helper::BrokenHelper) {
        debugs(33, 5, HERE << "Certificate for " << sslConnectHostOrIp << " cannot be generated. ssl_crtd response: " << reply);
    } else if (!reply.other().hasContent()) {
        debugs(1, DBG_IMPORTANT, HERE << "\"ssl_crtd\" helper returned <NULL> reply.");
    } else {
        Ssl::CrtdMessage reply_message(Ssl::CrtdMessage::REPLY);
        if (reply_message.parse(reply.other().content(), reply.other().contentSize()) != Ssl::CrtdMessage::OK) {
            debugs(33, 5, HERE << "Reply from ssl_crtd for " << sslConnectHostOrIp << " is incorrect");
        } else {
            if (reply.result != Helper::Okay) {
                debugs(33, 5, HERE << "Certificate for " << sslConnectHostOrIp << " cannot be generated. ssl_crtd response: " << reply_message.getBody());
            } else {
                debugs(33, 5, HERE << "Certificate for " << sslConnectHostOrIp << " was successfully recieved from ssl_crtd");
                if (sslServerBump && (sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare)) {
                    doPeekAndSpliceStep();
                    auto ssl = fd_table[clientConnection->fd].ssl.get();
                    bool ret = Ssl::configureSSLUsingPkeyAndCertFromMemory(ssl, reply_message.getBody().c_str(), *port);
                    if (!ret)
                        debugs(33, 5, "Failed to set certificates to ssl object for PeekAndSplice mode");

                    Security::ContextPointer ctx;
                    ctx.resetAndLock(SSL_get_SSL_CTX(ssl));
                    Ssl::configureUnconfiguredSslContext(ctx, signAlgorithm, *port);
                } else {
                    Security::ContextPointer ctx(Ssl::generateSslContextUsingPkeyAndCertFromMemory(reply_message.getBody().c_str(), *port));
                    getSslContextDone(ctx, true);
                }
                return;
            }
        }
    }
    Security::ContextPointer nil;
    getSslContextDone(nil);
}

void ConnStateData::buildSslCertGenerationParams(Ssl::CertificateProperties &certProperties)
{
    certProperties.commonName =  sslCommonName_.isEmpty() ? sslConnectHostOrIp.termedBuf() : sslCommonName_.c_str();

    const bool triedToConnect = sslServerBump && sslServerBump->entry;
    const bool connectedOK = triedToConnect && sslServerBump->entry->isEmpty();
    if (connectedOK) {
        if (X509 *mimicCert = sslServerBump->serverCert.get())
            certProperties.mimicCert.resetAndLock(mimicCert);

        ACLFilledChecklist checklist(NULL, sslServerBump->request.getRaw(),
                                     clientConnection != NULL ? clientConnection->rfc931 : dash_str);
        checklist.sslErrors = cbdataReference(sslServerBump->sslErrors());

        for (sslproxy_cert_adapt *ca = Config.ssl_client.cert_adapt; ca != NULL; ca = ca->next) {
            // If the algorithm already set, then ignore it.
            if ((ca->alg == Ssl::algSetCommonName && certProperties.setCommonName) ||
                    (ca->alg == Ssl::algSetValidAfter && certProperties.setValidAfter) ||
                    (ca->alg == Ssl::algSetValidBefore && certProperties.setValidBefore) )
                continue;

            if (ca->aclList && checklist.fastCheck(ca->aclList) == ACCESS_ALLOWED) {
                const char *alg = Ssl::CertAdaptAlgorithmStr[ca->alg];
                const char *param = ca->param;

                // For parameterless CN adaptation, use hostname from the
                // CONNECT request.
                if (ca->alg == Ssl::algSetCommonName) {
                    if (!param)
                        param = sslConnectHostOrIp.termedBuf();
                    certProperties.commonName = param;
                    certProperties.setCommonName = true;
                } else if (ca->alg == Ssl::algSetValidAfter)
                    certProperties.setValidAfter = true;
                else if (ca->alg == Ssl::algSetValidBefore)
                    certProperties.setValidBefore = true;

                debugs(33, 5, HERE << "Matches certificate adaptation aglorithm: " <<
                       alg << " param: " << (param ? param : "-"));
            }
        }

        certProperties.signAlgorithm = Ssl::algSignEnd;
        for (sslproxy_cert_sign *sg = Config.ssl_client.cert_sign; sg != NULL; sg = sg->next) {
            if (sg->aclList && checklist.fastCheck(sg->aclList) == ACCESS_ALLOWED) {
                certProperties.signAlgorithm = (Ssl::CertSignAlgorithm)sg->alg;
                break;
            }
        }
    } else {// did not try to connect (e.g. client-first) or failed to connect
        // In case of an error while connecting to the secure server, use a
        // trusted certificate, with no mimicked fields and no adaptation
        // algorithms. There is nothing we can mimic, so we want to minimize the
        // number of warnings the user will have to see to get to the error page.
        // We will close the connection, so that the trust is not extended to
        // non-Squid content.
        certProperties.signAlgorithm = Ssl::algSignTrusted;
    }

    assert(certProperties.signAlgorithm != Ssl::algSignEnd);

    if (certProperties.signAlgorithm == Ssl::algSignUntrusted) {
        assert(port->untrustedSigningCert.get());
        certProperties.signWithX509.resetAndLock(port->untrustedSigningCert.get());
        certProperties.signWithPkey.resetAndLock(port->untrustedSignPkey.get());
    } else {
        assert(port->signingCert.get());
        certProperties.signWithX509.resetAndLock(port->signingCert.get());

        if (port->signPkey.get())
            certProperties.signWithPkey.resetAndLock(port->signPkey.get());
    }
    signAlgorithm = certProperties.signAlgorithm;

    certProperties.signHash = Ssl::DefaultSignHash;
}

void
ConnStateData::getSslContextStart()
{
    // If we are called, then CONNECT has succeeded. Finalize it.
    if (auto xact = pipeline.front()) {
        if (xact->http && xact->http->request && xact->http->request->method == Http::METHOD_CONNECT)
            xact->finished();
        // cannot proceed with encryption if requests wait for plain responses
        Must(pipeline.empty());
    }
    /* careful: finished() above frees request, host, etc. */

    if (port->generateHostCertificates) {
        Ssl::CertificateProperties certProperties;
        buildSslCertGenerationParams(certProperties);
        sslBumpCertKey = certProperties.dbKey().c_str();
        assert(sslBumpCertKey.size() > 0 && sslBumpCertKey[0] != '\0');

        // Disable caching for bumpPeekAndSplice mode
        if (!(sslServerBump && (sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare))) {
            debugs(33, 5, "Finding SSL certificate for " << sslBumpCertKey << " in cache");
            Ssl::LocalContextStorage * ssl_ctx_cache = Ssl::TheGlobalContextStorage.getLocalStorage(port->s);
            Security::ContextPointer *cachedCtx = ssl_ctx_cache ? ssl_ctx_cache->get(sslBumpCertKey.termedBuf()) : nullptr;
            if (cachedCtx) {
                debugs(33, 5, "SSL certificate for " << sslBumpCertKey << " found in cache");
                if (Ssl::verifySslCertificate(*cachedCtx, certProperties)) {
                    debugs(33, 5, "Cached SSL certificate for " << sslBumpCertKey << " is valid");
                    getSslContextDone(*cachedCtx);
                    return;
                } else {
                    debugs(33, 5, "Cached SSL certificate for " << sslBumpCertKey << " is out of date. Delete this certificate from cache");
                    if (ssl_ctx_cache)
                        ssl_ctx_cache->del(sslBumpCertKey.termedBuf());
                }
            } else {
                debugs(33, 5, "SSL certificate for " << sslBumpCertKey << " haven't found in cache");
            }
        }

#if USE_SSL_CRTD
        try {
            debugs(33, 5, HERE << "Generating SSL certificate for " << certProperties.commonName << " using ssl_crtd.");
            Ssl::CrtdMessage request_message(Ssl::CrtdMessage::REQUEST);
            request_message.setCode(Ssl::CrtdMessage::code_new_certificate);
            request_message.composeRequest(certProperties);
            debugs(33, 5, HERE << "SSL crtd request: " << request_message.compose().c_str());
            Ssl::Helper::GetInstance()->sslSubmit(request_message, sslCrtdHandleReplyWrapper, this);
            return;
        } catch (const std::exception &e) {
            debugs(33, DBG_IMPORTANT, "ERROR: Failed to compose ssl_crtd " <<
                   "request for " << certProperties.commonName <<
                   " certificate: " << e.what() << "; will now block to " <<
                   "generate that certificate.");
            // fall through to do blocking in-process generation.
        }
#endif // USE_SSL_CRTD

        debugs(33, 5, HERE << "Generating SSL certificate for " << certProperties.commonName);
        if (sslServerBump && (sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare)) {
            doPeekAndSpliceStep();
            auto ssl = fd_table[clientConnection->fd].ssl.get();
            if (!Ssl::configureSSL(ssl, certProperties, *port))
                debugs(33, 5, "Failed to set certificates to ssl object for PeekAndSplice mode");

            Security::ContextPointer ctx;
            ctx.resetAndLock(SSL_get_SSL_CTX(ssl));
            Ssl::configureUnconfiguredSslContext(ctx, certProperties.signAlgorithm, *port);
        } else {
            Security::ContextPointer dynCtx(Ssl::generateSslContext(certProperties, *port));
            getSslContextDone(dynCtx, true);
        }
        return;
    }

    Security::ContextPointer nil;
    getSslContextDone(nil);
}

void
ConnStateData::getSslContextDone(Security::ContextPointer &ctx, bool isNew)
{
    // Try to add generated ssl context to storage.
    if (port->generateHostCertificates && isNew) {

        if (ctx && (signAlgorithm == Ssl::algSignTrusted)) {
            Ssl::chainCertificatesToSSLContext(ctx, *port);
        } else if (signAlgorithm == Ssl::algSignTrusted) {
            debugs(33, DBG_IMPORTANT, "WARNING: can not add signing certificate to SSL context chain because SSL context chain is invalid!");
        }
        //else it is self-signed or untrusted do not attrach any certificate

        Ssl::LocalContextStorage *ssl_ctx_cache = Ssl::TheGlobalContextStorage.getLocalStorage(port->s);
        assert(sslBumpCertKey.size() > 0 && sslBumpCertKey[0] != '\0');
        if (ctx) {
            if (!ssl_ctx_cache || !ssl_ctx_cache->add(sslBumpCertKey.termedBuf(), new Security::ContextPointer(ctx))) {
                // If it is not in storage delete after using. Else storage deleted it.
                fd_table[clientConnection->fd].dynamicTlsContext = ctx;
            }
        } else {
            debugs(33, 2, HERE << "Failed to generate SSL cert for " << sslConnectHostOrIp);
        }
    }

    // If generated ssl context = NULL, try to use static ssl context.
    if (!ctx) {
        if (!port->secure.staticContext) {
            debugs(83, DBG_IMPORTANT, "Closing " << clientConnection->remote << " as lacking TLS context");
            clientConnection->close();
            return;
        } else {
            debugs(33, 5, "Using static TLS context.");
            ctx = port->secure.staticContext;
        }
    }

    if (!httpsCreate(clientConnection, ctx))
        return;

    // bumped intercepted conns should already have Config.Timeout.request set
    // but forwarded connections may only have Config.Timeout.lifetime. [Re]set
    // to make sure the connection does not get stuck on non-SSL clients.
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5, TimeoutDialer,
                                     this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.request, timeoutCall);

    switchedToHttps_ = true;

    auto ssl = fd_table[clientConnection->fd].ssl.get();
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ClientBio *bio = static_cast<Ssl::ClientBio *>(BIO_get_data(b));
    bio->setReadBufData(inBuf);
    inBuf.clear();
    clientNegotiateSSL(clientConnection->fd, this);
}

void
ConnStateData::switchToHttps(HttpRequest *request, Ssl::BumpMode bumpServerMode)
{
    assert(!switchedToHttps_);

    sslConnectHostOrIp = request->url.host();
    resetSslCommonName(request->url.host());

    // We are going to read new request
    flags.readMore = true;
    debugs(33, 5, HERE << "converting " << clientConnection << " to SSL");

    // keep version major.minor details the same.
    // but we are now performing the HTTPS handshake traffic
    transferProtocol.protocol = AnyP::PROTO_HTTPS;

    // If sslServerBump is set, then we have decided to deny CONNECT
    // and now want to switch to SSL to send the error to the client
    // without even peeking at the origin server certificate.
    if (bumpServerMode == Ssl::bumpServerFirst && !sslServerBump) {
        request->flags.sslPeek = true;
        sslServerBump = new Ssl::ServerBump(request);
    } else if (bumpServerMode == Ssl::bumpPeek || bumpServerMode == Ssl::bumpStare) {
        request->flags.sslPeek = true;
        sslServerBump = new Ssl::ServerBump(request, NULL, bumpServerMode);
    }

    // commSetConnTimeout() was called for this request before we switched.
    // Fix timeout to request_start_timeout
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.request_start_timeout, timeoutCall);
    // Also reset receivedFirstByte_ flag to allow this timeout work in the case we have
    // a bumbed "connect" request on non transparent port.
    receivedFirstByte_ = false;
    // Get more data to peek at Tls
    parsingTlsHandshake = true;
    readSomeData();
}

void
ConnStateData::parseTlsHandshake()
{
    Must(parsingTlsHandshake);

    assert(!inBuf.isEmpty());
    receivedFirstByte();
    fd_note(clientConnection->fd, "Parsing TLS handshake");

    bool unsupportedProtocol = false;
    try {
        if (!tlsParser.parseHello(inBuf)) {
            // need more data to finish parsing
            readSomeData();
            return;
        }
    }
    catch (const std::exception &ex) {
        debugs(83, 2, "error on FD " << clientConnection->fd << ": " << ex.what());
        unsupportedProtocol = true;
    }

    parsingTlsHandshake = false;

    if (mayTunnelUnsupportedProto())
        preservedClientData = inBuf;

    // Even if the parser failed, each TLS detail should either be set
    // correctly or still be "unknown"; copying unknown detail is a no-op.
    Security::TlsDetails::Pointer const &details = tlsParser.details;
    clientConnection->tlsNegotiations()->retrieveParsedInfo(details);
    if (details && !details->serverName.isEmpty()) {
        resetSslCommonName(details->serverName.c_str());
        if (sslServerBump)
            sslServerBump->clientSni = details->serverName;
    }

    // We should disable read/write handlers
    Comm::SetSelect(clientConnection->fd, COMM_SELECT_READ, NULL, NULL, 0);
    Comm::SetSelect(clientConnection->fd, COMM_SELECT_WRITE, NULL, NULL, 0);

    if (unsupportedProtocol) {
        Http::StreamPointer context = pipeline.front();
        Must(context && context->http);
        HttpRequest::Pointer request = context->http->request;
        debugs(83, 5, "Got something other than TLS Client Hello. Cannot SslBump.");
        sslBumpMode = Ssl::bumpNone;
        if (!clientTunnelOnError(this, context, request, HttpRequestMethod(), ERR_PROTOCOL_UNKNOWN))
            clientConnection->close();
        return;
    }

    if (!sslServerBump || sslServerBump->act.step1 == Ssl::bumpClientFirst) { // Either means client-first.
        getSslContextStart();
        return;
    } else if (sslServerBump->act.step1 == Ssl::bumpServerFirst) {
        // will call httpsPeeked() with certificate and connection, eventually
        FwdState::fwdStart(clientConnection, sslServerBump->entry, sslServerBump->request.getRaw());
    } else {
        Must(sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare);
        startPeekAndSplice();
    }
}

void httpsSslBumpStep2AccessCheckDone(allow_t answer, void *data)
{
    ConnStateData *connState = (ConnStateData *) data;

    // if the connection is closed or closing, just return.
    if (!connState->isOpen())
        return;

    debugs(33, 5, "Answer: " << answer << " kind:" << answer.kind);
    assert(connState->serverBump());
    Ssl::BumpMode bumpAction;
    if (answer == ACCESS_ALLOWED) {
        bumpAction = (Ssl::BumpMode)answer.kind;
    } else
        bumpAction = Ssl::bumpSplice;

    connState->serverBump()->act.step2 = bumpAction;
    connState->sslBumpMode = bumpAction;

    if (bumpAction == Ssl::bumpTerminate) {
        connState->clientConnection->close();
    } else if (bumpAction != Ssl::bumpSplice) {
        connState->startPeekAndSplice();
    } else if (!connState->splice())
        connState->clientConnection->close();
}

bool
ConnStateData::splice()
{
    // normally we can splice here, because we just got client hello message

    if (fd_table[clientConnection->fd].ssl.get()) {
        // Restore default read methods
        fd_table[clientConnection->fd].read_method = &default_read_method;
        fd_table[clientConnection->fd].write_method = &default_write_method;
    }

    // XXX: assuming that there was an HTTP/1.1 CONNECT to begin with...
    // reset the current protocol to HTTP/1.1 (was "HTTPS" for the bumping process)
    transferProtocol = Http::ProtocolVersion();
    assert(!pipeline.empty());
    Http::StreamPointer context = pipeline.front();
    ClientHttpRequest *http = context->http;
    tunnelStart(http);
    return true;
}

void
ConnStateData::startPeekAndSplice()
{
    // This is the Step2 of the SSL bumping
    assert(sslServerBump);
    Http::StreamPointer context = pipeline.front();
    ClientHttpRequest *http = context ? context->http : nullptr;

    if (sslServerBump->step == Ssl::bumpStep1) {
        sslServerBump->step = Ssl::bumpStep2;
        // Run a accessList check to check if want to splice or continue bumping

        ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(Config.accessList.ssl_bump, sslServerBump->request.getRaw(), nullptr);
        acl_checklist->al = http ? http->al : nullptr;
        //acl_checklist->src_addr = params.conn->remote;
        //acl_checklist->my_addr = s->s;
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpNone));
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpClientFirst));
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpServerFirst));
        acl_checklist->nonBlockingCheck(httpsSslBumpStep2AccessCheckDone, this);
        return;
    }

    // will call httpsPeeked() with certificate and connection, eventually
    Security::ContextPointer unConfiguredCTX(Ssl::createSSLContext(port->signingCert, port->signPkey, *port));
    fd_table[clientConnection->fd].dynamicTlsContext = unConfiguredCTX;

    if (!httpsCreate(clientConnection, unConfiguredCTX))
        return;

    switchedToHttps_ = true;

    auto ssl = fd_table[clientConnection->fd].ssl.get();
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ClientBio *bio = static_cast<Ssl::ClientBio *>(BIO_get_data(b));
    bio->setReadBufData(inBuf);
    bio->hold(true);

    // Here squid should have all of the client hello message so the
    // Squid_SSL_accept should return 0;
    // This block exist only to force openSSL parse client hello and detect
    // ERR_SECURE_ACCEPT_FAIL error, which should be checked and splice if required.
    int ret = 0;
    if ((ret = Squid_SSL_accept(this, NULL)) < 0) {
        debugs(83, 2, "SSL_accept failed.");
        HttpRequest::Pointer request(http ? http->request : nullptr);
        if (!clientTunnelOnError(this, context, request, HttpRequestMethod(), ERR_SECURE_ACCEPT_FAIL))
            clientConnection->close();
        return;
    }

    // We need to reset inBuf here, to be used by incoming requests in the case
    // of SSL bump
    inBuf.clear();

    debugs(83, 5, "Peek and splice at step2 done. Start forwarding the request!!! ");
    FwdState::Start(clientConnection, sslServerBump->entry, sslServerBump->request.getRaw(), http ? http->al : NULL);
}

void
ConnStateData::doPeekAndSpliceStep()
{
    auto ssl = fd_table[clientConnection->fd].ssl.get();
    BIO *b = SSL_get_rbio(ssl);
    assert(b);
    Ssl::ClientBio *bio = static_cast<Ssl::ClientBio *>(BIO_get_data(b));

    debugs(33, 5, "PeekAndSplice mode, proceed with client negotiation. Currrent state:" << SSL_state_string_long(ssl));
    bio->hold(false);

    Comm::SetSelect(clientConnection->fd, COMM_SELECT_WRITE, clientNegotiateSSL, this, 0);
    switchedToHttps_ = true;
}

void
ConnStateData::httpsPeeked(Comm::ConnectionPointer serverConnection)
{
    Must(sslServerBump != NULL);

    if (Comm::IsConnOpen(serverConnection)) {
        pinConnection(serverConnection, NULL, NULL, false);

        debugs(33, 5, HERE << "bumped HTTPS server: " << sslConnectHostOrIp);
    } else {
        debugs(33, 5, HERE << "Error while bumping: " << sslConnectHostOrIp);

        //  copy error detail from bump-server-first request to CONNECT request
        if (!pipeline.empty() && pipeline.front()->http != nullptr && pipeline.front()->http->request)
            pipeline.front()->http->request->detailError(sslServerBump->request->errType, sslServerBump->request->errDetail);
    }

    getSslContextStart();
}

#endif /* USE_OPENSSL */

bool
ConnStateData::initiateTunneledRequest(HttpRequest::Pointer const &cause, Http::MethodType const method, const char *reason, const SBuf &payload)
{
    // fake a CONNECT request to force connState to tunnel
    SBuf connectHost;
    unsigned short connectPort = 0;

    if (pinning.serverConnection != nullptr) {
        static char ip[MAX_IPSTRLEN];
        connectHost.assign(pinning.serverConnection->remote.toStr(ip, sizeof(ip)));
        connectPort = pinning.serverConnection->remote.port();
    } else if (cause && cause->method == Http::METHOD_CONNECT) {
        // We are inside a (not fully established) CONNECT request
        connectHost = cause->url.host();
        connectPort = cause->url.port();
    } else {
        debugs(33, 2, "Not able to compute URL, abort request tunneling for " << reason);
        return false;
    }

    debugs(33, 2, "Request tunneling for " << reason);
    ClientHttpRequest *http = buildFakeRequest(method, connectHost, connectPort, payload);
    HttpRequest::Pointer request = http->request;
    request->flags.forceTunnel = true;
    http->calloutContext = new ClientRequestContext(http);
    http->doCallouts();
    clientProcessRequestFinished(this, request);
    return true;
}

bool
ConnStateData::fakeAConnectRequest(const char *reason, const SBuf &payload)
{
    debugs(33, 2, "fake a CONNECT request to force connState to tunnel for " << reason);

    SBuf connectHost;
    assert(transparent());
    const unsigned short connectPort = clientConnection->local.port();

#if USE_OPENSSL
    if (serverBump() && !serverBump()->clientSni.isEmpty())
        connectHost.assign(serverBump()->clientSni);
    else
#endif
    {
        static char ip[MAX_IPSTRLEN];
        connectHost.assign(clientConnection->local.toStr(ip, sizeof(ip)));
    }

    ClientHttpRequest *http = buildFakeRequest(Http::METHOD_CONNECT, connectHost, connectPort, payload);

    http->calloutContext = new ClientRequestContext(http);
    HttpRequest::Pointer request = http->request;
    http->doCallouts();
    clientProcessRequestFinished(this, request);
    return true;
}

ClientHttpRequest *
ConnStateData::buildFakeRequest(Http::MethodType const method, SBuf &useHost, unsigned short usePort, const SBuf &payload)
{
    ClientHttpRequest *http = new ClientHttpRequest(this);
    Http::Stream *stream = new Http::Stream(clientConnection, http);

    StoreIOBuffer tempBuffer;
    tempBuffer.data = stream->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;

    ClientStreamData newServer = new clientReplyContext(http);
    ClientStreamData newClient = stream;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, newServer, clientSocketRecipient,
                     clientSocketDetach, newClient, tempBuffer);

    http->uri = SBufToCstring(useHost);
    stream->flags.parsed_ok = 1; // Do we need it?
    stream->mayUseConnection(true);

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "clientLifetimeTimeout",
                                     CommTimeoutCbPtrFun(clientLifetimeTimeout, stream->http));
    commSetConnTimeout(clientConnection, Config.Timeout.lifetime, timeoutCall);

    stream->registerWithConn();

    // Setup Http::Request object. Maybe should be replaced by a call to (modified)
    // clientProcessRequest
    HttpRequest::Pointer request = new HttpRequest();
    AnyP::ProtocolType proto = (method == Http::METHOD_NONE) ? AnyP::PROTO_AUTHORITY_FORM : AnyP::PROTO_HTTP;
    request->url.setScheme(proto, nullptr);
    request->method = method;
    request->url.host(useHost.c_str());
    request->url.port(usePort);
    http->request = request.getRaw();
    HTTPMSGLOCK(http->request);

    request->clientConnectionManager = this;

    if (proto == AnyP::PROTO_HTTP)
        request->header.putStr(Http::HOST, useHost.c_str());
    request->flags.intercepted = ((clientConnection->flags & COMM_INTERCEPTION) != 0);
    request->flags.interceptTproxy = ((clientConnection->flags & COMM_TRANSPARENT) != 0 );
    request->sources |= ((switchedToHttps() || port->transport.protocol == AnyP::PROTO_HTTPS) ? HttpMsg::srcHttps : HttpMsg::srcHttp);
#if USE_AUTH
    if (getAuth())
        request->auth_user_request = getAuth();
#endif
    request->client_addr = clientConnection->remote;
#if FOLLOW_X_FORWARDED_FOR
    request->indirect_client_addr = clientConnection->remote;
#endif /* FOLLOW_X_FORWARDED_FOR */
    request->my_addr = clientConnection->local;
    request->myportname = port->name;

    inBuf = payload;
    flags.readMore = false;

    setLogUri(http, urlCanonicalClean(request.getRaw()));
    return http;
}

/// check FD after clientHttp[s]ConnectionOpened, adjust HttpSockets as needed
static bool
OpenedHttpSocket(const Comm::ConnectionPointer &c, const Ipc::FdNoteId portType)
{
    if (!Comm::IsConnOpen(c)) {
        Must(NHttpSockets > 0); // we tried to open some
        --NHttpSockets; // there will be fewer sockets than planned
        Must(HttpSockets[NHttpSockets] < 0); // no extra fds received

        if (!NHttpSockets) // we could not open any listen sockets at all
            fatalf("Unable to open %s",FdNote(portType));

        return false;
    }
    return true;
}

/// find any unused HttpSockets[] slot and store fd there or return false
static bool
AddOpenedHttpSocket(const Comm::ConnectionPointer &conn)
{
    bool found = false;
    for (int i = 0; i < NHttpSockets && !found; ++i) {
        if ((found = HttpSockets[i] < 0))
            HttpSockets[i] = conn->fd;
    }
    return found;
}

static void
clientHttpConnectionsOpen(void)
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != NULL; s = s->next) {
        const SBuf &scheme = AnyP::UriScheme(s->transport.protocol).image();

        if (MAXTCPLISTENPORTS == NHttpSockets) {
            debugs(1, DBG_IMPORTANT, "WARNING: You have too many '" << scheme << "_port' lines.");
            debugs(1, DBG_IMPORTANT, "         The limit is " << MAXTCPLISTENPORTS << " HTTP ports.");
            continue;
        }

#if USE_OPENSSL
        if (s->flags.tunnelSslBumping) {
            if (!Config.accessList.ssl_bump) {
                debugs(33, DBG_IMPORTANT, "WARNING: No ssl_bump configured. Disabling ssl-bump on " << scheme << "_port " << s->s);
                s->flags.tunnelSslBumping = false;
            }
            if (!s->secure.staticContext && !s->generateHostCertificates) {
                debugs(1, DBG_IMPORTANT, "Will not bump SSL at " << scheme << "_port " << s->s << " due to TLS initialization failure.");
                s->flags.tunnelSslBumping = false;
                if (s->transport.protocol == AnyP::PROTO_HTTP)
                    s->secure.encryptTransport = false;
            }
            if (s->flags.tunnelSslBumping) {
                // Create ssl_ctx cache for this port.
                auto sz = s->dynamicCertMemCacheSize == std::numeric_limits<size_t>::max() ? 4194304 : s->dynamicCertMemCacheSize;
                Ssl::TheGlobalContextStorage.addLocalStorage(s->s, sz);
            }
        }

        if (s->secure.encryptTransport && !s->secure.staticContext) {
            debugs(1, DBG_CRITICAL, "ERROR: Ignoring " << scheme << "_port " << s->s << " due to TLS context initialization failure.");
            continue;
        }
#endif

        // Fill out a Comm::Connection which IPC will open as a listener for us
        //  then pass back when active so we can start a TcpAcceptor subscription.
        s->listenConn = new Comm::Connection;
        s->listenConn->local = s->s;

        s->listenConn->flags = COMM_NONBLOCKING | (s->flags.tproxyIntercept ? COMM_TRANSPARENT : 0) |
                               (s->flags.natIntercept ? COMM_INTERCEPTION : 0);

        typedef CommCbFunPtrCallT<CommAcceptCbPtrFun> AcceptCall;
        if (s->transport.protocol == AnyP::PROTO_HTTP) {
            // setup the subscriptions such that new connections accepted by listenConn are handled by HTTP
            RefCount<AcceptCall> subCall = commCbCall(5, 5, "httpAccept", CommAcceptCbPtrFun(httpAccept, CommAcceptCbParams(NULL)));
            Subscription::Pointer sub = new CallSubscription<AcceptCall>(subCall);

            AsyncCall::Pointer listenCall = asyncCall(33,2, "clientListenerConnectionOpened",
                                            ListeningStartedDialer(&clientListenerConnectionOpened, s, Ipc::fdnHttpSocket, sub));
            Ipc::StartListening(SOCK_STREAM, IPPROTO_TCP, s->listenConn, Ipc::fdnHttpSocket, listenCall);

#if USE_OPENSSL
        } else if (s->transport.protocol == AnyP::PROTO_HTTPS) {
            // setup the subscriptions such that new connections accepted by listenConn are handled by HTTPS
            RefCount<AcceptCall> subCall = commCbCall(5, 5, "httpsAccept", CommAcceptCbPtrFun(httpsAccept, CommAcceptCbParams(NULL)));
            Subscription::Pointer sub = new CallSubscription<AcceptCall>(subCall);

            AsyncCall::Pointer listenCall = asyncCall(33, 2, "clientListenerConnectionOpened",
                                            ListeningStartedDialer(&clientListenerConnectionOpened,
                                                    s, Ipc::fdnHttpsSocket, sub));
            Ipc::StartListening(SOCK_STREAM, IPPROTO_TCP, s->listenConn, Ipc::fdnHttpsSocket, listenCall);
#endif
        }

        HttpSockets[NHttpSockets] = -1; // set in clientListenerConnectionOpened
        ++NHttpSockets;
    }
}

void
clientStartListeningOn(AnyP::PortCfgPointer &port, const RefCount< CommCbFunPtrCallT<CommAcceptCbPtrFun> > &subCall, const Ipc::FdNoteId fdNote)
{
    // Fill out a Comm::Connection which IPC will open as a listener for us
    port->listenConn = new Comm::Connection;
    port->listenConn->local = port->s;
    port->listenConn->flags =
        COMM_NONBLOCKING |
        (port->flags.tproxyIntercept ? COMM_TRANSPARENT : 0) |
        (port->flags.natIntercept ? COMM_INTERCEPTION : 0);

    // route new connections to subCall
    typedef CommCbFunPtrCallT<CommAcceptCbPtrFun> AcceptCall;
    Subscription::Pointer sub = new CallSubscription<AcceptCall>(subCall);
    AsyncCall::Pointer listenCall =
        asyncCall(33, 2, "clientListenerConnectionOpened",
                  ListeningStartedDialer(&clientListenerConnectionOpened,
                                         port, fdNote, sub));
    Ipc::StartListening(SOCK_STREAM, IPPROTO_TCP, port->listenConn, fdNote, listenCall);

    assert(NHttpSockets < MAXTCPLISTENPORTS);
    HttpSockets[NHttpSockets] = -1;
    ++NHttpSockets;
}

/// process clientHttpConnectionsOpen result
static void
clientListenerConnectionOpened(AnyP::PortCfgPointer &s, const Ipc::FdNoteId portTypeNote, const Subscription::Pointer &sub)
{
    Must(s != NULL);

    if (!OpenedHttpSocket(s->listenConn, portTypeNote))
        return;

    Must(Comm::IsConnOpen(s->listenConn));

    // TCP: setup a job to handle accept() with subscribed handler
    AsyncJob::Start(new Comm::TcpAcceptor(s, FdNote(portTypeNote), sub));

    debugs(1, DBG_IMPORTANT, "Accepting " <<
           (s->flags.natIntercept ? "NAT intercepted " : "") <<
           (s->flags.tproxyIntercept ? "TPROXY intercepted " : "") <<
           (s->flags.tunnelSslBumping ? "SSL bumped " : "") <<
           (s->flags.accelSurrogate ? "reverse-proxy " : "")
           << FdNote(portTypeNote) << " connections at "
           << s->listenConn);

    Must(AddOpenedHttpSocket(s->listenConn)); // otherwise, we have received a fd we did not ask for
}

void
clientOpenListenSockets(void)
{
    clientHttpConnectionsOpen();
    Ftp::StartListening();

    if (NHttpSockets < 1)
        fatal("No HTTP, HTTPS, or FTP ports configured");
}

void
clientConnectionsClose()
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != NULL; s = s->next) {
        if (s->listenConn != NULL) {
            debugs(1, DBG_IMPORTANT, "Closing HTTP(S) port " << s->listenConn->local);
            s->listenConn->close();
            s->listenConn = NULL;
        }
    }

    Ftp::StopListening();

    // TODO see if we can drop HttpSockets array entirely */
    for (int i = 0; i < NHttpSockets; ++i) {
        HttpSockets[i] = -1;
    }

    NHttpSockets = 0;
}

int
varyEvaluateMatch(StoreEntry * entry, HttpRequest * request)
{
    SBuf vary(request->vary_headers);
    int has_vary = entry->getReply()->header.has(Http::HdrType::VARY);
#if X_ACCELERATOR_VARY

    has_vary |=
        entry->getReply()->header.has(Http::HdrType::HDR_X_ACCELERATOR_VARY);
#endif

    if (!has_vary || entry->mem_obj->vary_headers.isEmpty()) {
        if (!vary.isEmpty()) {
            /* Oops... something odd is going on here.. */
            debugs(33, DBG_IMPORTANT, "varyEvaluateMatch: Oops. Not a Vary object on second attempt, '" <<
                   entry->mem_obj->urlXXX() << "' '" << vary << "'");
            request->vary_headers.clear();
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

        if (!vary.isEmpty()) {
            request->vary_headers = vary;
            return VARY_OTHER;
        } else {
            /* Ouch.. we cannot handle this kind of variance */
            /* XXX This cannot really happen, but just to be complete */
            return VARY_CANCEL;
        }
    } else {
        if (vary.isEmpty()) {
            vary = httpMakeVaryMark(request, entry->getReply());

            if (!vary.isEmpty())
                request->vary_headers = vary;
        }

        if (vary.isEmpty()) {
            /* Ouch.. we cannot handle this kind of variance */
            /* XXX This cannot really happen, but just to be complete */
            return VARY_CANCEL;
        } else if (vary.cmp(entry->mem_obj->vary_headers) == 0) {
            return VARY_MATCH;
        } else {
            /* Oops.. we have already been here and still haven't
             * found the requested variant. Bail out
             */
            debugs(33, DBG_IMPORTANT, "varyEvaluateMatch: Oops. Not a Vary match on second attempt, '" <<
                   entry->mem_obj->urlXXX() << "' '" << vary << "'");
            return VARY_CANCEL;
        }
    }
}

ACLFilledChecklist *
clientAclChecklistCreate(const acl_access * acl, ClientHttpRequest * http)
{
    ConnStateData * conn = http->getConn();
    ACLFilledChecklist *ch = new ACLFilledChecklist(acl, http->request,
            cbdataReferenceValid(conn) && conn != NULL && conn->clientConnection != NULL ? conn->clientConnection->rfc931 : dash_str);
    ch->al = http->al;
    /*
     * hack for ident ACL. It needs to get full addresses, and a place to store
     * the ident result on persistent connections...
     */
    /* connection oriented auth also needs these two lines for it's operation. */
    return ch;
}

bool
ConnStateData::transparent() const
{
    return clientConnection != NULL && (clientConnection->flags & (COMM_TRANSPARENT|COMM_INTERCEPTION));
}

BodyPipe::Pointer
ConnStateData::expectRequestBody(int64_t size)
{
    bodyPipe = new BodyPipe(this);
    if (size >= 0)
        bodyPipe->setBodySize(size);
    else
        startDechunkingRequest();
    return bodyPipe;
}

int64_t
ConnStateData::mayNeedToReadMoreBody() const
{
    if (!bodyPipe)
        return 0; // request without a body or read/produced all body bytes

    if (!bodyPipe->bodySizeKnown())
        return -1; // probably need to read more, but we cannot be sure

    const int64_t needToProduce = bodyPipe->unproducedSize();
    const int64_t haveAvailable = static_cast<int64_t>(inBuf.length());

    if (needToProduce <= haveAvailable)
        return 0; // we have read what we need (but are waiting for pipe space)

    return needToProduce - haveAvailable;
}

void
ConnStateData::stopReceiving(const char *error)
{
    debugs(33, 4, HERE << "receiving error (" << clientConnection << "): " << error <<
           "; old sending error: " <<
           (stoppedSending() ? stoppedSending_ : "none"));

    if (const char *oldError = stoppedReceiving()) {
        debugs(33, 3, HERE << "already stopped receiving: " << oldError);
        return; // nothing has changed as far as this connection is concerned
    }

    stoppedReceiving_ = error;

    if (const char *sendError = stoppedSending()) {
        debugs(33, 3, HERE << "closing because also stopped sending: " << sendError);
        clientConnection->close();
    }
}

void
ConnStateData::expectNoForwarding()
{
    if (bodyPipe != NULL) {
        debugs(33, 4, HERE << "no consumer for virgin body " << bodyPipe->status());
        bodyPipe->expectNoConsumption();
    }
}

/// initialize dechunking state
void
ConnStateData::startDechunkingRequest()
{
    Must(bodyPipe != NULL);
    debugs(33, 5, HERE << "start dechunking" << bodyPipe->status());
    assert(!bodyParser);
    bodyParser = new Http1::TeChunkedParser;
}

/// put parsed content into input buffer and clean up
void
ConnStateData::finishDechunkingRequest(bool withSuccess)
{
    debugs(33, 5, HERE << "finish dechunking: " << withSuccess);

    if (bodyPipe != NULL) {
        debugs(33, 7, HERE << "dechunked tail: " << bodyPipe->status());
        BodyPipe::Pointer myPipe = bodyPipe;
        stopProducingFor(bodyPipe, withSuccess); // sets bodyPipe->bodySize()
        Must(!bodyPipe); // we rely on it being nil after we are done with body
        if (withSuccess) {
            Must(myPipe->bodySizeKnown());
            Http::StreamPointer context = pipeline.front();
            if (context != NULL && context->http && context->http->request)
                context->http->request->setContentLength(myPipe->bodySize());
        }
    }

    delete bodyParser;
    bodyParser = NULL;
}

// XXX: this is an HTTP/1-only operation
void
ConnStateData::sendControlMsg(HttpControlMsg msg)
{
    if (!isOpen()) {
        debugs(33, 3, HERE << "ignoring 1xx due to earlier closure");
        return;
    }

    // HTTP/1 1xx status messages are only valid when there is a transaction to trigger them
    if (!pipeline.empty()) {
        HttpReply::Pointer rep(msg.reply);
        Must(rep);
        // remember the callback
        cbControlMsgSent = msg.cbSuccess;

        typedef CommCbMemFunT<HttpControlMsgSink, CommIoCbParams> Dialer;
        AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, HttpControlMsgSink::wroteControlMsg);

        if (!writeControlMsgAndCall(rep.getRaw(), call)) {
            // but still inform the caller (so it may resume its operation)
            doneWithControlMsg();
        }
        return;
    }

    debugs(33, 3, HERE << " closing due to missing context for 1xx");
    clientConnection->close();
}

void
ConnStateData::doneWithControlMsg()
{
    HttpControlMsgSink::doneWithControlMsg();

    if (Http::StreamPointer deferredRequest = pipeline.front()) {
        debugs(33, 3, clientConnection << ": calling PushDeferredIfNeeded after control msg wrote");
        ClientSocketContextPushDeferredIfNeeded(deferredRequest, this);
    }
}

/// Our close handler called by Comm when the pinned connection is closed
void
ConnStateData::clientPinnedConnectionClosed(const CommCloseCbParams &io)
{
    // FwdState might repin a failed connection sooner than this close
    // callback is called for the failed connection.
    assert(pinning.serverConnection == io.conn);
    pinning.closeHandler = NULL; // Comm unregisters handlers before calling
    const bool sawZeroReply = pinning.zeroReply; // reset when unpinning
    pinning.serverConnection->noteClosure();
    unpinConnection(false);

    if (sawZeroReply && clientConnection != NULL) {
        debugs(33, 3, "Closing client connection on pinned zero reply.");
        clientConnection->close();
    }

}

void
ConnStateData::pinConnection(const Comm::ConnectionPointer &pinServer, HttpRequest *request, CachePeer *aPeer, bool auth, bool monitor)
{
    if (!Comm::IsConnOpen(pinning.serverConnection) ||
            pinning.serverConnection->fd != pinServer->fd)
        pinNewConnection(pinServer, request, aPeer, auth);

    if (monitor)
        startPinnedConnectionMonitoring();
}

void
ConnStateData::pinNewConnection(const Comm::ConnectionPointer &pinServer, HttpRequest *request, CachePeer *aPeer, bool auth)
{
    unpinConnection(true); // closes pinned connection, if any, and resets fields

    pinning.serverConnection = pinServer;

    debugs(33, 3, HERE << pinning.serverConnection);

    Must(pinning.serverConnection != NULL);

    // when pinning an SSL bumped connection, the request may be NULL
    const char *pinnedHost = "[unknown]";
    if (request) {
        pinning.host = xstrdup(request->url.host());
        pinning.port = request->url.port();
        pinnedHost = pinning.host;
    } else {
        pinning.port = pinServer->remote.port();
    }
    pinning.pinned = true;
    if (aPeer)
        pinning.peer = cbdataReference(aPeer);
    pinning.auth = auth;
    char stmp[MAX_IPSTRLEN];
    char desc[FD_DESC_SZ];
    snprintf(desc, FD_DESC_SZ, "%s pinned connection for %s (%d)",
             (auth || !aPeer) ? pinnedHost : aPeer->name,
             clientConnection->remote.toUrl(stmp,MAX_IPSTRLEN),
             clientConnection->fd);
    fd_note(pinning.serverConnection->fd, desc);

    typedef CommCbMemFunT<ConnStateData, CommCloseCbParams> Dialer;
    pinning.closeHandler = JobCallback(33, 5,
                                       Dialer, this, ConnStateData::clientPinnedConnectionClosed);
    // remember the pinned connection so that cb does not unpin a fresher one
    typedef CommCloseCbParams Params;
    Params &params = GetCommParams<Params>(pinning.closeHandler);
    params.conn = pinning.serverConnection;
    comm_add_close_handler(pinning.serverConnection->fd, pinning.closeHandler);
}

/// [re]start monitoring pinned connection for peer closures so that we can
/// propagate them to an _idle_ client pinned to that peer
void
ConnStateData::startPinnedConnectionMonitoring()
{
    if (pinning.readHandler != NULL)
        return; // already monitoring

    typedef CommCbMemFunT<ConnStateData, CommIoCbParams> Dialer;
    pinning.readHandler = JobCallback(33, 3,
                                      Dialer, this, ConnStateData::clientPinnedConnectionRead);
    Comm::Read(pinning.serverConnection, pinning.readHandler);
}

void
ConnStateData::stopPinnedConnectionMonitoring()
{
    if (pinning.readHandler != NULL) {
        Comm::ReadCancel(pinning.serverConnection->fd, pinning.readHandler);
        pinning.readHandler = NULL;
    }
}

#if USE_OPENSSL
bool
ConnStateData::handleIdleClientPinnedTlsRead()
{
    // A ready-for-reading connection means that the TLS server either closed
    // the connection, sent us some unexpected HTTP data, or started TLS
    // renegotiations. We should close the connection except for the last case.

    Must(pinning.serverConnection != nullptr);
    auto ssl = fd_table[pinning.serverConnection->fd].ssl.get();
    if (!ssl)
        return false;

    char buf[1];
    const int readResult = SSL_read(ssl, buf, sizeof(buf));

    if (readResult > 0 || SSL_pending(ssl) > 0) {
        debugs(83, 2, pinning.serverConnection << " TLS application data read");
        return false;
    }

    switch(const int error = SSL_get_error(ssl, readResult)) {
    case SSL_ERROR_WANT_WRITE:
        debugs(83, DBG_IMPORTANT, pinning.serverConnection << " TLS SSL_ERROR_WANT_WRITE request for idle pinned connection");
    // fall through to restart monitoring, for now
    case SSL_ERROR_NONE:
    case SSL_ERROR_WANT_READ:
        startPinnedConnectionMonitoring();
        return true;

    default:
        debugs(83, 2, pinning.serverConnection << " TLS error: " << error);
        return false;
    }

    // not reached
    return true;
}
#endif

/// Our read handler called by Comm when the server either closes an idle pinned connection or
/// perhaps unexpectedly sends something on that idle (from Squid p.o.v.) connection.
void
ConnStateData::clientPinnedConnectionRead(const CommIoCbParams &io)
{
    pinning.readHandler = NULL; // Comm unregisters handlers before calling

    if (io.flag == Comm::ERR_CLOSING)
        return; // close handler will clean up

    Must(pinning.serverConnection == io.conn);

#if USE_OPENSSL
    if (handleIdleClientPinnedTlsRead())
        return;
#endif

    const bool clientIsIdle = pipeline.empty();

    debugs(33, 3, "idle pinned " << pinning.serverConnection << " read " <<
           io.size << (clientIsIdle ? " with idle client" : ""));

    pinning.serverConnection->close();

    // If we are still sending data to the client, do not close now. When we are done sending,
    // ConnStateData::kick() checks pinning.serverConnection and will close.
    // However, if we are idle, then we must close to inform the idle client and minimize races.
    if (clientIsIdle && clientConnection != NULL)
        clientConnection->close();
}

const Comm::ConnectionPointer
ConnStateData::validatePinnedConnection(HttpRequest *request, const CachePeer *aPeer)
{
    debugs(33, 7, HERE << pinning.serverConnection);

    bool valid = true;
    if (!Comm::IsConnOpen(pinning.serverConnection))
        valid = false;
    else if (pinning.auth && pinning.host && request && strcasecmp(pinning.host, request->url.host()) != 0)
        valid = false;
    else if (request && pinning.port != request->url.port())
        valid = false;
    else if (pinning.peer && !cbdataReferenceValid(pinning.peer))
        valid = false;
    else if (aPeer != pinning.peer)
        valid = false;

    if (!valid) {
        /* The pinning info is not safe, remove any pinning info */
        unpinConnection(true);
    }

    return pinning.serverConnection;
}

Comm::ConnectionPointer
ConnStateData::borrowPinnedConnection(HttpRequest *request, const CachePeer *aPeer)
{
    debugs(33, 7, pinning.serverConnection);
    if (validatePinnedConnection(request, aPeer) != NULL)
        stopPinnedConnectionMonitoring();

    return pinning.serverConnection; // closed if validation failed
}

void
ConnStateData::unpinConnection(const bool andClose)
{
    debugs(33, 3, HERE << pinning.serverConnection);

    if (pinning.peer)
        cbdataReferenceDone(pinning.peer);

    if (Comm::IsConnOpen(pinning.serverConnection)) {
        if (pinning.closeHandler != NULL) {
            comm_remove_close_handler(pinning.serverConnection->fd, pinning.closeHandler);
            pinning.closeHandler = NULL;
        }

        stopPinnedConnectionMonitoring();

        // close the server side socket if requested
        if (andClose)
            pinning.serverConnection->close();
        pinning.serverConnection = NULL;
    }

    safe_free(pinning.host);

    pinning.zeroReply = false;

    /* NOTE: pinning.pinned should be kept. This combined with fd == -1 at the end of a request indicates that the host
     * connection has gone away */
}

void
ConnStateData::checkLogging()
{
    // if we are parsing request body, its request is responsible for logging
    if (bodyPipe)
        return;

    // a request currently using this connection is responsible for logging
    if (!pipeline.empty() && pipeline.back()->mayUseConnection())
        return;

    /* Either we are waiting for the very first transaction, or
     * we are done with the Nth transaction and are waiting for N+1st.
     * XXX: We assume that if anything was added to inBuf, then it could
     * only be consumed by actions already covered by the above checks.
     */

    // do not log connections that closed after a transaction (it is normal)
    // TODO: access_log needs ACLs to match received-no-bytes connections
    if (pipeline.nrequests && inBuf.isEmpty())
        return;

    /* Create a temporary ClientHttpRequest object. Its destructor will log. */
    ClientHttpRequest http(this);
    http.req_sz = inBuf.length();
    char const *uri = "error:transaction-end-before-headers";
    http.uri = xstrdup(uri);
    setLogUri(&http, uri);
}

bool
ConnStateData::mayTunnelUnsupportedProto()
{
    return Config.accessList.on_unsupported_protocol
#if USE_OPENSSL
           &&
           ((port->flags.isIntercepted() && port->flags.tunnelSslBumping)
            || (serverBump() && pinning.serverConnection))
#endif
           ;
}

