/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "base/AsyncCallbacks.h"
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
#include "debug/Messages.h"
#include "error/ExceptionErrorDetail.h"
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
#include "proxyp/Header.h"
#include "proxyp/Parser.h"
#include "sbuf/Stream.h"
#include "security/Certificate.h"
#include "security/CommunicationSecrets.h"
#include "security/Io.h"
#include "security/KeyLog.h"
#include "security/NegotiationHistory.h"
#include "servers/forward.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"
#include "TimeOrTag.h"
#include "tools.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "ClientInfo.h"
#include "MessageDelayPools.h"
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

#include <climits>
#include <cmath>
#include <limits>

#if HAVE_SYSTEMD_SD_DAEMON_H
#include <systemd/sd-daemon.h>
#endif

// TODO: Remove this custom dialer and simplify by creating the TcpAcceptor
// subscription later, inside clientListenerConnectionOpened() callback, just
// like htcpOpenPorts(), icpOpenPorts(), and snmpPortOpened() do it.
/// dials clientListenerConnectionOpened call
class ListeningStartedDialer:
    public CallDialer,
    public WithAnswer<Ipc::StartListeningAnswer>
{
public:
    typedef void (*Handler)(AnyP::PortCfgPointer &portCfg, const Ipc::FdNoteId note, const Subscription::Pointer &sub);
    ListeningStartedDialer(Handler aHandler, AnyP::PortCfgPointer &aPortCfg, const Ipc::FdNoteId note, const Subscription::Pointer &aSub):
        handler(aHandler), portCfg(aPortCfg), portTypeNote(note), sub(aSub) {}

    /* CallDialer API */
    void print(std::ostream &os) const override {
        os << '(' << answer_ << ", " << FdNote(portTypeNote) << " port=" << (void*)&portCfg << ')';
    }

    virtual bool canDial(AsyncCall &) const { return true; }
    virtual void dial(AsyncCall &) { (handler)(portCfg, portTypeNote, sub); }

    /* WithAnswer API */
    Ipc::StartListeningAnswer &answer() override { return answer_; }

public:
    Handler handler;

private:
    // answer_.conn (set/updated by IPC code) is portCfg.listenConn (used by us)
    Ipc::StartListeningAnswer answer_; ///< StartListening() results
    AnyP::PortCfgPointer portCfg;   ///< from HttpPortList
    Ipc::FdNoteId portTypeNote;    ///< Type of IPC socket being opened
    Subscription::Pointer sub; ///< The handler to be subscribed for this connection listener
};

static void clientListenerConnectionOpened(AnyP::PortCfgPointer &s, const Ipc::FdNoteId portTypeNote, const Subscription::Pointer &sub);

static IOACB httpAccept;
#if USE_IDENT
static IDCB clientIdentDone;
#endif
static int clientIsRequestBodyTooLargeForPolicy(int64_t bodyLength);

static void clientUpdateStatHistCounters(const LogTags &logType, int svc_time);
static void clientUpdateStatCounters(const LogTags &logType);
static void clientUpdateHierCounters(HierarchyLogEntry *);
static bool clientPingHasFinished(ping_data const *aPing);
void prepareLogWithRequestDetails(HttpRequest *, const AccessLogEntryPointer &);
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
    clientUpdateStatCounters(loggingTags());

    if (request->error)
        ++ statCounter.client_http.errors;

    clientUpdateStatHistCounters(loggingTags(),
                                 tvSubMsec(al->cache.start_time, current_time));

    clientUpdateHierCounters(&request->hier);
}

void
prepareLogWithRequestDetails(HttpRequest *request, const AccessLogEntryPointer &aLogEntry)
{
    assert(request);
    assert(aLogEntry != nullptr);

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
        if (ah != nullptr) {
            mb.reset();
            ah->lastMeta.packInto(&mb);
            aLogEntry->adapt.last_meta = xstrdup(mb.buf);
        }
#endif

        mb.clean();
    }

#if ICAP_CLIENT
    const Adaptation::Icap::History::Pointer ih = request->icapHistory();
    if (ih != nullptr)
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
        aLogEntry->request->error = request->error;
    }
}

void
ClientHttpRequest::logRequest()
{
    if (!out.size && loggingTags().oldType == LOG_TAG_NONE)
        debugs(33, 5, "logging half-baked transaction: " << log_uri);

    al->icp.opcode = ICP_INVALID;
    al->url = log_uri;
    debugs(33, 9, "clientLogRequest: al.url='" << al->url << "'");

    const auto findReply = [this]() -> const HttpReply * {
        if (al->reply)
            return al->reply.getRaw();
        if (const auto le = loggingEntry())
            return le->hasFreshestReply();
        return nullptr;
    };
    if (const auto reply = findReply()) {
        al->http.code = reply->sline.status();
        al->http.content_type = reply->content_type.termedBuf();
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

    tvSub(al->cache.trTime, al->cache.start_time, current_time);

    if (request)
        prepareLogWithRequestDetails(request, al);

#if USE_OPENSSL && 0

    /* This is broken. Fails if the connection has been closed. Needs
     * to snarf the ssl details some place earlier..
     */
    if (getConn() != NULL)
        al->cache.ssluser = sslGetUserEmail(fd_table[getConn()->fd].ssl);

#endif

    /* Add notes (if we have a request to annotate) */
    if (request) {
        SBuf matched;
        for (auto h: Config.notes) {
            if (h->match(request, al->reply.getRaw(), al, matched)) {
                request->notes()->add(h->key(), matched);
                debugs(33, 3, h->key() << " " << matched);
            }
        }
        // The al->notes and request->notes must point to the same object.
        al->syncNotes(request);
    }

    ACLFilledChecklist checklist(nullptr, request, nullptr);
    if (al->reply) {
        checklist.reply = al->reply.getRaw();
        HTTPMSGLOCK(checklist.reply);
    }

    if (request) {
        HTTPMSGUNLOCK(al->adapted_request);
        al->adapted_request = request;
        HTTPMSGLOCK(al->adapted_request);
    }
    // no need checklist.syncAle(): already synced
    checklist.al = al;
    accessLogLog(al, &checklist);

    bool updatePerformanceCounters = true;
    if (Config.accessList.stats_collection) {
        ACLFilledChecklist statsCheck(Config.accessList.stats_collection, request, nullptr);
        statsCheck.al = al;
        if (al->reply) {
            statsCheck.reply = al->reply.getRaw();
            HTTPMSGLOCK(statsCheck.reply);
        }
        updatePerformanceCounters = statsCheck.fastCheck().allowed();
    }

    if (updatePerformanceCounters) {
        if (request)
            updateCounters();

        if (getConn() != nullptr && getConn()->clientConnection != nullptr)
            clientdbUpdate(getConn()->clientConnection->remote, loggingTags(), AnyP::PROTO_HTTP, out.size);
    }
}

void
ClientHttpRequest::freeResources()
{
    safe_free(uri);
    safe_free(redirect.location);
    range_iter.boundary.clean();
    clearRequest();

    if (client_stream.tail)
        clientStreamAbort((clientStreamNode *)client_stream.tail->data, this);
}

void
httpRequestFree(void *data)
{
    ClientHttpRequest *http = (ClientHttpRequest *)data;
    assert(http != nullptr);
    delete http;
}

/* This is a handler normally called by comm_close() */
void ConnStateData::connStateClosed(const CommCloseCbParams &)
{
    if (clientConnection) {
        clientConnection->noteClosure();
        // keep closed clientConnection for logging, clientdb cleanup, etc.
    }
    deleteThis("ConnStateData::connStateClosed");
}

#if USE_AUTH
void
ConnStateData::setAuth(const Auth::UserRequest::Pointer &aur, const char *by)
{
    if (auth_ == nullptr) {
        if (aur != nullptr) {
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
    if (aur == nullptr) {
        debugs(33, 2, "WARNING: Graceful closure on " << clientConnection << " due to connection-auth erase from " << by);
        auth_->releaseAuthServer();
        auth_ = nullptr;
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
        auth_ = nullptr;
        // this is a fatal type of problem.
        // Close the connection immediately with TCP RST to abort all traffic flow
        comm_reset_close(clientConnection);
        return;
    }

    /* NOT REACHABLE */
}
#endif

void
ConnStateData::resetReadTimeout(const time_t timeout)
{
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer callback = JobCallback(33, 5, TimeoutDialer, this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, timeout, callback);
}

void
ConnStateData::extendLifetime()
{
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer callback = JobCallback(5, 4, TimeoutDialer, this, ConnStateData::lifetimeTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.lifetime, callback);
}

// cleans up before destructor is called
void
ConnStateData::swanSong()
{
    debugs(33, 2, clientConnection);

    flags.readMore = false;
    clientdbEstablished(clientConnection->remote, -1);  /* decrement */

    terminateAll(ERR_NONE, LogTagsErrors());
    checkLogging();

    // XXX: Closing pinned conn is too harsh: The Client may want to continue!
    unpinConnection(true);

    Server::swanSong();

#if USE_AUTH
    // NP: do this bit after closing the connections to avoid side effects from unwanted TCP RST
    setAuth(nullptr, "ConnStateData::SwanSong cleanup");
#endif

    flags.swanSang = true;
}

void
ConnStateData::callException(const std::exception &ex)
{
    Server::callException(ex); // logs ex and stops the job

    ErrorDetail::Pointer errorDetail;
    if (const auto tex = dynamic_cast<const TextException*>(&ex))
        errorDetail = new ExceptionErrorDetail(tex->id());
    else
        errorDetail = new ExceptionErrorDetail(Here().id());
    updateError(ERR_GATEWAY_FAILURE, errorDetail);
}

void
ConnStateData::updateError(const Error &error)
{
    if (const auto context = pipeline.front()) {
        const auto http = context->http;
        assert(http);
        http->updateError(error);
    } else {
        bareError.update(error);
    }
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
    debugs(33, 3, clientConnection);

    if (isOpen())
        debugs(33, DBG_IMPORTANT, "ERROR: Squid BUG: ConnStateData did not close " << clientConnection);

    if (!flags.swanSang)
        debugs(33, DBG_IMPORTANT, "ERROR: Squid BUG: ConnStateData was not destroyed properly; " << clientConnection);

    if (bodyPipe != nullptr)
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
clientPackRangeHdr(const HttpReplyPointer &rep, const HttpHdrRangeSpec * spec, String boundary, MemBuf * mb)
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
int64_t
ClientHttpRequest::mRangeCLen() const
{
    int64_t clen = 0;
    MemBuf mb;

    assert(memObject());

    mb.init();
    HttpHdrRange::iterator pos = request->range->begin();

    while (pos != request->range->end()) {
        /* account for headers for this range */
        mb.reset();
        clientPackRangeHdr(&storeEntry()->mem().freshestReply(),
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
    String b(visible_appname_string);
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
    // do not try to deliver if client already ABORTED
    if (!http->getConn() || !cbdataReferenceValid(http->getConn()) || !Comm::IsConnOpen(http->getConn()->clientConnection))
        return;

    /* Test preconditions */
    assert(node != nullptr);
    /* TODO: handle this rather than asserting
     * - it should only ever happen if we cause an abort and
     * the callback chain loops back to here, so we can simply return.
     * However, that itself shouldn't happen, so it stays as an assert for now.
     */
    assert(cbdataReferenceValid(node));
    assert(node->node.next == nullptr);
    Http::StreamPointer context = dynamic_cast<Http::Stream *>(node->data.getRaw());
    assert(context != nullptr);

    /* TODO: check offset is what we asked for */

    // TODO: enforces HTTP/1 MUST on pipeline order, but is irrelevant to HTTP/2
    if (context != http->getConn()->pipeline.front())
        context->deferRecipientForLater(node, rep, receivedData);
    else if (http->getConn()->cbControlMsgSent) // 1xx to the user is pending
        context->deferRecipientForLater(node, rep, receivedData);
    else
        http->getConn()->handleReply(rep, receivedData);
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
    assert(node != nullptr);
    /* TODO: handle this rather than asserting
     * - it should only ever happen if we cause an abort and
     * the callback chain loops back to here, so we can simply return.
     * However, that itself shouldn't happen, so it stays as an assert for now.
     */
    assert(cbdataReferenceValid(node));
    /* Set null by ContextFree */
    assert(node->node.next == nullptr);
    /* this is the assert discussed above */
    assert(nullptr == dynamic_cast<Http::Stream *>(node->data.getRaw()));
    /* We are only called when the client socket shutsdown.
     * Tell the prev pipeline member we're finished
     */
    clientStreamDetach(node, http);
}

void
ConnStateData::readNextRequest()
{
    debugs(33, 5, clientConnection << " reading next req");

    fd_note(clientConnection->fd, "Idle client: Waiting for next request");
    /**
     * Set the timeout BEFORE calling readSomeData().
     */
    resetReadTimeout(clientConnection->timeLeft(idleTimeout()));

    readSomeData();
    /** Please don't do anything with the FD past here! */
}

static void
ClientSocketContextPushDeferredIfNeeded(Http::StreamPointer deferredRequest, ConnStateData * conn)
{
    debugs(33, 2, conn->clientConnection << " Sending next");

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
    debugs(33, 4, "sending error (" << clientConnection << "): " << error <<
           "; old receiving error: " <<
           (stoppedReceiving() ? stoppedReceiving_ : "none"));

    if (const char *oldError = stoppedSending()) {
        debugs(33, 3, "already stopped sending: " << oldError);
        return; // nothing has changed as far as this connection is concerned
    }
    stoppedSending_ = error;

    if (!stoppedReceiving()) {
        if (const int64_t expecting = mayNeedToReadMoreBody()) {
            debugs(33, 5, "must still read " << expecting <<
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
        if (ctx->http->loggingTags().isTcpHit())
            statCounter.client_http.hit_kbytes_out += size;
    }
    ctx->writeComplete(size);
}

Http::Stream *
ConnStateData::abortRequestParsing(const char *const uri)
{
    ClientHttpRequest *http = new ClientHttpRequest(this);
    http->req_sz = inBuf.length();
    http->setErrorUri(uri);
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
    if (nullptr == end) {
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

    return nullptr;
}

static char *
prepareAcceleratedURL(ConnStateData * conn, const Http1::RequestParserPointer &hp)
{
    int vhost = conn->port->vhost;
    int vport = conn->port->vport;
    static char ipbuf[MAX_IPSTRLEN];

    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */

    static const SBuf cache_object("cache_object://");
    if (hp->requestUri().startsWith(cache_object))
        return nullptr; /* already in good shape */

    // XXX: re-use proper URL parser for this
    SBuf url = hp->requestUri(); // use full provided URI if we abort
    do { // use a loop so we can break out of it
        ::Parser::Tokenizer tok(url);
        if (tok.skip('/')) // origin-form URL already.
            break;

        if (conn->port->vhost)
            return nullptr; /* already in good shape */

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
        vport = conn->clientConnection->local.port();

    char *receivedHost = nullptr;
    if (vhost && (receivedHost = hp->getHostHeaderField())) {
        SBuf host(receivedHost);
        debugs(33, 5, "ACCEL VHOST REWRITE: vhost=" << host << " + vport=" << vport);
        if (vport > 0) {
            // remove existing :port (if any), cope with IPv6+ without port
            const auto lastColonPos = host.rfind(':');
            if (lastColonPos != SBuf::npos && *host.rbegin() != ']') {
                host.chop(0, lastColonPos); // truncate until the last colon
            }
            host.appendf(":%d", vport);
        } // else nothing to alter port-wise.
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        const auto url_sz = scheme.length() + host.length() + url.length() + 32;
        char *uri = static_cast<char *>(xcalloc(url_sz, 1));
        snprintf(uri, url_sz, SQUIDSBUFPH "://" SQUIDSBUFPH SQUIDSBUFPH, SQUIDSBUFPRINT(scheme), SQUIDSBUFPRINT(host), SQUIDSBUFPRINT(url));
        debugs(33, 5, "ACCEL VHOST REWRITE: " << uri);
        return uri;
    } else if (conn->port->defaultsite /* && !vhost */) {
        debugs(33, 5, "ACCEL DEFAULTSITE REWRITE: defaultsite=" << conn->port->defaultsite << " + vport=" << vport);
        char vportStr[32];
        vportStr[0] = '\0';
        if (vport > 0) {
            snprintf(vportStr, sizeof(vportStr),":%d",vport);
        }
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        const int url_sz = scheme.length() + strlen(conn->port->defaultsite) + sizeof(vportStr) + url.length() + 32;
        char *uri = static_cast<char *>(xcalloc(url_sz, 1));
        snprintf(uri, url_sz, SQUIDSBUFPH "://%s%s" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme), conn->port->defaultsite, vportStr, SQUIDSBUFPRINT(url));
        debugs(33, 5, "ACCEL DEFAULTSITE REWRITE: " << uri);
        return uri;
    } else if (vport > 0 /* && (!vhost || no Host:) */) {
        debugs(33, 5, "ACCEL VPORT REWRITE: *_port IP + vport=" << vport);
        /* Put the local socket IP address as the hostname, with whatever vport we found  */
        conn->clientConnection->local.toHostStr(ipbuf,MAX_IPSTRLEN);
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        const int url_sz = scheme.length() + sizeof(ipbuf) + url.length() + 32;
        char *uri = static_cast<char *>(xcalloc(url_sz, 1));
        snprintf(uri, url_sz, SQUIDSBUFPH "://%s:%d" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme), ipbuf, vport, SQUIDSBUFPRINT(url));
        debugs(33, 5, "ACCEL VPORT REWRITE: " << uri);
        return uri;
    }

    return nullptr;
}

static char *
buildUrlFromHost(ConnStateData * conn, const Http1::RequestParserPointer &hp)
{
    char *uri = nullptr;
    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */
    if (const char *host = hp->getHostHeaderField()) {
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        const int url_sz = scheme.length() + strlen(host) + hp->requestUri().length() + 32;
        uri = static_cast<char *>(xcalloc(url_sz, 1));
        snprintf(uri, url_sz, SQUIDSBUFPH "://%s" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme),
                 host,
                 SQUIDSBUFPRINT(hp->requestUri()));
    }
    return uri;
}

char *
ConnStateData::prepareTlsSwitchingURL(const Http1::RequestParserPointer &hp)
{
    Must(switchedToHttps());

    if (!hp->requestUri().isEmpty() && hp->requestUri()[0] != '/')
        return nullptr; /* already in good shape */

    char *uri = buildUrlFromHost(this, hp);
#if USE_OPENSSL
    if (!uri) {
        Must(tlsConnectPort);
        Must(!tlsConnectHostOrIp.isEmpty());
        SBuf useHost;
        if (!tlsClientSni().isEmpty())
            useHost = tlsClientSni();
        else
            useHost = tlsConnectHostOrIp;

        const SBuf &scheme = AnyP::UriScheme(transferProtocol.protocol).image();
        const int url_sz = scheme.length() + useHost.length() + hp->requestUri().length() + 32;
        uri = static_cast<char *>(xcalloc(url_sz, 1));
        snprintf(uri, url_sz, SQUIDSBUFPH "://" SQUIDSBUFPH ":%d" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme),
                 SQUIDSBUFPRINT(useHost),
                 tlsConnectPort,
                 SQUIDSBUFPRINT(hp->requestUri()));
    }
#endif
    if (uri)
        debugs(33, 5, "TLS switching host rewrite: " << uri);
    return uri;
}

static char *
prepareTransparentURL(ConnStateData * conn, const Http1::RequestParserPointer &hp)
{
    // TODO Must() on URI !empty when the parser supports throw. For now avoid assert().
    if (!hp->requestUri().isEmpty() && hp->requestUri()[0] != '/')
        return nullptr; /* already in good shape */

    char *uri = buildUrlFromHost(conn, hp);
    if (!uri) {
        /* Put the local socket IP address as the hostname.  */
        static char ipbuf[MAX_IPSTRLEN];
        conn->clientConnection->local.toHostStr(ipbuf,MAX_IPSTRLEN);
        const SBuf &scheme = AnyP::UriScheme(conn->transferProtocol.protocol).image();
        const int url_sz = sizeof(ipbuf) + hp->requestUri().length() + 32;
        uri = static_cast<char *>(xcalloc(url_sz, 1));
        snprintf(uri, url_sz, SQUIDSBUFPH "://%s:%d" SQUIDSBUFPH,
                 SQUIDSBUFPRINT(scheme),
                 ipbuf, conn->clientConnection->local.port(), SQUIDSBUFPRINT(hp->requestUri()));
    }

    if (uri)
        debugs(33, 5, "TRANSPARENT REWRITE: " << uri);
    return uri;
}

Http::Stream *
ConnStateData::parseHttpRequest(const Http1::RequestParserPointer &hp)
{
    /* Attempt to parse the first line; this will define where the method, url, version and header begin */
    {
        Must(hp);

        if (preservingClientData_)
            preservedClientData = inBuf;

        const bool parsedOk = hp->parse(inBuf);

        // sync the buffers after parsing.
        inBuf = hp->remaining();

        if (hp->needsMoreData()) {
            debugs(33, 5, "Incomplete request, waiting for end of request line");
            return nullptr;
        }

        if (!parsedOk) {
            const bool tooBig =
                hp->parseStatusCode == Http::scRequestHeaderFieldsTooLarge ||
                hp->parseStatusCode == Http::scUriTooLong;
            auto result = abortRequestParsing(
                              tooBig ? "error:request-too-large" : "error:invalid-request");
            // assume that remaining leftovers belong to this bad request
            if (!inBuf.isEmpty())
                consumeInput(inBuf.length());
            return result;
        }
    }

    /* We know the whole request is in parser now */
    debugs(11, 2, "HTTP Client " << clientConnection);
    debugs(11, 2, "HTTP Client REQUEST:\n---------\n" <<
           hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol() << "\n" <<
           hp->mimeHeader() <<
           "\n----------");

    /* deny CONNECT via accelerated ports */
    if (hp->method() == Http::METHOD_CONNECT && port != nullptr && port->flags.accelSurrogate) {
        debugs(33, DBG_IMPORTANT, "WARNING: CONNECT method received on " << transferProtocol << " Accelerator port " << port->s.port());
        debugs(33, DBG_IMPORTANT, "WARNING: for request: " << hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol());
        hp->parseStatusCode = Http::scMethodNotAllowed;
        return abortRequestParsing("error:method-not-allowed");
    }

    /* HTTP/2 connection magic prefix starts with "PRI ".
     * Deny "PRI" method if used in HTTP/1.x or 0.9 versions.
     * If seen it signals a broken client or proxy has corrupted the traffic.
     */
    if (hp->method() == Http::METHOD_PRI && hp->messageProtocol() < Http::ProtocolVersion(2,0)) {
        debugs(33, DBG_IMPORTANT, "WARNING: PRI method received on " << transferProtocol << " port " << port->s.port());
        debugs(33, DBG_IMPORTANT, "WARNING: for request: " << hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol());
        hp->parseStatusCode = Http::scMethodNotAllowed;
        return abortRequestParsing("error:method-not-allowed");
    }

    if (hp->method() == Http::METHOD_NONE) {
        debugs(33, DBG_IMPORTANT, "WARNING: Unsupported method: " << hp->method() << " " << hp->requestUri() << " " << hp->messageProtocol());
        hp->parseStatusCode = Http::scMethodNotAllowed;
        return abortRequestParsing("error:unsupported-request-method");
    }

    // Process headers after request line
    debugs(33, 3, "complete request received. " <<
           "prefix_sz = " << hp->messageHeaderSize() <<
           ", request-line-size=" << hp->firstLineSize() <<
           ", mime-header-size=" << hp->headerBlockSize() <<
           ", mime header block:\n" << hp->mimeHeader() << "\n----------");

    /* Ok, all headers are received */
    ClientHttpRequest *http = new ClientHttpRequest(this);

    http->req_sz = hp->messageHeaderSize();
    Http::Stream *result = new Http::Stream(clientConnection, http);

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
           (transparent()?"intercept":(port->flags.accelSurrogate ? "accel":"")));
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
    if (switchedToHttps()) {
        http->uri = prepareTlsSwitchingURL(hp);
    } else if (transparent()) {
        /* intercept or transparent mode, properly working with no failures */
        http->uri = prepareTransparentURL(this, hp);

    } else if (internalCheck(hp->requestUri())) { // NP: only matches relative-URI
        /* internal URL mode */
        /* prepend our name & port */
        http->uri = xstrdup(internalLocalUri(nullptr, hp->requestUri()));
        // We just re-wrote the URL. Must replace the Host: header.
        //  But have not parsed there yet!! flag for local-only handling.
        http->flags.internal = true;

    } else if (port->flags.accelSurrogate) {
        /* accelerator mode */
        http->uri = prepareAcceleratedURL(this, hp);
        http->flags.accel = true;
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
ConnStateData::shouldCloseOnEof() const
{
    if (pipeline.empty() && inBuf.isEmpty()) {
        debugs(33, 4, "yes, without active requests and unparsed input");
        return true;
    }

    if (!Config.onoff.half_closed_clients) {
        debugs(33, 3, "yes, without half_closed_clients");
        return true;
    }

    // Squid currently tries to parse (possibly again) a partially received
    // request after an EOF with half_closed_clients. To give that last parse in
    // afterClientRead() a chance, we ignore partially parsed requests here.
    debugs(33, 3, "no, honoring half_closed_clients");
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
        debugs(33, 3, "truncated body: closing half-closed " << clientConnection);
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
    debugs(33,4, "Will close after error: " << clientConnection);
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

        // Get error details from the fake certificate-peeking request.
        http->request->error.update(sslServerBump->request->error);
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
                ACLFilledChecklist check(Config.ssl_client.cert_error, nullptr);
                const auto sslErrors = std::make_unique<Security::CertErrors>(Security::CertError(SQUID_X509_V_ERR_DOMAIN_MISMATCH, srvCert));
                check.sslErrors = sslErrors.get();
                clientAclChecklistFill(check, http);
                allowDomainMismatch = check.fastCheck().allowed();
            }

            if (!allowDomainMismatch) {
                quitAfterError(request);

                clientStreamNode *node = context->getClientReplyContext();
                clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
                assert (repContext);

                request->hier = sslServerBump->request->hier;

                // Create an error object and fill it
                const auto err = new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scServiceUnavailable, request, http->al);
                err->src_addr = clientConnection->remote;
                const Security::ErrorDetail::Pointer errDetail = new Security::ErrorDetail(
                    SQUID_X509_V_ERR_DOMAIN_MISMATCH,
                    srvCert, nullptr);
                updateError(ERR_SECURE_CONNECT_FAIL, errDetail);
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

/// initiate tunneling if possible or return false otherwise
bool
ConnStateData::tunnelOnError(const err_type requestError)
{
    if (!Config.accessList.on_unsupported_protocol) {
        debugs(33, 5, "disabled; send error: " << requestError);
        return false;
    }

    if (!preservingClientData_) {
        debugs(33, 3, "may have forgotten client data; send error: " << requestError);
        return false;
    }

    ACLFilledChecklist checklist(Config.accessList.on_unsupported_protocol, nullptr);
    checklist.requestErrorType = requestError;
    fillChecklist(checklist);
    auto answer = checklist.fastCheck();
    if (answer.allowed() && answer.kind == 1) {
        debugs(33, 3, "Request will be tunneled to server");
        const auto context = pipeline.front();
        const auto http = context ? context->http : nullptr;
        const auto request = http ? http->request : nullptr;
        if (context)
            context->finished(); // Will remove from pipeline queue
        Comm::SetSelect(clientConnection->fd, COMM_SELECT_READ, nullptr, nullptr, 0);
        return initiateTunneledRequest(request, "unknown-protocol", preservedClientData);
    }
    debugs(33, 3, "denied; send error: " << requestError);
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
    if (request != nullptr && request->flags.resetTcp && Comm::IsConnOpen(conn->clientConnection)) {
        debugs(33, 3, "Sending TCP RST on " << conn->clientConnection);
        conn->flags.readMore = false;
        comm_reset_close(conn->clientConnection);
    }
}

void
clientProcessRequest(ConnStateData *conn, const Http1::RequestParserPointer &hp, Http::Stream *context)
{
    ClientHttpRequest *http = context->http;
    bool mustReplyToOptions = false;
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

    request->manager(conn, http->al);

    request->flags.accelerated = http->flags.accel;
    request->flags.sslBumped=conn->switchedToHttps();
    // TODO: decouple http->flags.accel from request->flags.sslBumped
    request->flags.noDirect = (request->flags.accelerated && !request->flags.sslBumped) ?
                              !conn->port->allow_direct : 0;
    request->sources |= isFtp ? Http::Message::srcFtp :
                        ((request->flags.sslBumped || conn->port->transport.protocol == AnyP::PROTO_HTTPS) ? Http::Message::srcHttps : Http::Message::srcHttp);
#if USE_AUTH
    if (request->flags.sslBumped) {
        if (conn->getAuth() != nullptr)
            request->auth_user_request = conn->getAuth();
    }
#endif

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
            http->setLogUriToRequestUri();
        } else
            debugs(33, 2, "internal URL found: " << request->url.getScheme() << "://" << request->url.authority(true) << " (not this proxy)");

        if (ForSomeCacheManager(request->url.path()))
            request->flags.disableCacheUse("cache manager URL");
    }

    request->flags.internal = http->flags.internal;

    if (request->url.getScheme() == AnyP::PROTO_CACHE_OBJECT)
        request->flags.disableCacheUse("cache_object URL scheme");

    if (!isFtp) {
        // XXX: for non-HTTP messages instantiate a different Http::Message child type
        // for now Squid only supports HTTP requests
        const AnyP::ProtocolVersion &http_ver = hp->messageProtocol();
        assert(request->http_ver.protocol == http_ver.protocol);
        request->http_ver.major = http_ver.major;
        request->http_ver.minor = http_ver.minor;
    }

    mustReplyToOptions = (request->method == Http::METHOD_OPTIONS) &&
                         (request->header.getInt64(Http::HdrType::MAX_FORWARDS) == 0);
    if (!urlCheckRequest(request.getRaw()) || mustReplyToOptions) {
        clientStreamNode *node = context->getClientReplyContext();
        conn->quitAfterError(request.getRaw());
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_UNSUP_REQ, Http::scNotImplemented, nullptr,
                                    conn, request.getRaw(), nullptr, nullptr);
        assert(context->http->out.offset == 0);
        context->pullData();
        clientProcessRequestFinished(conn, request);
        return;
    }

    const auto frameStatus = request->checkEntityFraming();
    if (frameStatus != Http::scNone) {
        clientStreamNode *node = context->getClientReplyContext();
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        conn->quitAfterError(request.getRaw());
        repContext->setReplyToError(ERR_INVALID_REQ, frameStatus, nullptr, conn, request.getRaw(), nullptr, nullptr);
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
    const auto chunked = request->header.chunked();
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
                                        Http::scContentTooLarge, nullptr,
                                        conn, http->request, nullptr, nullptr);
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

void
ConnStateData::add(const Http::StreamPointer &context)
{
    debugs(33, 3, context << " to " << pipeline.count() << '/' << pipeline.nrequests);
    if (bareError) {
        debugs(33, 5, "assigning " << bareError);
        assert(context);
        assert(context->http);
        context->http->updateError(bareError);
        bareError.clear();
    }
    pipeline.add(context);
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

    // when queue filled already we can't add more.
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

    ACLFilledChecklist ch(Config.accessList.proxyProtocol, nullptr);
    fillChecklist(ch);
    if (!ch.fastCheck().allowed())
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
        // display the first of every 32 occurrences at level 1, the others at level 2.
        static uint8_t hide = 0;
        debugs(33, (hide++ % 32 == 0 ? DBG_IMPORTANT : 2), msg << " from " << clientConnection);
#else
        debugs(33, DBG_IMPORTANT, msg << " from " << clientConnection);
#endif
        mustStop(msg);
    }
    return false;
}

/// Attempts to extract a PROXY protocol header from the input buffer and,
/// upon success, stores the parsed header in proxyProtocolHeader_.
/// \returns true if the header was successfully parsed
/// \returns false if more data is needed to parse the header or on error
bool
ConnStateData::parseProxyProtocolHeader()
{
    try {
        const auto parsed = ProxyProtocol::Parse(inBuf);
        proxyProtocolHeader_ = parsed.header;
        assert(bool(proxyProtocolHeader_));
        inBuf.consume(parsed.size);
        needProxyProtocolHeader_ = false;
        if (proxyProtocolHeader_->hasForwardedAddresses()) {
            clientConnection->local = proxyProtocolHeader_->destinationAddress;
            clientConnection->remote = proxyProtocolHeader_->sourceAddress;
            if ((clientConnection->flags & COMM_TRANSPARENT))
                clientConnection->flags ^= COMM_TRANSPARENT; // prevent TPROXY spoofing of this new IP.
            debugs(33, 5, "PROXY/" << proxyProtocolHeader_->version() << " upgrade: " << clientConnection);
        }
    } catch (const Parser::BinaryTokenizer::InsufficientInput &) {
        debugs(33, 3, "PROXY protocol: waiting for more than " << inBuf.length() << " bytes");
        return false;
    } catch (const std::exception &e) {
        return proxyProtocolError(e.what());
    }
    return true;
}

void
ConnStateData::receivedFirstByte()
{
    if (receivedFirstByte_)
        return;

    receivedFirstByte_ = true;
    resetReadTimeout(Config.Timeout.request);
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

    debugs(33, 5, clientConnection << ": attempting to parse");

    // Loop while we have read bytes that are not needed for producing the body
    // On errors, bodyPipe may become nil, but readMore will be cleared
    while (!inBuf.isEmpty() && !bodyPipe && flags.readMore) {

        // Prohibit concurrent requests when using a pinned to-server connection
        // because our Client classes do not support request pipelining.
        if (pinning.pinned && !pinning.readHandler) {
            debugs(33, 3, clientConnection << " waits for busy " << pinning.serverConnection);
            break;
        }

        /* Limit the number of concurrent requests */
        if (concurrentRequestQueueFilled())
            break;

        // try to parse the PROXY protocol header magic bytes
        if (needProxyProtocolHeader_) {
            if (!parseProxyProtocolHeader())
                break;

            // we have been waiting for PROXY to provide client-IP
            // for some lookups, ie rDNS and IDENT.
            whenClientIpKnown();

            // Done with PROXY protocol which has cleared preservingClientData_.
            // If the next protocol supports on_unsupported_protocol, then its
            // parseOneRequest() must reset preservingClientData_.
            assert(!preservingClientData_);
        }

        if (Http::StreamPointer context = parseOneRequest()) {
            debugs(33, 5, clientConnection << ": done parsing a request");
            extendLifetime();
            context->registerWithConn();

#if USE_OPENSSL
            if (switchedToHttps())
                parsedBumpedRequestCount++;
#endif

            processParsedRequest(context);

            parsed_req = true; // XXX: do we really need to parse everything right NOW ?

            if (context->mayUseConnection()) {
                debugs(33, 3, "Not parsing new requests, as this request may need the connection");
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
        // We may get here if the client half-closed after sending a partial
        // request. See doClientRead() and shouldCloseOnEof().
        // XXX: This partially duplicates ConnStateData::kick().
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
    if (bodyPipe != nullptr)
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
    assert(bodyPipe != nullptr);

    if (bodyParser) { // chunked encoding
        if (const err_type error = handleChunkedRequestBody()) {
            abortChunkedRequestBody(error);
            return false;
        }
    } else { // identity encoding
        debugs(33,5, "handling plain request body for " << clientConnection);
        const size_t putSize = bodyPipe->putMoreData(inBuf.c_str(), inBuf.length());
        if (putSize > 0)
            consumeInput(putSize);

        if (!bodyPipe->mayNeedMoreData()) {
            // BodyPipe will clear us automagically when we produced everything
            bodyPipe = nullptr;
        }
    }

    if (!bodyPipe) {
        debugs(33,5, "produced entire request body for " << clientConnection);

        if (const char *reason = stoppedSending()) {
            /* we've finished reading like good clients,
             * now do the close that initiateClose initiated.
             */
            debugs(33, 3, "closing for earlier sending error: " << reason);
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
        debugs(33, 3, "malformed chunks" << bodyPipe->status());
        return ERR_INVALID_REQ;
    }

    debugs(33, 7, "need more chunked data" << *bodyPipe->status());
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
                                       Http::scContentTooLarge : HTTP_BAD_REQUEST;
        repContext->setReplyToError(error, scode,
                                    repContext->http->uri,
                                    CachePeer,
                                    repContext->http->request,
                                    inBuf, nullptr);
        context->pullData();
    } else {
        // close or otherwise we may get stuck as nobody will notice the error?
        comm_reset_close(clientConnection);
    }
#else
    debugs(33, 3, "aborting chunked request without error " << error);
    comm_reset_close(clientConnection);
#endif
    flags.readMore = false;
}

void
ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer )
{
    // request reader may get stuck waiting for space if nobody consumes body
    if (bodyPipe != nullptr)
        bodyPipe->enableAutoConsumption();

    // kids extend
}

/** general lifetime handler for HTTP requests */
void
ConnStateData::requestTimeout(const CommTimeoutCbParams &io)
{
    if (!Comm::IsConnOpen(io.conn))
        return;

    const err_type error = receivedFirstByte_ ? ERR_REQUEST_PARSE_TIMEOUT : ERR_REQUEST_START_TIMEOUT;
    updateError(error);
    if (tunnelOnError(error))
        return;

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

void
ConnStateData::lifetimeTimeout(const CommTimeoutCbParams &io)
{
    debugs(33, DBG_IMPORTANT, "WARNING: Closing client connection due to lifetime timeout" <<
           Debug::Extra << "connection: " << io.conn);

    LogTagsErrors lte;
    lte.timedout = true;
    terminateAll(ERR_LIFETIME_EXP, lte);
}

ConnStateData::ConnStateData(const MasterXaction::Pointer &xact) :
    AsyncJob("ConnStateData"), // kids overwrite
    Server(xact)
#if USE_OPENSSL
    , tlsParser(Security::HandshakeParser::fromClient)
#endif
{
    // store the details required for creating more MasterXaction objects as new requests come in
    log_addr = xact->tcpClient->remote;
    log_addr.applyClientMask(Config.Addrs.client_netmask);

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
            debugs(33, DBG_IMPORTANT, "WARNING: Path MTU discovery disabling is not supported on your platform.");
            reported = true;
        }
#endif
    }

    typedef CommCbMemFunT<ConnStateData, CommCloseCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(33, 5, Dialer, this, ConnStateData::connStateClosed);
    comm_add_close_handler(clientConnection->fd, call);

    needProxyProtocolHeader_ = port->flags.proxySurrogate;
    if (needProxyProtocolHeader_) {
        if (!proxyProtocolValidateClient()) // will close the connection on failure
            return;
    } else
        whenClientIpKnown();

    // requires needProxyProtocolHeader_ which is initialized above
    preservingClientData_ = shouldPreserveClientData();
}

void
ConnStateData::whenClientIpKnown()
{
    debugs(33, 7, clientConnection->remote);
    if (Dns::ResolveClientAddressesAsap)
        fqdncache_gethostbyaddr(clientConnection->remote, FQDN_LOOKUP_IF_MISS);

#if USE_IDENT
    if (Ident::TheConfig.identLookup) {
        ACLFilledChecklist identChecklist(Ident::TheConfig.identLookup, nullptr, nullptr);
        fillChecklist(identChecklist);
        if (identChecklist.fastCheck().allowed())
            Ident::Start(clientConnection, clientIdentDone, this);
    }
#endif

    clientdbEstablished(clientConnection->remote, 1);

#if USE_DELAY_POOLS
    fd_table[clientConnection->fd].clientInfo = nullptr;

    if (!Config.onoff.client_db)
        return; // client delay pools require client_db

    const auto &pools = ClientDelayPools::Instance()->pools;
    if (pools.size()) {
        ACLFilledChecklist ch(nullptr, nullptr, nullptr);
        fillChecklist(ch);
        // TODO: we check early to limit error response bandwidth but we
        // should recheck when we can honor delay_pool_uses_indirect
        for (unsigned int pool = 0; pool < pools.size(); ++pool) {

            /* pools require explicit 'allow' to assign a client into them */
            if (pools[pool]->access) {
                ch.changeAcl(pools[pool]->access);
                auto answer = ch.fastCheck();
                if (answer.allowed()) {

                    /*  request client information from db after we did all checks
                        this will save hash lookup if client failed checks */
                    ClientInfo * cli = clientdbGetInfo(clientConnection->remote);
                    assert(cli);

                    /* put client info in FDE */
                    fd_table[clientConnection->fd].clientInfo = cli;

                    /* setup write limiter for this request */
                    const double burst = floor(0.5 +
                                               (pools[pool]->highwatermark * Config.ClientDelay.initial)/100.0);
                    cli->setWriteLimiter(pools[pool]->rate, burst, pools[pool]->highwatermark);
                    break;
                } else {
                    debugs(83, 4, "Delay pool " << pool << " skipped because ACL " << answer);
                }
            }
        }
    }
#endif

    // kids must extend to actually start doing something (e.g., reading)
}

Security::IoResult
ConnStateData::acceptTls()
{
    const auto handshakeResult = Security::Accept(*clientConnection);

#if USE_OPENSSL
    // log ASAP, even if the handshake has not completed (or failed)
    const auto fd = clientConnection->fd;
    assert(fd >= 0);
    keyLogger.checkpoint(*fd_table[fd].ssl, *this);
#else
    // TODO: Support fd_table[fd].ssl dereference in other builds.
#endif

    return handshakeResult;
}

/** Handle a new connection on an HTTP socket. */
void
httpAccept(const CommAcceptCbParams &params)
{
    Assure(params.port);

    // NP: it is possible the port was reconfigured when the call or accept() was queued.

    if (params.flag != Comm::OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, params.port->listenConn << ": accept failure: " << xstrerr(params.xerrno));
        return;
    }

    debugs(33, 4, params.conn << ": accepted");
    fd_note(params.conn->fd, "client http connect");
    const auto xact = MasterXaction::MakePortful(params.port);
    xact->tcpClient = params.conn;

    // Socket is ready, setup the connection manager to start using it
    auto *srv = Http::NewServer(xact);
    // XXX: do not abandon the MasterXaction object
    AsyncJob::Start(srv); // usually async-calls readSomeData()
}

/// Create TLS connection structure and update fd_table
static bool
httpsCreate(const ConnStateData *connState, const Security::ContextPointer &ctx)
{
    const auto conn = connState->clientConnection;
    if (Security::CreateServerSession(ctx, conn, connState->port->secure, "client https start")) {
        debugs(33, 5, "will negotiate TLS on " << conn);
        return true;
    }

    debugs(33, DBG_IMPORTANT, "ERROR: could not create TLS server context for " << conn);
    conn->close();
    return false;
}

/** negotiate an SSL connection */
static void
clientNegotiateSSL(int fd, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;

    const auto handshakeResult = conn->acceptTls();
    switch (handshakeResult.category) {
    case Security::IoResult::ioSuccess:
        break;

    case Security::IoResult::ioWantRead:
        Comm::SetSelect(conn->clientConnection->fd, COMM_SELECT_READ, clientNegotiateSSL, conn, 0);
        return;

    case Security::IoResult::ioWantWrite:
        Comm::SetSelect(conn->clientConnection->fd, COMM_SELECT_WRITE, clientNegotiateSSL, conn, 0);
        return;

    case Security::IoResult::ioError:
        debugs(83, (handshakeResult.important ? Important(62) : 2), "ERROR: " << handshakeResult.errorDescription <<
               " while accepting a TLS connection on " << conn->clientConnection << ": " << handshakeResult.errorDetail);
        // TODO: No ConnStateData::tunnelOnError() on this forward-proxy code
        // path because we cannot know the intended connection target?
        conn->updateError(ERR_SECURE_ACCEPT_FAIL, handshakeResult.errorDetail);
        conn->clientConnection->close();
        return;
    }

    Security::SessionPointer session(fd_table[fd].ssl);

#if USE_OPENSSL
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
#else
    debugs(83, 2, "TLS session reuse not yet implemented.");
#endif

    // Connection established. Retrieve TLS connection parameters for logging.
    conn->clientConnection->tlsNegotiations()->retrieveNegotiatedInfo(session);

#if USE_OPENSSL
    X509 *client_cert = SSL_get_peer_certificate(session.get());

    if (client_cert) {
        debugs(83, 3, "FD " << fd << " client certificate: subject: " <<
               Security::SubjectName(*client_cert));

        debugs(83, 3, "FD " << fd << " client certificate: issuer: " <<
               Security::IssuerName(*client_cert));

        X509_free(client_cert);
    } else {
        debugs(83, 5, "FD " << fd << " has no client certificate.");
    }
#else
    debugs(83, 2, "Client certificate requesting not yet implemented.");
#endif

    // If we are called, then bumped CONNECT has succeeded. Finalize it.
    if (auto xact = conn->pipeline.front()) {
        if (xact->http && xact->http->request && xact->http->request->method == Http::METHOD_CONNECT)
            xact->finished();
        // cannot proceed with encryption if requests wait for plain responses
        Must(conn->pipeline.empty());
    }
    /* careful: finished() above frees request, host, etc. */

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

    if (!ctx || !httpsCreate(connState, ctx))
        return;

    connState->resetReadTimeout(Config.Timeout.request);

    Comm::SetSelect(details->fd, COMM_SELECT_READ, clientNegotiateSSL, connState, 0);
}

#if USE_OPENSSL
/**
 * A callback function to use with the ACLFilledChecklist callback.
 */
static void
httpsSslBumpAccessCheckDone(Acl::Answer answer, void *data)
{
    ConnStateData *connState = (ConnStateData *) data;

    // if the connection is closed or closing, just return.
    if (!connState->isOpen())
        return;

    if (answer.allowed()) {
        debugs(33, 2, "sslBump action " << Ssl::bumpMode(answer.kind) << "needed for " << connState->clientConnection);
        connState->sslBumpMode = static_cast<Ssl::BumpMode>(answer.kind);
    } else {
        debugs(33, 3, "sslBump not needed for " << connState->clientConnection);
        connState->sslBumpMode = Ssl::bumpSplice;
    }

    if (connState->sslBumpMode == Ssl::bumpTerminate) {
        connState->clientConnection->close();
        return;
    }

    if (!connState->fakeAConnectRequest("ssl-bump", connState->inBuf))
        connState->clientConnection->close();
}
#endif

/** handle a new HTTPS connection */
static void
httpsAccept(const CommAcceptCbParams &params)
{
    Assure(params.port);

    // NP: it is possible the port was reconfigured when the call or accept() was queued.

    if (params.flag != Comm::OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, "httpsAccept: " << params.port->listenConn << ": accept failure: " << xstrerr(params.xerrno));
        return;
    }

    const auto xact = MasterXaction::MakePortful(params.port);
    xact->tcpClient = params.conn;

    debugs(33, 4, params.conn << " accepted, starting SSL negotiation.");
    fd_note(params.conn->fd, "client https connect");

    // Socket is ready, setup the connection manager to start using it
    auto *srv = Https::NewServer(xact);
    // XXX: do not abandon the MasterXaction object
    AsyncJob::Start(srv); // usually async-calls postHttpsAccept()
}

void
ConnStateData::postHttpsAccept()
{
    if (port->flags.tunnelSslBumping) {
#if USE_OPENSSL
        debugs(33, 5, "accept transparent connection: " << clientConnection);

        if (!Config.accessList.ssl_bump) {
            httpsSslBumpAccessCheckDone(ACCESS_DENIED, this);
            return;
        }

        const auto mx = MasterXaction::MakePortful(port);
        mx->tcpClient = clientConnection;
        // Create a fake HTTP request and ALE for the ssl_bump ACL check,
        // using tproxy/intercept provided destination IP and port.
        // XXX: Merge with subsequent fakeAConnectRequest(), buildFakeRequest().
        // XXX: Do this earlier (e.g., in Http[s]::One::Server constructor).
        HttpRequest *request = new HttpRequest(mx);
        static char ip[MAX_IPSTRLEN];
        assert(clientConnection->flags & (COMM_TRANSPARENT | COMM_INTERCEPTION));
        request->url.host(clientConnection->local.toStr(ip, sizeof(ip)));
        request->url.port(clientConnection->local.port());
        request->myportname = port->name;
        const AccessLogEntry::Pointer connectAle = new AccessLogEntry;
        CodeContext::Reset(connectAle);
        // TODO: Use these request/ALE when waiting for new bumped transactions.

        ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(Config.accessList.ssl_bump, request, nullptr);
        fillChecklist(*acl_checklist);
        // Build a local AccessLogEntry to allow requiresAle() acls work
        acl_checklist->al = connectAle;
        acl_checklist->al->cache.start_time = current_time;
        acl_checklist->al->tcpClient = clientConnection;
        acl_checklist->al->cache.port = port;
        acl_checklist->al->cache.caddr = log_addr;
        acl_checklist->al->proxyProtocolHeader = proxyProtocolHeader_;
        acl_checklist->al->updateError(bareError);
        HTTPMSGUNLOCK(acl_checklist->al->request);
        acl_checklist->al->request = request;
        HTTPMSGLOCK(acl_checklist->al->request);
        Http::StreamPointer context = pipeline.front();
        ClientHttpRequest *http = context ? context->http : nullptr;
        const char *log_uri = http ? http->log_uri : nullptr;
        acl_checklist->syncAle(request, log_uri);
        acl_checklist->nonBlockingCheck(httpsSslBumpAccessCheckDone, this);
#else
        fatal("FATAL: SSL-Bump requires --with-openssl");
#endif
        return;
    } else {
        httpsEstablish(this, port->secure.staticContext);
    }
}

#if USE_OPENSSL
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
        debugs(33, 5, "Certificate for " << tlsConnectHostOrIp << " cannot be generated. ssl_crtd response: " << reply);
    } else if (!reply.other().hasContent()) {
        debugs(1, DBG_IMPORTANT, "\"ssl_crtd\" helper returned <NULL> reply.");
    } else {
        Ssl::CrtdMessage reply_message(Ssl::CrtdMessage::REPLY);
        if (reply_message.parse(reply.other().content(), reply.other().contentSize()) != Ssl::CrtdMessage::OK) {
            debugs(33, 5, "Reply from ssl_crtd for " << tlsConnectHostOrIp << " is incorrect");
        } else {
            if (reply.result != Helper::Okay) {
                debugs(33, 5, "Certificate for " << tlsConnectHostOrIp << " cannot be generated. ssl_crtd response: " << reply_message.getBody());
            } else {
                debugs(33, 5, "Certificate for " << tlsConnectHostOrIp << " was successfully received from ssl_crtd");
                if (sslServerBump && (sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare)) {
                    doPeekAndSpliceStep();
                    auto ssl = fd_table[clientConnection->fd].ssl.get();
                    bool ret = Ssl::configureSSLUsingPkeyAndCertFromMemory(ssl, reply_message.getBody().c_str(), *port);
                    if (!ret)
                        debugs(33, 5, "Failed to set certificates to ssl object for PeekAndSplice mode");

                    Security::ContextPointer ctx(Security::GetFrom(fd_table[clientConnection->fd].ssl));
                    Ssl::configureUnconfiguredSslContext(ctx, signAlgorithm, *port);
                } else {
                    Security::ContextPointer ctx(Ssl::GenerateSslContextUsingPkeyAndCertFromMemory(reply_message.getBody().c_str(), port->secure, (signAlgorithm == Ssl::algSignTrusted)));
                    if (ctx && !sslBumpCertKey.isEmpty())
                        storeTlsContextToCache(sslBumpCertKey, ctx);
                    getSslContextDone(ctx);
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
    certProperties.commonName = sslCommonName_.isEmpty() ? tlsConnectHostOrIp.c_str() : sslCommonName_.c_str();

    const bool connectedOk = sslServerBump && sslServerBump->connectedOk();
    if (connectedOk) {
        if (X509 *mimicCert = sslServerBump->serverCert.get())
            certProperties.mimicCert.resetAndLock(mimicCert);

        ACLFilledChecklist checklist(nullptr, sslServerBump->request.getRaw());
        fillChecklist(checklist);

        for (sslproxy_cert_adapt *ca = Config.ssl_client.cert_adapt; ca != nullptr; ca = ca->next) {
            // If the algorithm already set, then ignore it.
            if ((ca->alg == Ssl::algSetCommonName && certProperties.setCommonName) ||
                    (ca->alg == Ssl::algSetValidAfter && certProperties.setValidAfter) ||
                    (ca->alg == Ssl::algSetValidBefore && certProperties.setValidBefore) )
                continue;

            if (ca->aclList && checklist.fastCheck(ca->aclList).allowed()) {
                const char *alg = Ssl::CertAdaptAlgorithmStr[ca->alg];
                const char *param = ca->param;

                // For parameterless CN adaptation, use hostname from the
                // CONNECT request.
                if (ca->alg == Ssl::algSetCommonName) {
                    if (!param)
                        param = tlsConnectHostOrIp.c_str();
                    certProperties.commonName = param;
                    certProperties.setCommonName = true;
                } else if (ca->alg == Ssl::algSetValidAfter)
                    certProperties.setValidAfter = true;
                else if (ca->alg == Ssl::algSetValidBefore)
                    certProperties.setValidBefore = true;

                debugs(33, 5, "Matches certificate adaptation aglorithm: " <<
                       alg << " param: " << (param ? param : "-"));
            }
        }

        certProperties.signAlgorithm = Ssl::algSignEnd;
        for (sslproxy_cert_sign *sg = Config.ssl_client.cert_sign; sg != nullptr; sg = sg->next) {
            if (sg->aclList && checklist.fastCheck(sg->aclList).allowed()) {
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
        assert(port->secure.untrustedSigningCa.cert);
        certProperties.signWithX509.resetAndLock(port->secure.untrustedSigningCa.cert.get());
        certProperties.signWithPkey.resetAndLock(port->secure.untrustedSigningCa.pkey.get());
    } else {
        assert(port->secure.signingCa.cert.get());
        certProperties.signWithX509.resetAndLock(port->secure.signingCa.cert.get());

        if (port->secure.signingCa.pkey)
            certProperties.signWithPkey.resetAndLock(port->secure.signingCa.pkey.get());
    }
    signAlgorithm = certProperties.signAlgorithm;

    certProperties.signHash = Ssl::DefaultSignHash;
}

Security::ContextPointer
ConnStateData::getTlsContextFromCache(const SBuf &cacheKey, const Ssl::CertificateProperties &certProperties)
{
    debugs(33, 5, "Finding SSL certificate for " << cacheKey << " in cache");
    Ssl::LocalContextStorage * ssl_ctx_cache = Ssl::TheGlobalContextStorage.getLocalStorage(port->s);
    if (const auto ctx = ssl_ctx_cache ? ssl_ctx_cache->get(cacheKey) : nullptr) {
        if (Ssl::verifySslCertificate(*ctx, certProperties)) {
            debugs(33, 5, "Cached SSL certificate for " << certProperties.commonName << " is valid");
            return *ctx;
        } else {
            debugs(33, 5, "Cached SSL certificate for " << certProperties.commonName << " is out of date. Delete this certificate from cache");
            if (ssl_ctx_cache)
                ssl_ctx_cache->del(cacheKey);
        }
    }
    return Security::ContextPointer(nullptr);
}

void
ConnStateData::storeTlsContextToCache(const SBuf &cacheKey, Security::ContextPointer &ctx)
{
    Ssl::LocalContextStorage *ssl_ctx_cache = Ssl::TheGlobalContextStorage.getLocalStorage(port->s);
    if (!ssl_ctx_cache || !ssl_ctx_cache->add(cacheKey, ctx)) {
        // If it is not in storage delete after using. Else storage deleted it.
        fd_table[clientConnection->fd].dynamicTlsContext = ctx;
    }
}

void
ConnStateData::getSslContextStart()
{
    if (port->secure.generateHostCertificates) {
        Ssl::CertificateProperties certProperties;
        buildSslCertGenerationParams(certProperties);

        // Disable caching for bumpPeekAndSplice mode
        if (!(sslServerBump && (sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare))) {
            sslBumpCertKey.clear();
            Ssl::InRamCertificateDbKey(certProperties, sslBumpCertKey);
            assert(!sslBumpCertKey.isEmpty());

            Security::ContextPointer ctx(getTlsContextFromCache(sslBumpCertKey, certProperties));
            if (ctx) {
                getSslContextDone(ctx);
                return;
            }
        }

#if USE_SSL_CRTD
        try {
            debugs(33, 5, "Generating SSL certificate for " << certProperties.commonName << " using ssl_crtd.");
            Ssl::CrtdMessage request_message(Ssl::CrtdMessage::REQUEST);
            request_message.setCode(Ssl::CrtdMessage::code_new_certificate);
            request_message.composeRequest(certProperties);
            debugs(33, 5, "SSL crtd request: " << request_message.compose().c_str());
            Ssl::Helper::Submit(request_message, sslCrtdHandleReplyWrapper, this);
            return;
        } catch (const std::exception &e) {
            debugs(33, DBG_IMPORTANT, "ERROR: Failed to compose ssl_crtd " <<
                   "request for " << certProperties.commonName <<
                   " certificate: " << e.what() << "; will now block to " <<
                   "generate that certificate.");
            // fall through to do blocking in-process generation.
        }
#endif // USE_SSL_CRTD

        debugs(33, 5, "Generating SSL certificate for " << certProperties.commonName);
        if (sslServerBump && (sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare)) {
            doPeekAndSpliceStep();
            auto ssl = fd_table[clientConnection->fd].ssl.get();
            if (!Ssl::configureSSL(ssl, certProperties, *port))
                debugs(33, 5, "Failed to set certificates to ssl object for PeekAndSplice mode");

            Security::ContextPointer ctx(Security::GetFrom(fd_table[clientConnection->fd].ssl));
            Ssl::configureUnconfiguredSslContext(ctx, certProperties.signAlgorithm, *port);
        } else {
            Security::ContextPointer dynCtx(Ssl::GenerateSslContext(certProperties, port->secure, (signAlgorithm == Ssl::algSignTrusted)));
            if (dynCtx && !sslBumpCertKey.isEmpty())
                storeTlsContextToCache(sslBumpCertKey, dynCtx);
            getSslContextDone(dynCtx);
        }
        return;
    }

    Security::ContextPointer nil;
    getSslContextDone(nil);
}

void
ConnStateData::getSslContextDone(Security::ContextPointer &ctx)
{
    if (port->secure.generateHostCertificates && !ctx) {
        debugs(33, 2, "Failed to generate TLS context for " << tlsConnectHostOrIp);
    }

    // If generated ssl context = nullptr, try to use static ssl context.
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

    if (!httpsCreate(this, ctx))
        return;

    // bumped intercepted conns should already have Config.Timeout.request set
    // but forwarded connections may only have Config.Timeout.lifetime. [Re]set
    // to make sure the connection does not get stuck on non-SSL clients.
    resetReadTimeout(Config.Timeout.request);

    switchedToHttps_ = true;

    auto ssl = fd_table[clientConnection->fd].ssl.get();
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ClientBio *bio = static_cast<Ssl::ClientBio *>(BIO_get_data(b));
    bio->setReadBufData(inBuf);
    inBuf.clear();
    clientNegotiateSSL(clientConnection->fd, this);
}

void
ConnStateData::switchToHttps(ClientHttpRequest *http, Ssl::BumpMode bumpServerMode)
{
    assert(!switchedToHttps_);
    Must(http->request);
    auto &request = http->request;

    // Depending on receivedFirstByte_, we are at the start of either an
    // established CONNECT tunnel with the client or an intercepted TCP (and
    // presumably TLS) connection from the client. Expect TLS Client Hello.
    const auto insideConnectTunnel = receivedFirstByte_;
    debugs(33, 5, (insideConnectTunnel ? "post-CONNECT " : "raw TLS ") << clientConnection);

    tlsConnectHostOrIp = request->url.hostOrIp();
    tlsConnectPort = request->url.port();
    resetSslCommonName(request->url.host());

    // We are going to read new request
    flags.readMore = true;

    // keep version major.minor details the same.
    // but we are now performing the HTTPS handshake traffic
    transferProtocol.protocol = AnyP::PROTO_HTTPS;

    // If sslServerBump is set, then we have decided to deny CONNECT
    // and now want to switch to SSL to send the error to the client
    // without even peeking at the origin server certificate.
    if (bumpServerMode == Ssl::bumpServerFirst && !sslServerBump) {
        request->flags.sslPeek = true;
        sslServerBump = new Ssl::ServerBump(http);
    } else if (bumpServerMode == Ssl::bumpPeek || bumpServerMode == Ssl::bumpStare) {
        request->flags.sslPeek = true;
        sslServerBump = new Ssl::ServerBump(http, nullptr, bumpServerMode);
    }

    // commSetConnTimeout() was called for this request before we switched.
    // Fix timeout to request_start_timeout
    resetReadTimeout(Config.Timeout.request_start_timeout);
    // Also reset receivedFirstByte_ flag to allow this timeout work in the case we have
    // a bumbed "connect" request on non transparent port.
    receivedFirstByte_ = false;
    // Get more data to peek at Tls
    parsingTlsHandshake = true;

    // If the protocol has changed, then reset preservingClientData_.
    // Otherwise, its value initially set in start() is still valid/fresh.
    // shouldPreserveClientData() uses parsingTlsHandshake which is reset above.
    if (insideConnectTunnel)
        preservingClientData_ = shouldPreserveClientData();

    readSomeData();
}

void
ConnStateData::parseTlsHandshake()
{
    Must(parsingTlsHandshake);

    assert(!inBuf.isEmpty());
    receivedFirstByte();
    fd_note(clientConnection->fd, "Parsing TLS handshake");

    // stops being nil if we fail to parse the handshake
    ErrorDetail::Pointer parseErrorDetails;

    try {
        if (!tlsParser.parseHello(inBuf)) {
            // need more data to finish parsing
            readSomeData();
            return;
        }
    }
    catch (const TextException &ex) {
        debugs(83, 2, "exception: " << ex);
        parseErrorDetails = new ExceptionErrorDetail(ex.id());
    }
    catch (...) {
        debugs(83, 2, "exception: " << CurrentException);
        static const auto d = MakeNamedErrorDetail("TLS_ACCEPT_PARSE");
        parseErrorDetails = d;
    }

    parsingTlsHandshake = false;

    // client data may be needed for splicing and for
    // tunneling unsupportedProtocol after an error
    preservedClientData = inBuf;

    // Even if the parser failed, each TLS detail should either be set
    // correctly or still be "unknown"; copying unknown detail is a no-op.
    Security::TlsDetails::Pointer const &details = tlsParser.details;
    clientConnection->tlsNegotiations()->retrieveParsedInfo(details);
    if (details && !details->serverName.isEmpty()) {
        resetSslCommonName(details->serverName.c_str());
        tlsClientSni_ = details->serverName;
    }

    // We should disable read/write handlers
    Comm::ResetSelect(clientConnection->fd);

    if (parseErrorDetails) {
        Http::StreamPointer context = pipeline.front();
        Must(context && context->http);
        HttpRequest::Pointer request = context->http->request;
        debugs(83, 5, "Got something other than TLS Client Hello. Cannot SslBump.");
        updateError(ERR_PROTOCOL_UNKNOWN, parseErrorDetails);
        if (!tunnelOnError(ERR_PROTOCOL_UNKNOWN))
            clientConnection->close();
        return;
    }

    if (!sslServerBump || sslServerBump->act.step1 == Ssl::bumpClientFirst) { // Either means client-first.
        getSslContextStart();
        return;
    } else if (sslServerBump->act.step1 == Ssl::bumpServerFirst) {
        debugs(83, 5, "server-first skips step2; start forwarding the request");
        sslServerBump->step = XactionStep::tlsBump3;
        Http::StreamPointer context = pipeline.front();
        ClientHttpRequest *http = context ? context->http : nullptr;
        // will call httpsPeeked() with certificate and connection, eventually
        FwdState::Start(clientConnection, sslServerBump->entry, sslServerBump->request.getRaw(), http ? http->al : nullptr);
    } else {
        Must(sslServerBump->act.step1 == Ssl::bumpPeek || sslServerBump->act.step1 == Ssl::bumpStare);
        startPeekAndSplice();
    }
}

static void
httpsSslBumpStep2AccessCheckDone(Acl::Answer answer, void *data)
{
    ConnStateData *connState = (ConnStateData *) data;

    // if the connection is closed or closing, just return.
    if (!connState->isOpen())
        return;

    debugs(33, 5, "Answer: " << answer << " kind:" << answer.kind);
    assert(connState->serverBump());
    Ssl::BumpMode bumpAction;
    if (answer.allowed()) {
        bumpAction = (Ssl::BumpMode)answer.kind;
    } else
        bumpAction = Ssl::bumpSplice;

    connState->serverBump()->act.step2 = bumpAction;
    connState->sslBumpMode = bumpAction;
    Http::StreamPointer context = connState->pipeline.front();
    if (ClientHttpRequest *http = (context ? context->http : nullptr))
        http->al->ssl.bumpMode = bumpAction;

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

    // fde::ssl/tls_read_method() probably reads from our own inBuf. If so, then
    // we should not lose any raw bytes when switching to raw I/O here.
    if (fd_table[clientConnection->fd].ssl.get())
        fd_table[clientConnection->fd].useDefaultIo();

    // XXX: assuming that there was an HTTP/1.1 CONNECT to begin with...
    // reset the current protocol to HTTP/1.1 (was "HTTPS" for the bumping process)
    transferProtocol = Http::ProtocolVersion();
    assert(!pipeline.empty());
    Http::StreamPointer context = pipeline.front();
    Must(context);
    Must(context->http);
    ClientHttpRequest *http = context->http;
    HttpRequest::Pointer request = http->request;
    context->finished();
    if (transparent()) {
        // For transparent connections, make a new fake CONNECT request, now
        // with SNI as target. doCallout() checks, adaptations may need that.
        return fakeAConnectRequest("splice", preservedClientData);
    } else {
        // For non transparent connections  make a new tunneled CONNECT, which
        // also sets the HttpRequest::flags::forceTunnel flag to avoid
        // respond with "Connection Established" to the client.
        // This fake CONNECT request required to allow use of SNI in
        // doCallout() checks and adaptations.
        return initiateTunneledRequest(request, "splice", preservedClientData);
    }
}

void
ConnStateData::startPeekAndSplice()
{
    // This is the Step2 of the SSL bumping
    assert(sslServerBump);
    Http::StreamPointer context = pipeline.front();
    ClientHttpRequest *http = context ? context->http : nullptr;

    if (sslServerBump->at(XactionStep::tlsBump1)) {
        sslServerBump->step = XactionStep::tlsBump2;
        // Run a accessList check to check if want to splice or continue bumping

        ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(Config.accessList.ssl_bump, sslServerBump->request.getRaw(), nullptr);
        acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpNone));
        acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpClientFirst));
        acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpServerFirst));
        fillChecklist(*acl_checklist);
        acl_checklist->nonBlockingCheck(httpsSslBumpStep2AccessCheckDone, this);
        return;
    }

    // will call httpsPeeked() with certificate and connection, eventually
    Security::ContextPointer unConfiguredCTX(Ssl::createSSLContext(port->secure.signingCa.cert, port->secure.signingCa.pkey, port->secure));
    fd_table[clientConnection->fd].dynamicTlsContext = unConfiguredCTX;

    if (!httpsCreate(this, unConfiguredCTX))
        return;

    switchedToHttps_ = true;

    auto ssl = fd_table[clientConnection->fd].ssl.get();
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ClientBio *bio = static_cast<Ssl::ClientBio *>(BIO_get_data(b));
    bio->setReadBufData(inBuf);
    bio->hold(true);

    // We have successfully parsed client Hello, but our TLS handshake parser is
    // forgiving. Now we use a TLS library to parse the same bytes, so that we
    // can honor on_unsupported_protocol if needed. If there are no errors, we
    // expect Security::Accept() to ask us to write (our) TLS server Hello. We
    // also allow an ioWantRead result in case some fancy TLS extension that
    // Squid does not yet understand requires reading post-Hello client bytes.
    const auto handshakeResult = acceptTls();
    if (!handshakeResult.wantsIo())
        return handleSslBumpHandshakeError(handshakeResult);

    // We need to reset inBuf here, to be used by incoming requests in the case
    // of SSL bump
    inBuf.clear();

    debugs(83, 5, "Peek and splice at step2 done. Start forwarding the request!!! ");
    sslServerBump->step = XactionStep::tlsBump3;
    FwdState::Start(clientConnection, sslServerBump->entry, sslServerBump->request.getRaw(), http ? http->al : nullptr);
}

/// process a problematic Security::Accept() result on the SslBump code path
void
ConnStateData::handleSslBumpHandshakeError(const Security::IoResult &handshakeResult)
{
    auto errCategory = ERR_NONE;

    switch (handshakeResult.category) {
    case Security::IoResult::ioSuccess: {
        static const auto d = MakeNamedErrorDetail("TLS_ACCEPT_UNEXPECTED_SUCCESS");
        updateError(errCategory = ERR_GATEWAY_FAILURE, d);
        break;
    }

    case Security::IoResult::ioWantRead: {
        static const auto d = MakeNamedErrorDetail("TLS_ACCEPT_UNEXPECTED_READ");
        updateError(errCategory = ERR_GATEWAY_FAILURE, d);
        break;
    }

    case Security::IoResult::ioWantWrite: {
        static const auto d = MakeNamedErrorDetail("TLS_ACCEPT_UNEXPECTED_WRITE");
        updateError(errCategory = ERR_GATEWAY_FAILURE, d);
        break;
    }

    case Security::IoResult::ioError:
        debugs(83, (handshakeResult.important ? DBG_IMPORTANT : 2), "ERROR: " << handshakeResult.errorDescription <<
               " while SslBump-accepting a TLS connection on " << clientConnection << ": " << handshakeResult.errorDetail);
        updateError(errCategory = ERR_SECURE_ACCEPT_FAIL, handshakeResult.errorDetail);
        break;

    }

    if (!tunnelOnError(errCategory))
        clientConnection->close();
}

void
ConnStateData::doPeekAndSpliceStep()
{
    auto ssl = fd_table[clientConnection->fd].ssl.get();
    BIO *b = SSL_get_rbio(ssl);
    assert(b);
    Ssl::ClientBio *bio = static_cast<Ssl::ClientBio *>(BIO_get_data(b));

    debugs(33, 5, "PeekAndSplice mode, proceed with client negotiation. Current state:" << SSL_state_string_long(ssl));
    bio->hold(false);

    Comm::SetSelect(clientConnection->fd, COMM_SELECT_WRITE, clientNegotiateSSL, this, 0);
    switchedToHttps_ = true;
}

void
ConnStateData::httpsPeeked(PinnedIdleContext pic)
{
    Must(sslServerBump != nullptr);
    Must(sslServerBump->request == pic.request);
    Must(pipeline.empty() || pipeline.front()->http == nullptr || pipeline.front()->http->request == pic.request.getRaw());

    if (Comm::IsConnOpen(pic.connection)) {
        notePinnedConnectionBecameIdle(pic);
        debugs(33, 5, "bumped HTTPS server: " << tlsConnectHostOrIp);
    } else
        debugs(33, 5, "Error while bumping: " << tlsConnectHostOrIp);

    getSslContextStart();
}

#endif /* USE_OPENSSL */

bool
ConnStateData::initiateTunneledRequest(HttpRequest::Pointer const &cause, const char *reason, const SBuf &payload)
{
    // fake a CONNECT request to force connState to tunnel
    SBuf connectHost;
    unsigned short connectPort = 0;

    if (pinning.serverConnection != nullptr) {
        static char ip[MAX_IPSTRLEN];
        connectHost = pinning.serverConnection->remote.toStr(ip, sizeof(ip));
        connectPort = pinning.serverConnection->remote.port();
    } else if (cause) {
        connectHost = cause->url.hostOrIp();
        connectPort = cause->url.port();
#if USE_OPENSSL
    } else if (!tlsConnectHostOrIp.isEmpty()) {
        connectHost = tlsConnectHostOrIp;
        connectPort = tlsConnectPort;
#endif
    } else if (transparent()) {
        static char ip[MAX_IPSTRLEN];
        connectHost = clientConnection->local.toStr(ip, sizeof(ip));
        connectPort = clientConnection->local.port();
    } else {
        // Typical cases are malformed HTTP requests on http_port and malformed
        // TLS handshakes on non-bumping https_port. TODO: Discover these
        // problems earlier so that they can be classified/detailed better.
        debugs(33, 2, "Not able to compute URL, abort request tunneling for " << reason);
        // TODO: throw when nonBlockingCheck() callbacks gain job protections
        static const auto d = MakeNamedErrorDetail("TUNNEL_TARGET");
        updateError(ERR_INVALID_REQ, d);
        return false;
    }

    debugs(33, 2, "Request tunneling for " << reason);
    ClientHttpRequest *http = buildFakeRequest(connectHost, connectPort, payload);
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
    if (!tlsClientSni_.isEmpty())
        connectHost.assign(tlsClientSni_);
    else
#endif
    {
        static char ip[MAX_IPSTRLEN];
        clientConnection->local.toHostStr(ip, sizeof(ip));
        connectHost.assign(ip);
    }

    ClientHttpRequest *http = buildFakeRequest(connectHost, connectPort, payload);

    http->calloutContext = new ClientRequestContext(http);
    HttpRequest::Pointer request = http->request;
    http->doCallouts();
    clientProcessRequestFinished(this, request);
    return true;
}

ClientHttpRequest *
ConnStateData::buildFakeRequest(SBuf &useHost, unsigned short usePort, const SBuf &payload)
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

    stream->flags.parsed_ok = 1; // Do we need it?
    stream->mayUseConnection(true);
    extendLifetime();
    stream->registerWithConn();

    const auto mx = MasterXaction::MakePortful(port);
    mx->tcpClient = clientConnection;
    // Setup Http::Request object. Maybe should be replaced by a call to (modified)
    // clientProcessRequest
    HttpRequest::Pointer request = new HttpRequest(mx);
    request->url.setScheme(AnyP::PROTO_AUTHORITY_FORM, nullptr);
    request->method = Http::METHOD_CONNECT;
    request->url.host(useHost.c_str());
    request->url.port(usePort);

    http->uri = SBufToCstring(request->effectiveRequestUri());
    http->initRequest(request.getRaw());

    request->manager(this, http->al);

    request->header.putStr(Http::HOST, useHost.c_str());

    request->sources |= ((switchedToHttps() || port->transport.protocol == AnyP::PROTO_HTTPS) ? Http::Message::srcHttps : Http::Message::srcHttp);
#if USE_AUTH
    if (getAuth())
        request->auth_user_request = getAuth();
#endif

    inBuf = payload;
    flags.readMore = false;

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
    const auto savedContext = CodeContext::Current();
    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        CodeContext::Reset(s);
        const SBuf &scheme = AnyP::UriScheme(s->transport.protocol).image();

        if (MAXTCPLISTENPORTS == NHttpSockets) {
            debugs(1, DBG_IMPORTANT, "WARNING: You have too many '" << scheme << "_port' lines." <<
                   Debug::Extra << "The limit is " << MAXTCPLISTENPORTS << " HTTP ports.");
            continue;
        }

#if USE_OPENSSL
        if (s->flags.tunnelSslBumping) {
            if (!Config.accessList.ssl_bump) {
                debugs(33, DBG_IMPORTANT, "WARNING: No ssl_bump configured. Disabling ssl-bump on " << scheme << "_port " << s->s);
                s->flags.tunnelSslBumping = false;
            }
            if (!s->secure.staticContext && !s->secure.generateHostCertificates) {
                debugs(1, DBG_IMPORTANT, "Will not bump SSL at " << scheme << "_port " << s->s << " due to TLS initialization failure.");
                s->flags.tunnelSslBumping = false;
                if (s->transport.protocol == AnyP::PROTO_HTTP)
                    s->secure.encryptTransport = false;
            }
            if (s->flags.tunnelSslBumping) {
                // Create ssl_ctx cache for this port.
                Ssl::TheGlobalContextStorage.addLocalStorage(s->s, s->secure.dynamicCertMemCacheSize);
            }
        }
#endif

        if (s->secure.encryptTransport && !s->secure.staticContext) {
            debugs(1, DBG_CRITICAL, "ERROR: Ignoring " << scheme << "_port " << s->s << " due to TLS context initialization failure.");
            continue;
        }

        const auto protocol = s->transport.protocol;
        assert(protocol == AnyP::PROTO_HTTP || protocol == AnyP::PROTO_HTTPS);
        const auto isHttps = protocol == AnyP::PROTO_HTTPS;
        using AcceptCall = CommCbFunPtrCallT<CommAcceptCbPtrFun>;
        RefCount<AcceptCall> subCall = commCbCall(5, 5, isHttps ? "httpsAccept" : "httpAccept",
                                       CommAcceptCbPtrFun(isHttps ? httpsAccept : httpAccept, CommAcceptCbParams(nullptr)));
        clientStartListeningOn(s, subCall, isHttps ? Ipc::fdnHttpsSocket : Ipc::fdnHttpSocket);
    }
    CodeContext::Reset(savedContext);
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
        (port->flags.natIntercept ? COMM_INTERCEPTION : 0) |
        (port->workerQueues ? COMM_REUSEPORT : 0);

    // route new connections to subCall
    typedef CommCbFunPtrCallT<CommAcceptCbPtrFun> AcceptCall;
    Subscription::Pointer sub = new CallSubscription<AcceptCall>(subCall);
    const auto listenCall =
        asyncCall(33, 2, "clientListenerConnectionOpened",
                  ListeningStartedDialer(&clientListenerConnectionOpened,
                                         port, fdNote, sub));
    AsyncCallback<Ipc::StartListeningAnswer> callback(listenCall);
    Ipc::StartListening(SOCK_STREAM, IPPROTO_TCP, port->listenConn, fdNote, callback);

    assert(NHttpSockets < MAXTCPLISTENPORTS);
    HttpSockets[NHttpSockets] = -1;
    ++NHttpSockets;
}

/// process clientHttpConnectionsOpen result
static void
clientListenerConnectionOpened(AnyP::PortCfgPointer &s, const Ipc::FdNoteId portTypeNote, const Subscription::Pointer &sub)
{
    Must(s != nullptr);

    if (!OpenedHttpSocket(s->listenConn, portTypeNote))
        return;

    Must(Comm::IsConnOpen(s->listenConn));

    // TCP: setup a job to handle accept() with subscribed handler
    AsyncJob::Start(new Comm::TcpAcceptor(s, FdNote(portTypeNote), sub));

    debugs(1, Important(13), "Accepting " <<
           (s->flags.natIntercept ? "NAT intercepted " : "") <<
           (s->flags.tproxyIntercept ? "TPROXY intercepted " : "") <<
           (s->flags.tunnelSslBumping ? "SSL bumped " : "") <<
           (s->flags.accelSurrogate ? "reverse-proxy " : "")
           << FdNote(portTypeNote) << " connections at "
           << s->listenConn);

    Must(AddOpenedHttpSocket(s->listenConn)); // otherwise, we have received a fd we did not ask for

#if USE_SYSTEMD
    // When the very first port opens, tell systemd we are able to serve connections.
    // Subsequent sd_notify() calls, including calls during reconfiguration,
    // do nothing because the first call parameter is 1.
    // XXX: Send the notification only after opening all configured ports.
    if (opt_foreground || opt_no_daemon) {
        const auto result = sd_notify(1, "READY=1");
        if (result < 0) {
            debugs(1, DBG_IMPORTANT, "WARNING: failed to send start-up notification to systemd" <<
                   Debug::Extra << "sd_notify() error: " << xstrerr(-result));
        }
    }
#endif
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
    const auto savedContext = CodeContext::Current();
    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        CodeContext::Reset(s);
        if (s->listenConn != nullptr) {
            debugs(1, Important(14), "Closing HTTP(S) port " << s->listenConn->local);
            s->listenConn->close();
            s->listenConn = nullptr;
        }
    }
    CodeContext::Reset(savedContext);

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
    const auto &reply = entry->mem().freshestReply();
    auto has_vary = reply.header.has(Http::HdrType::VARY);
#if X_ACCELERATOR_VARY

    has_vary |=
        reply.header.has(Http::HdrType::HDR_X_ACCELERATOR_VARY);
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
        vary = httpMakeVaryMark(request, &reply);

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
            vary = httpMakeVaryMark(request, &reply);

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
    const auto checklist = new ACLFilledChecklist(acl, nullptr, nullptr);
    clientAclChecklistFill(*checklist, http);
    return checklist;
}

void
clientAclChecklistFill(ACLFilledChecklist &checklist, ClientHttpRequest *http)
{
    assert(http);

    if (!checklist.request && http->request)
        checklist.setRequest(http->request);

    if (!checklist.al && http->al) {
        checklist.al = http->al;
        checklist.syncAle(http->request, http->log_uri);
        if (!checklist.reply && http->al->reply) {
            checklist.reply = http->al->reply.getRaw();
            HTTPMSGLOCK(checklist.reply);
        }
    }

    if (const auto conn = http->getConn())
        checklist.setConn(conn); // may already be set
}

void
ConnStateData::fillChecklist(ACLFilledChecklist &checklist) const
{
    const auto context = pipeline.front();
    if (const auto http = context ? context->http : nullptr)
        return clientAclChecklistFill(checklist, http); // calls checklist.setConn()

    // no requests, but we always have connection-level details
    // TODO: ACL checks should not require a mutable ConnStateData. Adjust the
    // code that accidentally violates that principle to remove this const_cast!
    checklist.setConn(const_cast<ConnStateData*>(this));

    // Set other checklist fields inside our fillConnectionLevelDetails() rather
    // than here because clientAclChecklistFill() code path calls that method
    // (via ACLFilledChecklist::setConn()) rather than calling us directly.
}

void
ConnStateData::fillConnectionLevelDetails(ACLFilledChecklist &checklist) const
{
    assert(checklist.conn() == this);
    assert(clientConnection);

    if (!checklist.request) { // preserve (better) addresses supplied by setRequest()
        checklist.src_addr = clientConnection->remote;
        checklist.my_addr = clientConnection->local; // TODO: or port->s?
    }

#if USE_OPENSSL
    if (!checklist.sslErrors && sslServerBump)
        checklist.sslErrors = sslServerBump->sslErrors();
#endif

    if (!checklist.rfc931[0]) // checklist creator may have supplied it already
        checklist.setIdent(clientConnection->rfc931);

}

bool
ConnStateData::transparent() const
{
    return clientConnection != nullptr && (clientConnection->flags & (COMM_TRANSPARENT|COMM_INTERCEPTION));
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
    debugs(33, 4, "receiving error (" << clientConnection << "): " << error <<
           "; old sending error: " <<
           (stoppedSending() ? stoppedSending_ : "none"));

    if (const char *oldError = stoppedReceiving()) {
        debugs(33, 3, "already stopped receiving: " << oldError);
        return; // nothing has changed as far as this connection is concerned
    }

    stoppedReceiving_ = error;

    if (const char *sendError = stoppedSending()) {
        debugs(33, 3, "closing because also stopped sending: " << sendError);
        clientConnection->close();
    }
}

void
ConnStateData::expectNoForwarding()
{
    if (bodyPipe != nullptr) {
        debugs(33, 4, "no consumer for virgin body " << bodyPipe->status());
        bodyPipe->expectNoConsumption();
    }
}

/// initialize dechunking state
void
ConnStateData::startDechunkingRequest()
{
    Must(bodyPipe != nullptr);
    debugs(33, 5, "start dechunking" << bodyPipe->status());
    assert(!bodyParser);
    bodyParser = new Http1::TeChunkedParser;
}

/// put parsed content into input buffer and clean up
void
ConnStateData::finishDechunkingRequest(bool withSuccess)
{
    debugs(33, 5, "finish dechunking: " << withSuccess);

    if (bodyPipe != nullptr) {
        debugs(33, 7, "dechunked tail: " << bodyPipe->status());
        BodyPipe::Pointer myPipe = bodyPipe;
        stopProducingFor(bodyPipe, withSuccess); // sets bodyPipe->bodySize()
        Must(!bodyPipe); // we rely on it being nil after we are done with body
        if (withSuccess) {
            Must(myPipe->bodySizeKnown());
            Http::StreamPointer context = pipeline.front();
            if (context != nullptr && context->http && context->http->request)
                context->http->request->setContentLength(myPipe->bodySize());
        }
    }

    delete bodyParser;
    bodyParser = nullptr;
}

// XXX: this is an HTTP/1-only operation
void
ConnStateData::sendControlMsg(HttpControlMsg msg)
{
    if (const auto context = pipeline.front()) {
        if (context->http)
            context->http->al->reply = msg.reply;
    }

    if (!isOpen()) {
        debugs(33, 3, "ignoring 1xx due to earlier closure");
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

    debugs(33, 3, " closing due to missing context for 1xx");
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
    pinning.closeHandler = nullptr; // Comm unregisters handlers before calling
    const bool sawZeroReply = pinning.zeroReply; // reset when unpinning
    pinning.serverConnection->noteClosure();
    unpinConnection(false);

    if (sawZeroReply && clientConnection != nullptr) {
        debugs(33, 3, "Closing client connection on pinned zero reply.");
        clientConnection->close();
    }

}

void
ConnStateData::pinBusyConnection(const Comm::ConnectionPointer &pinServer, const HttpRequest::Pointer &request)
{
    pinConnection(pinServer, *request);
}

void
ConnStateData::notePinnedConnectionBecameIdle(PinnedIdleContext pic)
{
    Must(pic.connection);
    Must(pic.request);
    pinConnection(pic.connection, *pic.request);

    // monitor pinned server connection for remote-end closures.
    startPinnedConnectionMonitoring();

    if (pipeline.empty())
        kick(); // in case clientParseRequests() was blocked by a busy pic.connection
}

/// Forward future client requests using the given server connection.
void
ConnStateData::pinConnection(const Comm::ConnectionPointer &pinServer, const HttpRequest &request)
{
    if (Comm::IsConnOpen(pinning.serverConnection) &&
            pinning.serverConnection->fd == pinServer->fd) {
        debugs(33, 3, "already pinned" << pinServer);
        return;
    }

    unpinConnection(true); // closes pinned connection, if any, and resets fields

    pinning.serverConnection = pinServer;

    debugs(33, 3, pinning.serverConnection);

    Must(pinning.serverConnection != nullptr);

    const char *pinnedHost = "[unknown]";
    pinning.host = xstrdup(request.url.host());
    pinning.port = request.url.port();
    pinnedHost = pinning.host;
    pinning.pinned = true;
    if (CachePeer *aPeer = pinServer->getPeer())
        pinning.peer = cbdataReference(aPeer);
    pinning.auth = request.flags.connectionAuth;
    char stmp[MAX_IPSTRLEN];
    char desc[FD_DESC_SZ];
    snprintf(desc, FD_DESC_SZ, "%s pinned connection for %s (%d)",
             (pinning.auth || !pinning.peer) ? pinnedHost : pinning.peer->name,
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
    if (pinning.readHandler != nullptr)
        return; // already monitoring

    typedef CommCbMemFunT<ConnStateData, CommIoCbParams> Dialer;
    pinning.readHandler = JobCallback(33, 3,
                                      Dialer, this, ConnStateData::clientPinnedConnectionRead);
    Comm::Read(pinning.serverConnection, pinning.readHandler);
}

void
ConnStateData::stopPinnedConnectionMonitoring()
{
    if (pinning.readHandler != nullptr) {
        Comm::ReadCancel(pinning.serverConnection->fd, pinning.readHandler);
        pinning.readHandler = nullptr;
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
        [[fallthrough]]; // to restart monitoring, for now

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
    pinning.readHandler = nullptr; // Comm unregisters handlers before calling

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
    if (clientIsIdle && clientConnection != nullptr)
        clientConnection->close();
}

Comm::ConnectionPointer
ConnStateData::borrowPinnedConnection(HttpRequest *request, const AccessLogEntryPointer &ale)
{
    debugs(33, 7, pinning.serverConnection);
    Must(request);

    const auto pinningError = [&](const err_type type) {
        unpinConnection(true);
        HttpRequestPointer requestPointer = request;
        return ErrorState::NewForwarding(type, requestPointer, ale);
    };

    if (!Comm::IsConnOpen(pinning.serverConnection))
        throw pinningError(ERR_ZERO_SIZE_OBJECT);

    if (pinning.auth && pinning.host && strcasecmp(pinning.host, request->url.host()) != 0)
        throw pinningError(ERR_CANNOT_FORWARD); // or generalize ERR_CONFLICT_HOST

    if (pinning.port != request->url.port())
        throw pinningError(ERR_CANNOT_FORWARD); // or generalize ERR_CONFLICT_HOST

    if (pinning.peer && !cbdataReferenceValid(pinning.peer))
        throw pinningError(ERR_ZERO_SIZE_OBJECT);

    if (pinning.peerAccessDenied)
        throw pinningError(ERR_CANNOT_FORWARD); // or generalize ERR_FORWARDING_DENIED

    stopPinnedConnectionMonitoring();
    return pinning.serverConnection;
}

Comm::ConnectionPointer
ConnStateData::BorrowPinnedConnection(HttpRequest *request, const AccessLogEntryPointer &ale)
{
    if (const auto connManager = request ? request->pinnedConnection() : nullptr)
        return connManager->borrowPinnedConnection(request, ale);

    // ERR_CANNOT_FORWARD is somewhat misleading here; we can still forward, but
    // there is no point since the client connection is now gone
    HttpRequestPointer requestPointer = request;
    throw ErrorState::NewForwarding(ERR_CANNOT_FORWARD, requestPointer, ale);
}

void
ConnStateData::unpinConnection(const bool andClose)
{
    debugs(33, 3, pinning.serverConnection);

    if (pinning.peer)
        cbdataReferenceDone(pinning.peer);

    if (Comm::IsConnOpen(pinning.serverConnection)) {
        if (pinning.closeHandler != nullptr) {
            comm_remove_close_handler(pinning.serverConnection->fd, pinning.closeHandler);
            pinning.closeHandler = nullptr;
        }

        stopPinnedConnectionMonitoring();

        // close the server side socket if requested
        if (andClose)
            pinning.serverConnection->close();
        pinning.serverConnection = nullptr;
    }

    safe_free(pinning.host);

    pinning.zeroReply = false;
    pinning.peerAccessDenied = false;

    /* NOTE: pinning.pinned should be kept. This combined with fd == -1 at the end of a request indicates that the host
     * connection has gone away */
}

void
ConnStateData::terminateAll(const Error &rawError, const LogTagsErrors &lte)
{
    auto error = rawError; // (cheap) copy so that we can detail
    // We detail even ERR_NONE: There should be no transactions left, and
    // detailed ERR_NONE will be unused. Otherwise, this detail helps in triage.
    if (!error.detail) {
        static const auto d = MakeNamedErrorDetail("WITH_CLIENT");
        error.detail = d;
    }

    debugs(33, 3, pipeline.count() << '/' << pipeline.nrequests << " after " << error);

    if (pipeline.empty()) {
        bareError.update(error); // XXX: bareLogTagsErrors
    } else {
        // We terminate the current CONNECT/PUT/etc. context below, logging any
        // error details, but that context may leave unparsed bytes behind.
        // Consume them to stop checkLogging() from logging them again later.
        const auto intputToConsume =
#if USE_OPENSSL
            parsingTlsHandshake ? "TLS handshake" : // more specific than CONNECT
#endif
            bodyPipe ? "HTTP request body" :
            pipeline.back()->mayUseConnection() ? "HTTP CONNECT" :
            nullptr;

        while (const auto context = pipeline.front()) {
            context->noteIoError(error, lte);
            context->finished(); // cleanup and self-deregister
            assert(context != pipeline.front());
        }

        if (intputToConsume && !inBuf.isEmpty()) {
            debugs(83, 5, "forgetting client " << intputToConsume << " bytes: " << inBuf.length());
            inBuf.clear();
        }
    }

    clientConnection->close();
}

/// log the last (attempt at) transaction if nobody else did
void
ConnStateData::checkLogging()
{
    // to simplify our logic, we assume that terminateAll() has been called
    assert(pipeline.empty());

    // do not log connections that closed after a transaction (it is normal)
    // TODO: access_log needs ACLs to match received-no-bytes connections
    if (pipeline.nrequests && inBuf.isEmpty())
        return;

    /* Create a temporary ClientHttpRequest object. Its destructor will log. */
    ClientHttpRequest http(this);
    http.req_sz = inBuf.length();
    // XXX: Or we died while waiting for the pinned connection to become idle.
    http.setErrorUri("error:transaction-end-before-headers");
    http.updateError(bareError);
}

bool
ConnStateData::shouldPreserveClientData() const
{
    // PROXY protocol bytes are meant for us and, hence, cannot be tunneled
    if (needProxyProtocolHeader_)
        return false;

    // If our decision here is negative, configuration changes are irrelevant.
    // Otherwise, clientTunnelOnError() rechecks configuration before tunneling.
    if (!Config.accessList.on_unsupported_protocol)
        return false;

    // TODO: Figure out whether/how we can support FTP tunneling.
    if (port->transport.protocol == AnyP::PROTO_FTP)
        return false;

#if USE_OPENSSL
    if (parsingTlsHandshake)
        return true;

    // the 1st HTTP request on a bumped connection
    if (!parsedBumpedRequestCount && switchedToHttps())
        return true;
#endif

    // the 1st HTTP(S) request on a connection to an intercepting port
    if (!pipeline.nrequests && transparent())
        return true;

    return false;
}

NotePairs::Pointer
ConnStateData::notes()
{
    if (!theNotes)
        theNotes = new NotePairs;
    return theNotes;
}

std::ostream &
operator <<(std::ostream &os, const ConnStateData::PinnedIdleContext &pic)
{
    return os << pic.connection << ", request=" << pic.request;
}

std::ostream &
operator <<(std::ostream &os, const ConnStateData::ServerConnectionContext &scc)
{
    return os << scc.conn_ << ", srv_bytes=" << scc.preReadServerBytes.length();
}

