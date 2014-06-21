/*
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
#include "acl/FilledChecklist.h"
#include "anyp/PortCfg.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "CachePeer.h"
#include "ChunkedCodingParser.h"
#include "client_db.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "client_side.h"
#include "ClientRequestContext.h"
#include "clientStream.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/TcpAcceptor.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "fqdncache.h"
#include "FwdState.h"
#include "globals.h"
#include "http.h"
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
#include "Mem.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mime_header.h"
#include "profiler/Profiler.h"
#include "rfc1738.h"
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
#if USE_SSL
#include "ssl/ProxyCerts.h"
#include "ssl/context_storage.h"
#include "ssl/helper.h"
#include "ssl/ServerBump.h"
#include "ssl/support.h"
#include "ssl/gadgets.h"
#endif
#if USE_SSL_CRTD
#include "ssl/crtd_message.h"
#include "ssl/certificate_db.h"
#endif

#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_MATH_H
#include <math.h>
#endif
#if HAVE_LIMITS
#include <limits>
#endif

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

/// dials clientListenerConnectionOpened call
class ListeningStartedDialer: public CallDialer, public Ipc::StartListeningCb
{
public:
    typedef void (*Handler)(AnyP::PortCfg *portCfg, const Ipc::FdNoteId note, const Subscription::Pointer &sub);
    ListeningStartedDialer(Handler aHandler, AnyP::PortCfg *aPortCfg, const Ipc::FdNoteId note, const Subscription::Pointer &aSub):
            handler(aHandler), portCfg(aPortCfg), portTypeNote(note), sub(aSub) {}

    virtual void print(std::ostream &os) const {
        startPrint(os) <<
        ", " << FdNote(portTypeNote) << " port=" << (void*)portCfg << ')';
    }

    virtual bool canDial(AsyncCall &) const { return true; }
    virtual void dial(AsyncCall &) { (handler)(portCfg, portTypeNote, sub); }

public:
    Handler handler;

private:
    AnyP::PortCfg *portCfg;   ///< from Config.Sockaddr.http
    Ipc::FdNoteId portTypeNote;    ///< Type of IPC socket being opened
    Subscription::Pointer sub; ///< The handler to be subscribed for this connetion listener
};

static void clientListenerConnectionOpened(AnyP::PortCfg *s, const Ipc::FdNoteId portTypeNote, const Subscription::Pointer &sub);

/* our socket-related context */

CBDATA_CLASS_INIT(ClientSocketContext);

/* Local functions */
/* ClientSocketContext */
static ClientSocketContext *ClientSocketContextNew(const Comm::ConnectionPointer &clientConn, ClientHttpRequest *);
/* other */
static IOCB clientWriteComplete;
static IOCB clientWriteBodyComplete;
static IOACB httpAccept;
#if USE_SSL
static IOACB httpsAccept;
#endif
static CTCB clientLifetimeTimeout;
static ClientSocketContext *parseHttpRequestAbort(ConnStateData * conn, const char *uri);
static ClientSocketContext *parseHttpRequest(ConnStateData *, HttpParser *, HttpRequestMethod *, Http::ProtocolVersion *);
#if USE_IDENT
static IDCB clientIdentDone;
#endif
static CSCB clientSocketRecipient;
static CSD clientSocketDetach;
static void clientSetKeepaliveFlag(ClientHttpRequest *);
static int clientIsContentLengthValid(HttpRequest * r);
static int clientIsRequestBodyTooLargeForPolicy(int64_t bodyLength);

static void clientUpdateStatHistCounters(LogTags logType, int svc_time);
static void clientUpdateStatCounters(LogTags logType);
static void clientUpdateHierCounters(HierarchyLogEntry *);
static bool clientPingHasFinished(ping_data const *aPing);
void prepareLogWithRequestDetails(HttpRequest *, AccessLogEntry::Pointer &);
#ifndef PURIFY
static bool connIsUsable(ConnStateData * conn);
#endif
static int responseFinishedOrFailed(HttpReply * rep, StoreIOBuffer const &receivedData);
static void ClientSocketContextPushDeferredIfNeeded(ClientSocketContext::Pointer deferredRequest, ConnStateData * conn);
static void clientUpdateSocketStats(LogTags logType, size_t size);

char *skipLeadingSpace(char *aString);
static void connNoteUseOfBuffer(ConnStateData* conn, size_t byteCount);

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

    debugs(33, 4, HERE << clientConnection << ": reading request...");

    if (!maybeMakeSpaceAvailable())
        return;

    typedef CommCbMemFunT<ConnStateData, CommIoCbParams> Dialer;
    reader = JobCallback(33, 5, Dialer, this, ConnStateData::clientReadRequest);
    comm_read(clientConnection, in.addressToReadInto(), getAvailableBufferLength(), reader);
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
ClientSocketContextNew(const Comm::ConnectionPointer &client, ClientHttpRequest * http)
{
    ClientSocketContext *newContext;
    assert(http != NULL);
    newContext = new ClientSocketContext;
    newContext->http = http;
    newContext->clientConnection = client;
    return newContext;
}

void
ClientSocketContext::writeControlMsg(HttpControlMsg &msg)
{
    const HttpReply::Pointer rep(msg.reply);
    Must(rep != NULL);

    // apply selected clientReplyContext::buildReplyHeader() mods
    // it is not clear what headers are required for control messages
    rep->header.removeHopByHopEntries();
    rep->header.putStr(HDR_CONNECTION, "keep-alive");
    httpHdrMangleList(&rep->header, http->request, ROR_REPLY);

    // remember the callback
    cbControlMsgSent = msg.cbSuccess;

    MemBuf *mb = rep->pack();

    debugs(11, 2, "HTTP Client " << clientConnection);
    debugs(11, 2, "HTTP Client CONTROL MSG:\n---------\n" << mb->buf << "\n----------");

    AsyncCall::Pointer call = commCbCall(33, 5, "ClientSocketContext::wroteControlMsg",
                                         CommIoCbPtrFun(&WroteControlMsg, this));
    Comm::Write(clientConnection, mb, call);

    delete mb;
}

/// called when we wrote the 1xx response
void
ClientSocketContext::wroteControlMsg(const Comm::ConnectionPointer &conn, char *, size_t, comm_err_t errflag, int xerrno)
{
    if (errflag == COMM_ERR_CLOSING)
        return;

    if (errflag == COMM_OK) {
        ScheduleCallHere(cbControlMsgSent);
        return;
    }

    debugs(33, 3, HERE << "1xx writing failed: " << xstrerr(xerrno));
    // no error notification: see HttpControlMsg.h for rationale and
    // note that some errors are detected elsewhere (e.g., close handler)

    // close on 1xx errors to be conservative and to simplify the code
    // (if we do not close, we must notify the source of a failure!)
    conn->close();
}

/// wroteControlMsg() wrapper: ClientSocketContext is not an AsyncJob
void
ClientSocketContext::WroteControlMsg(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    ClientSocketContext *context = static_cast<ClientSocketContext*>(data);
    context->wroteControlMsg(conn, bufnotused, size, errflag, xerrno);
}

#if USE_IDENT
static void
clientIdentDone(const char *ident, void *data)
{
    ConnStateData *conn = (ConnStateData *)data;
    xstrncpy(conn->clientConnection->rfc931, ident ? ident : dash_str, USER_IDENT_SZ);
}
#endif

void
clientUpdateStatCounters(LogTags logType)
{
    ++statCounter.client_http.requests;

    if (logTypeIsATcpHit(logType))
        ++statCounter.client_http.hits;

    if (logType == LOG_TCP_HIT)
        ++statCounter.client_http.disk_hits;
    else if (logType == LOG_TCP_MEM_HIT)
        ++statCounter.client_http.mem_hits;
}

void
clientUpdateStatHistCounters(LogTags logType, int svc_time)
{
    statCounter.client_http.allSvcTime.count(svc_time);
    /**
     * The idea here is not to be complete, but to get service times
     * for only well-defined types.  For example, we don't include
     * LOG_TCP_REFRESH_FAIL because its not really a cache hit
     * (we *tried* to validate it, but failed).
     */

    switch (logType) {

    case LOG_TCP_REFRESH_UNMODIFIED:
        statCounter.client_http.nearHitSvcTime.count(svc_time);
        break;

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
                                 tvSubMsec(start_time, current_time));

    clientUpdateHierCounters(&request->hier);
}

void
prepareLogWithRequestDetails(HttpRequest * request, AccessLogEntry::Pointer &aLogEntry)
{
    assert(request);
    assert(aLogEntry != NULL);

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

#if USE_ADAPTATION
        const Adaptation::History::Pointer ah = request->adaptLogHistory();
        if (ah != NULL) {
            packerClean(&p);
            mb.reset();
            packerToMemInit(&p, &mb);
            ah->lastMeta.packInto(&p);
            aLogEntry->adapt.last_meta = xstrdup(mb.buf);
        }
#endif

        packerClean(&p);
        mb.clean();
    }

#if ICAP_CLIENT
    const Adaptation::Icap::History::Pointer ih = request->icapHistory();
    if (ih != NULL)
        aLogEntry->icap.processingTime = ih->processingTime();
#endif

    aLogEntry->http.method = request->method;
    aLogEntry->http.version = request->http_ver;
    aLogEntry->hier = request->hier;
    if (request->content_length > 0) // negative when no body or unknown length
        aLogEntry->cache.requestSize += request->content_length;
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
    if (!out.size && !logType)
        debugs(33, 5, HERE << "logging half-baked transaction: " << log_uri);

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

    if (loggingEntry() && loggingEntry()->mem_obj)
        al->cache.objectSize = loggingEntry()->contentLen();

    al->cache.caddr.setNoAddr();

    if (getConn() != NULL) {
        al->cache.caddr = getConn()->log_addr;
        al->cache.port =  cbdataReference(getConn()->port);
    }

    al->cache.requestSize = req_sz;
    al->cache.requestHeadersSize = req_sz;

    al->cache.replySize = out.size;
    al->cache.replyHeadersSize = out.headers_sz;

    al->cache.highOffset = out.offset;

    al->cache.code = logType;

    al->cache.msec = tvSubMsec(start_time, current_time);

    if (request)
        prepareLogWithRequestDetails(request, al);

    if (getConn() != NULL && getConn()->clientConnection != NULL && getConn()->clientConnection->rfc931[0])
        al->cache.rfc931 = getConn()->clientConnection->rfc931;

#if USE_SSL && 0

    /* This is broken. Fails if the connection has been closed. Needs
     * to snarf the ssl details some place earlier..
     */
    if (getConn() != NULL)
        al->cache.ssluser = sslGetUserEmail(fd_table[getConn()->fd].ssl);

#endif

    /*Add notes*/
    // The al->notes and request->notes must point to the same object.
    (void)SyncNotes(*al, *request);
    typedef Notes::iterator ACAMLI;
    for (ACAMLI i = Config.notes.begin(); i != Config.notes.end(); ++i) {
        if (const char *value = (*i)->match(request, al->reply)) {
            NotePairs &notes = SyncNotes(*al, *request);
            notes.add((*i)->key.termedBuf(), value);
            debugs(33, 3, HERE << (*i)->key.termedBuf() << " " << value);
        }
    }

    ACLFilledChecklist checklist(NULL, request, NULL);
    if (al->reply) {
        checklist.reply = al->reply;
        HTTPMSGLOCK(checklist.reply);
    }

    if (request) {
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

/// propagates abort event to all contexts
void
ConnStateData::notifyAllContexts(int xerrno)
{
    typedef ClientSocketContext::Pointer CSCP;
    for (CSCP c = getCurrentContext(); c.getRaw(); c = c->next)
        c->noteIoError(xerrno);
}

/* This is a handler normally called by comm_close() */
void ConnStateData::connStateClosed(const CommCloseCbParams &io)
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
    flags.readMore = false;
    clientdbEstablished(clientConnection->remote, -1);	/* decrement */
    assert(areAllContextsForThisConnection());
    freeAllContexts();

    unpinConnection();

    if (Comm::IsConnOpen(clientConnection))
        clientConnection->close();

#if USE_AUTH
    // NP: do this bit after closing the connections to avoid side effects from unwanted TCP RST
    setAuth(NULL, "ConnStateData::SwanSong cleanup");
#endif

    BodyProducer::swanSong();
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
    assert(this != NULL);
    debugs(33, 3, HERE << clientConnection);

    if (isOpen())
        debugs(33, DBG_IMPORTANT, "BUG: ConnStateData did not close " << clientConnection);

    if (!flags.swanSang)
        debugs(33, DBG_IMPORTANT, "BUG: ConnStateData was not destroyed properly; " << clientConnection);

    cbdataReferenceDone(port);

    if (bodyPipe != NULL)
        stopProducingFor(bodyPipe, false);

#if USE_SSL
    delete sslServerBump;
#endif
}

/**
 * clientSetKeepaliveFlag() sets request->flags.proxyKeepalive.
 * This is the client-side persistent connection flag.  We need
 * to set this relatively early in the request processing
 * to handle hacks for broken servers and clients.
 */
static void
clientSetKeepaliveFlag(ClientHttpRequest * http)
{
    HttpRequest *request = http->request;

    debugs(33, 3, "clientSetKeepaliveFlag: http_ver = " <<
           request->http_ver.major << "." << request->http_ver.minor);
    debugs(33, 3, "clientSetKeepaliveFlag: method = " <<
           RequestMethodStr(request->method));

    // TODO: move to HttpRequest::hdrCacheInit, just like HttpReply.
    request->flags.proxyKeepalive = request->persistent();
}

static int
clientIsContentLengthValid(HttpRequest * r)
{
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
        return 1;		/* too large */

    return 0;
}

#ifndef PURIFY
bool
connIsUsable(ConnStateData * conn)
{
    if (conn == NULL || !cbdataReferenceValid(conn) || !Comm::IsConnOpen(conn->clientConnection))
        return false;

    return true;
}

#endif

// careful: the "current" context may be gone if we wrote an early response
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

    if (!multipartRangeRequest() && !http->request->flags.chunkedReply) {
        size_t length = lengthToSend(bodyData.range());
        noteSentBodyBytes (length);
        AsyncCall::Pointer call = commCbCall(33, 5, "clientWriteBodyComplete",
                                             CommIoCbPtrFun(clientWriteBodyComplete, this));
        Comm::Write(clientConnection, bodyData.data, length, call, NULL);
        return;
    }

    MemBuf mb;
    mb.init();
    if (multipartRangeRequest())
        packRange(bodyData, &mb);
    else
        packChunk(bodyData, mb);

    if (mb.contentSize()) {
        /* write */
        AsyncCall::Pointer call = commCbCall(33, 5, "clientWriteComplete",
                                             CommIoCbPtrFun(clientWriteComplete, this));
        Comm::Write(clientConnection, &mb, call);
    }  else
        writeComplete(clientConnection, NULL, 0, COMM_OK);
}

/**
 * Packs bodyData into mb using chunked encoding. Packs the last-chunk
 * if bodyData is empty.
 */
void
ClientSocketContext::packChunk(const StoreIOBuffer &bodyData, MemBuf &mb)
{
    const uint64_t length =
        static_cast<uint64_t>(lengthToSend(bodyData.range()));
    noteSentBodyBytes(length);

    mb.Printf("%" PRIX64 "\r\n", length);
    mb.append(bodyData.data, length);
    mb.Printf("\r\n");
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
            assert(http->out.offset + (int64_t)available.size() > i->currentSpec()->offset);

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

        if (available.size() <= (uint64_t)skip)
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
            debugs(33, DBG_IMPORTANT, "clientIfRangeMatch: Weak ETags are not allowed in If-Range: " << spec.tag.str << " ? " << rep_tag.str);
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

    int64_t roffLimit = request->getRangeOffsetLimit();

    if (!rep)
        range_err = "no [parse-able] reply";
    else if ((rep->sline.status() != Http::scOkay) && (rep->sline.status() != Http::scPartialContent))
        range_err = "wrong status code";
    else if (hdr->has(HDR_CONTENT_RANGE))
        range_err = "origin server does ranges";
    else if (rep->content_length < 0)
        range_err = "unknown length";
    else if (rep->content_length != http->memObject()->getReply()->content_length)
        range_err = "INCONSISTENT length";	/* a bug? */

    /* hits only - upstream CachePeer determines correct behaviour on misses, and client_side_reply determines
     * hits candidates
     */
    else if (logTypeIsATcpHit(http->logType) && http->request->header.has(HDR_IF_RANGE) && !clientIfRangeMatch(http, rep))
        range_err = "If-Range match failed";
    else if (!http->request->range->canonize(rep))
        range_err = "canonization failed";
    else if (http->request->range->isComplex())
        range_err = "too complex range header";
    else if (!logTypeIsATcpHit(http->logType) && http->request->range->offsetLimitExceeded(roffLimit))
        range_err = "range outside range_offset_limit";

    /* get rid of our range specs on error */
    if (range_err) {
        /* XXX We do this here because we need canonisation etc. However, this current
         * code will lead to incorrect store offset requests - the store will have the
         * offset data, but we won't be requesting it.
         * So, we can either re-request, or generate an error
         */
        http->request->ignoreRange(range_err);
    } else {
        /* XXX: TODO: Review, this unconditional set may be wrong. */
        rep->sline.set(rep->sline.version, Http::scPartialContent);
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

    // dump now, so we dont output any body.
    debugs(11, 2, "HTTP Client " << clientConnection);
    debugs(11, 2, "HTTP Client REPLY:\n---------\n" << mb->buf << "\n----------");

    /* Save length of headers for persistent conn checks */
    http->out.headers_sz = mb->contentSize();
#if HEADERS_LOG

    headersLog(0, 0, http->request->method, rep);
#endif

    if (bodyData.data && bodyData.length) {
        if (multipartRangeRequest())
            packRange(bodyData, mb);
        else if (http->request->flags.chunkedReply) {
            packChunk(bodyData, *mb);
        } else {
            size_t length = lengthToSend(bodyData.range());
            noteSentBodyBytes (length);

            mb->append(bodyData.data, length);
        }
    }

    /* write */
    debugs(33,7, HERE << "sendStartOfMessage schedules clientWriteComplete");
    AsyncCall::Pointer call = commCbCall(33, 5, "clientWriteComplete",
                                         CommIoCbPtrFun(clientWriteComplete, this));
    Comm::Write(clientConnection, mb, call);
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

    /* TODO: check offset is what we asked for */

    if (context != http->getConn()->getCurrentContext()) {
        context->deferRecipientForLater(node, rep, receivedData);
        PROF_stop(clientSocketRecipient);
        return;
    }

    // After sending Transfer-Encoding: chunked (at least), always send
    // the last-chunk if there was no error, ignoring responseFinishedOrFailed.
    const bool mustSendLastChunk = http->request->flags.chunkedReply &&
                                   !http->request->flags.streamError && !context->startOfOutput();
    if (responseFinishedOrFailed(rep, receivedData) && !mustSendLastChunk) {
        context->writeComplete(context->clientConnection, NULL, 0, COMM_OK);
        PROF_stop(clientSocketRecipient);
        return;
    }

    if (!context->startOfOutput())
        context->sendBody(rep, receivedData);
    else {
        assert(rep);
        http->al->reply = rep;
        HTTPMSGLOCK(http->al->reply);
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
clientWriteBodyComplete(const Comm::ConnectionPointer &conn, char *buf, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    debugs(33,7, HERE << "clientWriteBodyComplete schedules clientWriteComplete");
    clientWriteComplete(conn, NULL, size, errflag, xerrno, data);
}

void
ConnStateData::readNextRequest()
{
    debugs(33, 5, HERE << clientConnection << " reading next req");

    fd_note(clientConnection->fd, "Idle client: Waiting for next request");
    /**
     * Set the timeout BEFORE calling clientReadRequest().
     */
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5,
                                     TimeoutDialer, this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.clientIdlePconn, timeoutCall);

    readSomeData();
    /** Please don't do anything with the FD past here! */
}

static void
ClientSocketContextPushDeferredIfNeeded(ClientSocketContext::Pointer deferredRequest, ConnStateData * conn)
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

/// called when we have successfully finished writing the response
void
ClientSocketContext::keepaliveNextRequest()
{
    ConnStateData * conn = http->getConn();

    debugs(33, 3, HERE << "ConnnStateData(" << conn->clientConnection << "), Context(" << clientConnection << ")");
    connIsFinished();

    if (conn->pinning.pinned && !Comm::IsConnOpen(conn->pinning.serverConnection)) {
        debugs(33, 2, HERE << conn->clientConnection << " Connection was pinned but server side gone. Terminating client connection");
        conn->clientConnection->close();
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

    if (const char *reason = conn->stoppedReceiving()) {
        debugs(33, 3, HERE << "closing for earlier request error: " << reason);
        conn->clientConnection->close();
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

    if (conn->clientParseRequests()) {
        debugs(33, 3, HERE << conn->clientConnection << ": parsed next request from buffer");
    }

    /** \par
     * Either we need to kick-start another read or, if we have
     * a half-closed connection, kill it after the last request.
     * This saves waiting for half-closed connections to finished being
     * half-closed _AND_ then, sometimes, spending "Timeout" time in
     * the keepalive "Waiting for next request" state.
     */
    if (commIsHalfClosed(conn->clientConnection->fd) && (conn->getConcurrentRequestCount() == 0)) {
        debugs(33, 3, "ClientSocketContext::keepaliveNextRequest: half-closed client with no pending requests, closing");
        conn->clientConnection->close();
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
        debugs(33, 3, HERE << conn->clientConnection << ": calling PushDeferredIfNeeded");
        ClientSocketContextPushDeferredIfNeeded(deferredRequest, conn);
    } else if (conn->flags.readMore) {
        debugs(33, 3, HERE << conn->clientConnection << ": calling conn->readNextRequest()");
        conn->readNextRequest();
    } else {
        // XXX: Can this happen? CONNECT tunnels have deferredRequest set.
        debugs(33, DBG_IMPORTANT, HERE << "abandoning " << conn->clientConnection);
    }
}

void
clientUpdateSocketStats(LogTags logType, size_t size)
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
        debugs(33, 5, HERE << "At end of current range spec for " << clientConnection);

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
    debugs (33, 5, "range: " << http->request->range <<
            "; http offset " << http->out.offset <<
            "; reply " << reply);

    // XXX: This method is called from many places, including pullData() which
    // may be called before prepareReply() [on some Squid-generated errors].
    // Hence, we may not even know yet whether we should honor/do ranges.

    if (http->request->range) {
        /* offset in range specs does not count the prefix of an http msg */
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
    debugs(33, 5, reply << " written " << http->out.size << " into " << clientConnection);

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
                       "range sequence on " << clientConnection);

                if (http->request->flags.proxyKeepalive)
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
                if (http->request->flags.proxyKeepalive)
                    return STREAM_COMPLETE;
                else
                    return STREAM_UNPLANNED_COMPLETE;
            }

            // The logic below is not clear: If we got more than we
            // expected why would persistency matter? Should not this
            // always be an error?
            if (bytesSent > bytesExpected) { // got extra
                if (http->request->flags.proxyKeepalive)
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
clientWriteComplete(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    ClientSocketContext *context = (ClientSocketContext *)data;
    context->writeComplete(conn, bufnotused, size, errflag);
}

/// remembers the abnormal connection termination for logging purposes
void
ClientSocketContext::noteIoError(const int xerrno)
{
    if (http) {
        if (xerrno == ETIMEDOUT)
            http->al->http.timedout = true;
        else // even if xerrno is zero (which means read abort/eof)
            http->al->http.aborted = true;
    }
}

void
ClientSocketContext::doClose()
{
    clientConnection->close();
}

/// called when we encounter a response-related error
void
ClientSocketContext::initiateClose(const char *reason)
{
    http->getConn()->stopSending(reason); // closes ASAP
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
                   " request body bytes with " << in.notYetUsed << " unused");
            return; // wait for the request receiver to finish reading
        }
    }

    clientConnection->close();
}

void
ClientSocketContext::writeComplete(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag)
{
    const StoreEntry *entry = http->storeEntry();
    http->out.size += size;
    debugs(33, 5, HERE << conn << ", sz " << size <<
           ", err " << errflag << ", off " << http->out.size << ", len " <<
           (entry ? entry->objectLen() : 0));
    clientUpdateSocketStats(http->logType, size);

    /* Bail out quickly on COMM_ERR_CLOSING - close handlers will tidy up */

    if (errflag == COMM_ERR_CLOSING || !Comm::IsConnOpen(conn))
        return;

    if (errflag || clientHttpRequestStatus(conn->fd, http)) {
        initiateClose("failure or true request status");
        /* Do we leak here ? */
        return;
    }

    switch (socketState()) {

    case STREAM_NONE:
        pullData();
        break;

    case STREAM_COMPLETE:
        debugs(33, 5, HERE << conn << " Keeping Alive");
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

SQUIDCEXTERN CSR clientGetMoreData;
SQUIDCEXTERN CSS clientReplyStatus;
SQUIDCEXTERN CSD clientReplyDetach;

static ClientSocketContext *
parseHttpRequestAbort(ConnStateData * csd, const char *uri)
{
    ClientHttpRequest *http;
    ClientSocketContext *context;
    StoreIOBuffer tempBuffer;
    http = new ClientHttpRequest(csd);
    http->req_sz = csd->in.notYetUsed;
    http->uri = xstrdup(uri);
    setLogUri (http, uri);
    context = ClientSocketContextNew(csd->clientConnection, http);
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
prepareAcceleratedURL(ConnStateData * conn, ClientHttpRequest *http, char *url, const char *req_hdr)
{
    int vhost = conn->port->vhost;
    int vport = conn->port->vport;
    char *host;
    char ipbuf[MAX_IPSTRLEN];

    http->flags.accel = true;

    /* BUG: Squid cannot deal with '*' URLs (RFC2616 5.1.2) */

    if (strncasecmp(url, "cache_object://", 15) == 0)
        return; /* already in good shape */

    if (*url != '/') {
        if (conn->port->vhost)
            return; /* already in good shape */

        /* else we need to ignore the host name */
        url = strstr(url, "//");

#if SHOULD_REJECT_UNKNOWN_URLS

        if (!url) {
            hp->request_parse_status = Http::scBadRequest;
            return parseHttpRequestAbort(conn, "error:invalid-request");
        }
#endif

        if (url)
            url = strchr(url + 2, '/');

        if (!url)
            url = (char *) "/";
    }

    if (vport < 0)
        vport = http->getConn()->clientConnection->local.port();

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
        http->getConn()->clientConnection->local.toHostStr(ipbuf,MAX_IPSTRLEN);
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

    if ((host = mime_get_header(req_hdr, "Host")) != NULL) {
        int url_sz = strlen(url) + 32 + Config.appendDomainLen +
                     strlen(host);
        http->uri = (char *)xcalloc(url_sz, 1);
        snprintf(http->uri, url_sz, "%s://%s%s", conn->port->protocol, host, url);
        debugs(33, 5, "TRANSPARENT HOST REWRITE: '" << http->uri <<"'");
    } else {
        /* Put the local socket IP address as the hostname.  */
        int url_sz = strlen(url) + 32 + Config.appendDomainLen;
        http->uri = (char *)xcalloc(url_sz, 1);
        http->getConn()->clientConnection->local.toHostStr(ipbuf,MAX_IPSTRLEN);
        snprintf(http->uri, url_sz, "%s://%s:%d%s",
                 http->getConn()->port->protocol,
                 ipbuf, http->getConn()->clientConnection->local.port(), url);
        debugs(33, 5, "TRANSPARENT REWRITE: '" << http->uri << "'");
    }
}

/** Parse an HTTP request
 *
 *  \note Sets result->flags.parsed_ok to 0 if failed to parse the request,
 *          to 1 if the request was correctly parsed.
 *  \param[in] csd a ConnStateData. The caller must make sure it is not null
 *  \param[in] hp an HttpParser
 *  \param[out] mehtod_p will be set as a side-effect of the parsing.
 *          Pointed-to value will be set to Http::METHOD_NONE in case of
 *          parsing failure
 *  \param[out] http_ver will be set as a side-effect of the parsing
 *  \return NULL on incomplete requests,
 *          a ClientSocketContext structure on success or failure.
 */
static ClientSocketContext *
parseHttpRequest(ConnStateData *csd, HttpParser *hp, HttpRequestMethod * method_p, Http::ProtocolVersion *http_ver)
{
    char *req_hdr = NULL;
    char *end;
    size_t req_sz;
    ClientHttpRequest *http;
    ClientSocketContext *result;
    StoreIOBuffer tempBuffer;
    int r;

    /* pre-set these values to make aborting simpler */
    *method_p = Http::METHOD_NONE;

    /* NP: don't be tempted to move this down or remove again.
     * It's the only DDoS protection old-String has against long URL */
    if ( hp->bufsiz <= 0) {
        debugs(33, 5, "Incomplete request, waiting for end of request line");
        return NULL;
    } else if ( (size_t)hp->bufsiz >= Config.maxRequestHeaderSize && headersEnd(hp->buf, Config.maxRequestHeaderSize) == 0) {
        debugs(33, 5, "parseHttpRequest: Too large request");
        hp->request_parse_status = Http::scHeaderTooLarge;
        return parseHttpRequestAbort(csd, "error:request-too-large");
    }

    /* Attempt to parse the first line; this'll define the method, url, version and header begin */
    r = HttpParserParseReqLine(hp);

    if (r == 0) {
        debugs(33, 5, "Incomplete request, waiting for end of request line");
        return NULL;
    }

    if (r == -1) {
        return parseHttpRequestAbort(csd, "error:invalid-request");
    }

    /* Request line is valid here .. */
    *http_ver = Http::ProtocolVersion(hp->req.v_maj, hp->req.v_min);

    /* This call scans the entire request, not just the headers */
    if (hp->req.v_maj > 0) {
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

    hp->hdr_start = hp->req.end + 1;

    /* Enforce max_request_size */
    if (req_sz >= Config.maxRequestHeaderSize) {
        debugs(33, 5, "parseHttpRequest: Too large request");
        hp->request_parse_status = Http::scHeaderTooLarge;
        return parseHttpRequestAbort(csd, "error:request-too-large");
    }

    /* Set method_p */
    *method_p = HttpRequestMethod(&hp->buf[hp->req.m_start], &hp->buf[hp->req.m_end]+1);

    /* deny CONNECT via accelerated ports */
    if (*method_p == Http::METHOD_CONNECT && csd->port && csd->port->flags.accelSurrogate) {
        debugs(33, DBG_IMPORTANT, "WARNING: CONNECT method received on " << csd->port->protocol << " Accelerator port " << csd->port->s.port() );
        /* XXX need a way to say "this many character length string" */
        debugs(33, DBG_IMPORTANT, "WARNING: for request: " << hp->buf);
        hp->request_parse_status = Http::scMethodNotAllowed;
        return parseHttpRequestAbort(csd, "error:method-not-allowed");
    }

    if (*method_p == Http::METHOD_NONE) {
        /* XXX need a way to say "this many character length string" */
        debugs(33, DBG_IMPORTANT, "clientParseRequestMethod: Unsupported method in request '" << hp->buf << "'");
        hp->request_parse_status = Http::scMethodNotAllowed;
        return parseHttpRequestAbort(csd, "error:unsupported-request-method");
    }

    /*
     * Process headers after request line
     * TODO: Use httpRequestParse here.
     */
    /* XXX this code should be modified to take a const char * later! */
    req_hdr = (char *) hp->buf + hp->req.end + 1;

    debugs(33, 3, "parseHttpRequest: req_hdr = {" << req_hdr << "}");

    end = (char *) hp->buf + hp->hdr_end;

    debugs(33, 3, "parseHttpRequest: end = {" << end << "}");

    debugs(33, 3, "parseHttpRequest: prefix_sz = " <<
           (int) HttpParserRequestLen(hp) << ", req_line_sz = " <<
           HttpParserReqSz(hp));

    /* Ok, all headers are received */
    http = new ClientHttpRequest(csd);

    http->req_sz = HttpParserRequestLen(hp);
    result = ClientSocketContextNew(csd->clientConnection, http);
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
    char *url = (char *)xmalloc(hp->req.u_end - hp->req.u_start + 16);

    memcpy(url, hp->buf + hp->req.u_start, hp->req.u_end - hp->req.u_start + 1);

    url[hp->req.u_end - hp->req.u_start + 1] = '\0';

#if THIS_VIOLATES_HTTP_SPECS_ON_URL_TRANSFORMATION

    if ((t = strchr(url, '#')))	/* remove HTML anchors */
        *t = '\0';

#endif

    debugs(33,5, HERE << "repare absolute URL from " <<
           (csd->transparent()?"intercept":(csd->port->flags.accelSurrogate ? "accel":"")));
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
    if (csd->transparent()) {
        /* intercept or transparent mode, properly working with no failures */
        prepareTransparentURL(csd, http, url, req_hdr);

    } else if (internalCheck(url)) {
        /* internal URL mode */
        /* prepend our name & port */
        http->uri = xstrdup(internalLocalUri(NULL, url));
        // We just re-wrote the URL. Must replace the Host: header.
        //  But have not parsed there yet!! flag for local-only handling.
        http->flags.internal = true;

    } else if (csd->port->flags.accelSurrogate || csd->switchedToHttps()) {
        /* accelerator mode */
        prepareAcceleratedURL(csd, http, url, req_hdr);
    }

    if (!http->uri) {
        /* No special rewrites have been applied above, use the
         * requested url. may be rewritten later, so make extra room */
        int url_sz = strlen(url) + Config.appendDomainLen + 5;
        http->uri = (char *)xcalloc(url_sz, 1);
        strcpy(http->uri, url);
    }

    debugs(33, 5, "parseHttpRequest: Complete request received");

    // XXX: crop this dump at the end of headers. No need for extras
    debugs(11, 2, "HTTP Client " << csd->clientConnection);
    debugs(11, 2, "HTTP Client REQUEST:\n---------\n" << (hp->buf) + hp->req.m_start << "\n----------");

    result->flags.parsed_ok = 1;
    xfree(url);
    return result;
}

int
ConnStateData::getAvailableBufferLength() const
{
    assert (in.allocatedSize > in.notYetUsed); // allocated more than used
    const size_t result = in.allocatedSize - in.notYetUsed - 1;
    // huge request_header_max_size may lead to more than INT_MAX unused space
    assert (static_cast<ssize_t>(result) <= INT_MAX);
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
        debugs(33, 2, "connReadWasError: FD " << clientConnection << ": got flag " << flag);
        return 1;
    }

    if (size < 0) {
        if (!ignoreErrno(xerrno)) {
            debugs(33, 2, "connReadWasError: FD " << clientConnection << ": " << xstrerr(xerrno));
            return 1;
        } else if (in.notYetUsed == 0) {
            debugs(33, 2, "connReadWasError: FD " << clientConnection << ": no data to process (" << xstrerr(xerrno) << ")");
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
            debugs(33, 4, HERE << clientConnection << " closed");
            return 1;
        } else if (!Config.onoff.half_closed_clients) {
            /* admin doesn't want to support half-closed client sockets */
            debugs(33, 3, HERE << clientConnection << " aborted (half_closed_clients disabled)");
            notifyAllContexts(0); // no specific error implies abort
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
        memmove(conn->in.buf, conn->in.buf + byteCount, conn->in.notYetUsed);
}

/// respond with ERR_TOO_BIG if request header exceeds request_header_max_size
void
ConnStateData::checkHeaderLimits()
{
    if (in.notYetUsed < Config.maxRequestHeaderSize)
        return; // can accumulte more header data

    debugs(33, 3, "Request header is too large (" << in.notYetUsed << " > " <<
           Config.maxRequestHeaderSize << " bytes)");

    ClientSocketContext *context = parseHttpRequestAbort(this, "error:request-too-large");
    clientStreamNode *node = context->getClientReplyContext();
    clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
    assert (repContext);
    repContext->setReplyToError(ERR_TOO_BIG,
                                Http::scBadRequest, Http::METHOD_NONE, NULL,
                                clientConnection->remote, NULL, NULL, NULL);
    context->registerWithConn();
    context->pullData();
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

#if USE_SSL
bool ConnStateData::serveDelayedError(ClientSocketContext *context)
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
    if (X509 *srvCert = sslServerBump->serverCert.get()) {
        HttpRequest *request = http->request;
        if (!Ssl::checkX509ServerValidity(srvCert, request->GetHost())) {
            debugs(33, 2, "SQUID_X509_V_ERR_DOMAIN_MISMATCH: Certificate " <<
                   "does not match domainname " << request->GetHost());

            bool allowDomainMismatch = false;
            if (Config.ssl_client.cert_error) {
                ACLFilledChecklist check(Config.ssl_client.cert_error, request, dash_str);
                check.sslErrors = new Ssl::CertErrors(Ssl::CertError(SQUID_X509_V_ERR_DOMAIN_MISMATCH, srvCert));
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
                request->hier.note(peekerRequest->hier.tcpServer, request->GetHost());

                // Create an error object and fill it
                ErrorState *err = new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scServiceUnavailable, request);
                err->src_addr = clientConnection->remote;
                Ssl::ErrorDetail *errDetail = new Ssl::ErrorDetail(
                    SQUID_X509_V_ERR_DOMAIN_MISMATCH,
                    srvCert, NULL);
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
#endif // USE_SSL

static void
clientProcessRequest(ConnStateData *conn, HttpParser *hp, ClientSocketContext *context, const HttpRequestMethod& method, Http::ProtocolVersion http_ver)
{
    ClientHttpRequest *http = context->http;
    HttpRequest::Pointer request;
    bool notedUseOfBuffer = false;
    bool chunked = false;
    bool mustReplyToOptions = false;
    bool unsupportedTe = false;
    bool expectBody = false;

    /* We have an initial client stream in place should it be needed */
    /* setup our private context */
    context->registerWithConn();

    if (context->flags.parsed_ok == 0) {
        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 2, "clientProcessRequest: Invalid Request");
        conn->quitAfterError(NULL);
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        switch (hp->request_parse_status) {
        case Http::scHeaderTooLarge:
            repContext->setReplyToError(ERR_TOO_BIG, Http::scBadRequest, method, http->uri, conn->clientConnection->remote, NULL, conn->in.buf, NULL);
            break;
        case Http::scMethodNotAllowed:
            repContext->setReplyToError(ERR_UNSUP_REQ, Http::scMethodNotAllowed, method, http->uri,
                                        conn->clientConnection->remote, NULL, conn->in.buf, NULL);
            break;
        default:
            repContext->setReplyToError(ERR_INVALID_REQ, hp->request_parse_status, method, http->uri,
                                        conn->clientConnection->remote, NULL, conn->in.buf, NULL);
        }
        assert(context->http->out.offset == 0);
        context->pullData();
        goto finish;
    }

    if ((request = HttpRequest::CreateFromUrlAndMethod(http->uri, method)) == NULL) {
        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 5, "Invalid URL: " << http->uri);
        conn->quitAfterError(request.getRaw());
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_INVALID_URL, Http::scBadRequest, method, http->uri, conn->clientConnection->remote, NULL, NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        goto finish;
    }

    /* RFC 2616 section 10.5.6 : handle unsupported HTTP major versions cleanly. */
    /* We currently only support 0.9, 1.0, 1.1 properly */
    if ( (http_ver.major == 0 && http_ver.minor != 9) ||
            (http_ver.major > 1) ) {

        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 5, "Unsupported HTTP version discovered. :\n" << HttpParserHdrBuf(hp));
        conn->quitAfterError(request.getRaw());
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_UNSUP_HTTPVERSION, Http::scHttpVersionNotSupported, method, http->uri,
                                    conn->clientConnection->remote, NULL, HttpParserHdrBuf(hp), NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        goto finish;
    }

    /* compile headers */
    /* we should skip request line! */
    /* XXX should actually know the damned buffer size here */
    if (http_ver.major >= 1 && !request->parseHeader(HttpParserHdrBuf(hp), HttpParserHdrSz(hp))) {
        clientStreamNode *node = context->getClientReplyContext();
        debugs(33, 5, "Failed to parse request headers:\n" << HttpParserHdrBuf(hp));
        conn->quitAfterError(request.getRaw());
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_INVALID_REQ, Http::scBadRequest, method, http->uri, conn->clientConnection->remote, NULL, NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        goto finish;
    }

    request->clientConnectionManager = conn;

    request->flags.accelerated = http->flags.accel;
    request->flags.sslBumped=conn->switchedToHttps();
    request->flags.ignoreCc = conn->port->ignore_cc;
    // TODO: decouple http->flags.accel from request->flags.sslBumped
    request->flags.noDirect = (request->flags.accelerated && !request->flags.sslBumped) ?
                              !conn->port->allow_direct : 0;
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
        if (request->flags.interceptTproxy) {
            if (Config.accessList.spoof_client_ip) {
                ACLFilledChecklist *checklist = clientAclChecklistCreate(Config.accessList.spoof_client_ip, http);
                request->flags.spoofClientIp = (checklist->fastCheck() == ACCESS_ALLOWED);
                delete checklist;
            } else
                request->flags.spoofClientIp = true;
        } else
            request->flags.spoofClientIp = false;
    }

    if (internalCheck(request->urlpath.termedBuf())) {
        if (internalHostnameIs(request->GetHost()) &&
                request->port == getMyPort()) {
            http->flags.internal = true;
        } else if (Config.onoff.global_internal_static && internalStaticCheck(request->urlpath.termedBuf())) {
            request->SetHost(internalHostname());
            request->port = getMyPort();
            http->flags.internal = true;
        }
    }

    if (http->flags.internal) {
        request->protocol = AnyP::PROTO_HTTP;
        request->login[0] = '\0';
    }

    request->flags.internal = http->flags.internal;
    setLogUri (http, urlCanonicalClean(request.getRaw()));
    request->client_addr = conn->clientConnection->remote; // XXX: remove reuest->client_addr member.
#if FOLLOW_X_FORWARDED_FOR
    // indirect client gets stored here because it is an HTTP header result (from X-Forwarded-For:)
    // not a details about teh TCP connection itself
    request->indirect_client_addr = conn->clientConnection->remote;
#endif /* FOLLOW_X_FORWARDED_FOR */
    request->my_addr = conn->clientConnection->local;
    request->myportname = conn->port->name;
    request->http_ver = http_ver;

    // Link this HttpRequest to ConnStateData relatively early so the following complex handling can use it
    // TODO: this effectively obsoletes a lot of conn->FOO copying. That needs cleaning up later.
    request->clientConnectionManager = conn;

    if (request->header.chunked()) {
        chunked = true;
    } else if (request->header.has(HDR_TRANSFER_ENCODING)) {
        const String te = request->header.getList(HDR_TRANSFER_ENCODING);
        // HTTP/1.1 requires chunking to be the last encoding if there is one
        unsupportedTe = te.size() && te != "identity";
    } // else implied identity coding

    mustReplyToOptions = (method == Http::METHOD_OPTIONS) &&
                         (request->header.getInt64(HDR_MAX_FORWARDS) == 0);
    if (!urlCheckRequest(request.getRaw()) || mustReplyToOptions || unsupportedTe) {
        clientStreamNode *node = context->getClientReplyContext();
        conn->quitAfterError(request.getRaw());
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(ERR_UNSUP_REQ, Http::scNotImplemented, request->method, NULL,
                                    conn->clientConnection->remote, request.getRaw(), NULL, NULL);
        assert(context->http->out.offset == 0);
        context->pullData();
        goto finish;
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
        goto finish;
    }

    if (request->header.has(HDR_EXPECT)) {
        const String expect = request->header.getList(HDR_EXPECT);
        const bool supportedExpect = (expect.caseCmp("100-continue") == 0);
        if (!supportedExpect) {
            clientStreamNode *node = context->getClientReplyContext();
            clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
            assert (repContext);
            conn->quitAfterError(request.getRaw());
            repContext->setReplyToError(ERR_INVALID_REQ, Http::scExpectationFailed, request->method, http->uri,
                                        conn->clientConnection->remote, request.getRaw(), NULL, NULL);
            assert(context->http->out.offset == 0);
            context->pullData();
            goto finish;
        }
    }

    http->request = request.getRaw();
    HTTPMSGLOCK(http->request);
    clientSetKeepaliveFlag(http);

    // Let tunneling code be fully responsible for CONNECT requests
    if (http->request->method == Http::METHOD_CONNECT) {
        context->mayUseConnection(true);
        conn->flags.readMore = false;

        // consume header early so that tunnel gets just the body
        connNoteUseOfBuffer(conn, http->req_sz);
        notedUseOfBuffer = true;
    }

#if USE_SSL
    if (conn->switchedToHttps() && conn->serveDelayedError(context))
        goto finish;
#endif

    /* Do we expect a request-body? */
    expectBody = chunked || request->content_length > 0;
    if (!context->mayUseConnection() && expectBody) {
        request->body_pipe = conn->expectRequestBody(
                                 chunked ? -1 : request->content_length);

        // consume header early so that body pipe gets just the body
        connNoteUseOfBuffer(conn, http->req_sz);
        notedUseOfBuffer = true;

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
            goto finish;
        }

        // We may stop producing, comm_close, and/or call setReplyToError()
        // below, so quit on errors to avoid http->doCallouts()
        if (!conn->handleRequestBodyData())
            goto finish;

        if (!request->body_pipe->productionEnded()) {
            debugs(33, 5, HERE << "need more request body");
            context->mayUseConnection(true);
            assert(conn->flags.readMore);
        }
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
    if (request != NULL && request->flags.resetTcp && Comm::IsConnOpen(conn->clientConnection)) {
        debugs(33, 3, HERE << "Sending TCP RST on " << conn->clientConnection);
        conn->flags.readMore = false;
        comm_reset_close(conn->clientConnection);
    }
}

static void
connStripBufferWhitespace (ConnStateData * conn)
{
    while (conn->in.notYetUsed > 0 && xisspace(conn->in.buf[0])) {
        memmove(conn->in.buf, conn->in.buf + 1, conn->in.notYetUsed - 1);
        -- conn->in.notYetUsed;
    }
}

/**
 * Limit the number of concurrent requests.
 * \return true  when there are available position(s) in the pipeline queue for another request.
 * \return false when the pipeline queue is full or disabled.
 */
bool
ConnStateData::concurrentRequestQueueFilled() const
{
    const int existingRequestCount = getConcurrentRequestCount();

    // default to the configured pipeline size.
    // add 1 because the head of pipeline is counted in concurrent requests and not prefetch queue
    const int concurrentRequestLimit = Config.pipeline_max_prefetch + 1;

    // when queue filled already we cant add more.
    if (existingRequestCount >= concurrentRequestLimit) {
        debugs(33, 3, clientConnection << " max concurrent requests reached (" << concurrentRequestLimit << ")");
        debugs(33, 5, clientConnection << " deferring new request until one is done");
        return true;
    }

    return false;
}

/**
 * Attempt to parse one or more requests from the input buffer.
 * If a request is successfully parsed, even if the next request
 * is only partially parsed, it will return TRUE.
 */
bool
ConnStateData::clientParseRequests()
{
    HttpRequestMethod method;
    bool parsed_req = false;

    debugs(33, 5, HERE << clientConnection << ": attempting to parse");

    // Loop while we have read bytes that are not needed for producing the body
    // On errors, bodyPipe may become nil, but readMore will be cleared
    while (in.notYetUsed > 0 && !bodyPipe && flags.readMore) {
        connStripBufferWhitespace(this);

        /* Don't try to parse if the buffer is empty */
        if (in.notYetUsed == 0)
            break;

        /* Limit the number of concurrent requests */
        if (concurrentRequestQueueFilled())
            break;

        /* Should not be needed anymore */
        /* Terminate the string */
        in.buf[in.notYetUsed] = '\0';

        /* Begin the parsing */
        PROF_start(parseHttpRequest);
        HttpParserInit(&parser_, in.buf, in.notYetUsed);

        /* Process request */
        Http::ProtocolVersion http_ver;
        ClientSocketContext *context = parseHttpRequest(this, &parser_, &method, &http_ver);
        PROF_stop(parseHttpRequest);

        /* partial or incomplete request */
        if (!context) {
            // TODO: why parseHttpRequest can just return parseHttpRequestAbort
            // (which becomes context) but checkHeaderLimits cannot?
            checkHeaderLimits();
            break;
        }

        /* status -1 or 1 */
        if (context) {
            debugs(33, 5, HERE << clientConnection << ": parsed a request");
            AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "clientLifetimeTimeout",
                                             CommTimeoutCbPtrFun(clientLifetimeTimeout, context->http));
            commSetConnTimeout(clientConnection, Config.Timeout.lifetime, timeoutCall);

            clientProcessRequest(this, &parser_, context, method, http_ver);

            parsed_req = true; // XXX: do we really need to parse everything right NOW ?

            if (context->mayUseConnection()) {
                debugs(33, 3, HERE << "Not parsing new requests, as this request may need the connection");
                break;
            }
        }
    }

    /* XXX where to 'finish' the parsing pass? */
    return parsed_req;
}

void
ConnStateData::clientReadRequest(const CommIoCbParams &io)
{
    debugs(33,5,HERE << io.conn << " size " << io.size);
    Must(reading());
    reader = NULL;

    /* Bail out quickly on COMM_ERR_CLOSING - close handlers will tidy up */

    if (io.flag == COMM_ERR_CLOSING) {
        debugs(33,5, HERE << io.conn << " closing Bailout.");
        return;
    }

    assert(Comm::IsConnOpen(clientConnection));
    assert(io.conn->fd == clientConnection->fd);

    /*
     * Don't reset the timeout value here.  The timeout value will be
     * set to Config.Timeout.request by httpAccept() and
     * clientWriteComplete(), and should apply to the request as a
     * whole, not individual read() calls.  Plus, it breaks our
     * lame half-close detection
     */
    if (connReadWasError(io.flag, io.size, io.xerrno)) {
        notifyAllContexts(io.xerrno);
        io.conn->close();
        return;
    }

    if (io.flag == COMM_OK) {
        if (io.size > 0) {
            kb_incr(&(statCounter.client_http.kbytes_in), io.size);

            // may comm_close or setReplyToError
            if (!handleReadData(io.buf, io.size))
                return;

        } else if (io.size == 0) {
            debugs(33, 5, HERE << io.conn << " closed?");

            if (connFinishedWithConn(io.size)) {
                clientConnection->close();
                return;
            }

            /* It might be half-closed, we can't tell */
            fd_table[io.conn->fd].flags.socket_eof = true;

            commMarkHalfClosed(io.conn->fd);

            fd_note(io.conn->fd, "half-closed");

            /* There is one more close check at the end, to detect aborted
             * (partial) requests. At this point we can't tell if the request
             * is partial.
             */
            /* Continue to process previously read data */
        }
    }

    /* Process next request */
    if (getConcurrentRequestCount() == 0)
        fd_note(io.fd, "Reading next request");

    if (!clientParseRequests()) {
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
        if (getConcurrentRequestCount() == 0 && commIsHalfClosed(io.fd)) {
            debugs(33, 5, HERE << io.conn << ": half-closed connection, no completed request parsed, connection closing.");
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
ConnStateData::handleReadData(char *buf, size_t size)
{
    char *current_buf = in.addressToReadInto();

    if (buf != current_buf)
        memmove(current_buf, buf, size);

    in.notYetUsed += size;

    in.buf[in.notYetUsed] = '\0'; /* Terminate the string */

    // if we are reading a body, stuff data into the body pipe
    if (bodyPipe != NULL)
        return handleRequestBodyData();
    return true;
}

/**
 * called when new request body data has been buffered in in.buf
 * may close the connection if we were closing and piped everything out
 *
 * \retval false called comm_close or setReplyToError (the caller should bail)
 * \retval true  we did not call comm_close or setReplyToError
 */
bool
ConnStateData::handleRequestBodyData()
{
    assert(bodyPipe != NULL);

    size_t putSize = 0;

    if (in.bodyParser) { // chunked encoding
        if (const err_type error = handleChunkedRequestBody(putSize)) {
            abortChunkedRequestBody(error);
            return false;
        }
    } else { // identity encoding
        debugs(33,5, HERE << "handling plain request body for " << clientConnection);
        putSize = bodyPipe->putMoreData(in.buf, in.notYetUsed);
        if (!bodyPipe->mayNeedMoreData()) {
            // BodyPipe will clear us automagically when we produced everything
            bodyPipe = NULL;
        }
    }

    if (putSize > 0)
        connNoteUseOfBuffer(this, putSize);

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
ConnStateData::handleChunkedRequestBody(size_t &putSize)
{
    debugs(33,7, HERE << "chunked from " << clientConnection << ": " << in.notYetUsed);

    try { // the parser will throw on errors

        if (!in.notYetUsed) // nothing to do (MemBuf::init requires this check)
            return ERR_NONE;

        MemBuf raw; // ChunkedCodingParser only works with MemBufs
        // add one because MemBuf will assert if it cannot 0-terminate
        raw.init(in.notYetUsed, in.notYetUsed+1);
        raw.append(in.buf, in.notYetUsed);

        const mb_size_t wasContentSize = raw.contentSize();
        BodyPipeCheckout bpc(*bodyPipe);
        const bool parsed = in.bodyParser->parse(&raw, &bpc.buf);
        bpc.checkIn();
        putSize = wasContentSize - raw.contentSize();

        // dechunk then check: the size limit applies to _dechunked_ content
        if (clientIsRequestBodyTooLargeForPolicy(bodyPipe->producedSize()))
            return ERR_TOO_BIG;

        if (parsed) {
            finishDechunkingRequest(true);
            Must(!bodyPipe);
            return ERR_NONE; // nil bodyPipe implies body end for the caller
        }

        // if chunk parser needs data, then the body pipe must need it too
        Must(!in.bodyParser->needsMoreData() || bodyPipe->mayNeedMoreData());

        // if parser needs more space and we can consume nothing, we will stall
        Must(!in.bodyParser->needsMoreSpace() || bodyPipe->buf().hasContent());
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
    // but if we fail when the server-side works already, the server may send
    // us its response too, causing various assertions. How to prevent that?
#if WE_KNOW_HOW_TO_SEND_ERRORS
    ClientSocketContext::Pointer context = getCurrentContext();
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
                                    in.buf, NULL);
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
ConnStateData::noteMoreBodySpaceAvailable(BodyPipe::Pointer )
{
    if (!handleRequestBodyData())
        return;

    // too late to read more body
    if (!isOpen() || stoppedReceiving())
        return;

    readSomeData();
}

void
ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer )
{
    // request reader may get stuck waiting for space if nobody consumes body
    if (bodyPipe != NULL)
        bodyPipe->enableAutoConsumption();

    stopReceiving("virgin request body consumer aborted"); // closes ASAP
}

/** general lifetime handler for HTTP requests */
void
ConnStateData::requestTimeout(const CommTimeoutCbParams &io)
{
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
    http->al->http.timedout = true;
    if (Comm::IsConnOpen(io.conn))
        io.conn->close();
}

ConnStateData::ConnStateData(const MasterXaction::Pointer &xact) :
        AsyncJob("ConnStateData"),
#if USE_SSL
        sslBumpMode(Ssl::bumpEnd),
        switchedToHttps_(false),
        sslServerBump(NULL),
#endif
        stoppedSending_(NULL),
        stoppedReceiving_(NULL)
{
    pinning.host = NULL;
    pinning.port = -1;
    pinning.pinned = false;
    pinning.auth = false;
    pinning.zeroReply = false;
    pinning.peer = NULL;

    // store the details required for creating more MasterXaction objects as new requests come in
    clientConnection = xact->tcpClient;
    port = cbdataReference(xact->squidPort.get());
    log_addr = xact->tcpClient->remote;
    log_addr.applyMask(Config.Addrs.client_netmask);

    in.buf = (char *)memAllocBuf(CLIENT_REQ_BUF_SZ, &in.allocatedSize);

    if (port->disable_pmtu_discovery != DISABLE_PMTU_OFF &&
            (transparent() || port->disable_pmtu_discovery == DISABLE_PMTU_ALWAYS)) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
        int i = IP_PMTUDISC_DONT;
        if (setsockopt(clientConnection->fd, SOL_IP, IP_MTU_DISCOVER, &i, sizeof(i)) < 0)
            debugs(33, 2, "WARNING: Path MTU discovery disabling failed on " << clientConnection << " : " << xstrerror());
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
        identChecklist.src_addr = xact->tcpClient->remote;
        identChecklist.my_addr = xact->tcpClient->local;
        if (identChecklist.fastCheck() == ACCESS_ALLOWED)
            Ident::Start(xact->tcpClient, clientIdentDone, this);
    }
#endif

    clientdbEstablished(clientConnection->remote, 1);

    flags.readMore = true;
}

/** Handle a new connection on HTTP socket. */
void
httpAccept(const CommAcceptCbParams &params)
{
    MasterXaction::Pointer xact = params.xaction;
    AnyP::PortCfgPointer s = xact->squidPort;

    if (!s.valid()) {
        // it is possible the call or accept() was still queued when the port was reconfigured
        debugs(33, 2, "HTTP accept failure: port reconfigured.");
        return;
    }

    if (params.flag != COMM_OK) {
        // Its possible the call was still queued when the client disconnected
        debugs(33, 2, "httpAccept: " << s->listenConn << ": accept failure: " << xstrerr(params.xerrno));
        return;
    }

    debugs(33, 4, HERE << params.conn << ": accepted");
    fd_note(params.conn->fd, "client http connect");

    if (s->tcp_keepalive.enabled) {
        commSetTcpKeepalive(params.conn->fd, s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);
    }

    ++ incoming_sockets_accepted;

    // Socket is ready, setup the connection manager to start using it
    ConnStateData *connState = new ConnStateData(xact);

    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, connState, ConnStateData::requestTimeout);
    commSetConnTimeout(params.conn, Config.Timeout.request, timeoutCall);

    connState->readSomeData();

#if USE_DELAY_POOLS
    fd_table[params.conn->fd].clientInfo = NULL;

    if (Config.onoff.client_db) {
        /* it was said several times that client write limiter does not work if client_db is disabled */

        ClientDelayPools& pools(Config.ClientDelay.pools);
        ACLFilledChecklist ch(NULL, NULL, NULL);

        // TODO: we check early to limit error response bandwith but we
        // should recheck when we can honor delay_pool_uses_indirect
        // TODO: we should also pass the port details for myportname here.
        ch.src_addr = params.conn->remote;
        ch.my_addr = params.conn->local;

        for (unsigned int pool = 0; pool < pools.size(); ++pool) {

            /* pools require explicit 'allow' to assign a client into them */
            if (pools[pool].access) {
                ch.accessList = pools[pool].access;
                allow_t answer = ch.fastCheck();
                if (answer == ACCESS_ALLOWED) {

                    /*  request client information from db after we did all checks
                        this will save hash lookup if client failed checks */
                    ClientInfo * cli = clientdbGetInfo(params.conn->remote);
                    assert(cli);

                    /* put client info in FDE */
                    fd_table[params.conn->fd].clientInfo = cli;

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
}

#if USE_SSL

/** Create SSL connection structure and update fd_table */
static SSL *
httpsCreate(const Comm::ConnectionPointer &conn, SSL_CTX *sslContext)
{
    SSL *ssl = SSL_new(sslContext);

    if (!ssl) {
        const int ssl_error = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: httpsAccept: Error allocating handle: " << ERR_error_string(ssl_error, NULL)  );
        conn->close();
        return NULL;
    }

    SSL_set_fd(ssl, conn->fd);
    fd_table[conn->fd].ssl = ssl;
    fd_table[conn->fd].read_method = &ssl_read_method;
    fd_table[conn->fd].write_method = &ssl_write_method;

    debugs(33, 5, "httpsCreate: will negotate SSL on " << conn);
    fd_note(conn->fd, "client https start");

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
            Comm::SetSelect(fd, COMM_SELECT_READ, clientNegotiateSSL, conn, 0);
            return;

        case SSL_ERROR_WANT_WRITE:
            Comm::SetSelect(fd, COMM_SELECT_WRITE, clientNegotiateSSL, conn, 0);
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
            debugs(83, DBG_IMPORTANT, "clientNegotiateSSL: Error negotiating SSL connection on FD " << fd << ": Closed by client");
            comm_close(fd);
            return;

        default:
            debugs(83, DBG_IMPORTANT, "clientNegotiateSSL: Error negotiating SSL connection on FD " <<
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

/**
 * If SSL_CTX is given, starts reading the SSL handshake.
 * Otherwise, calls switchToHttps to generate a dynamic SSL_CTX.
 */
static void
httpsEstablish(ConnStateData *connState,  SSL_CTX *sslContext, Ssl::BumpMode bumpMode)
{
    SSL *ssl = NULL;
    assert(connState);
    const Comm::ConnectionPointer &details = connState->clientConnection;

    if (sslContext && !(ssl = httpsCreate(details, sslContext)))
        return;

    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5, TimeoutDialer,
                                     connState, ConnStateData::requestTimeout);
    commSetConnTimeout(details, Config.Timeout.request, timeoutCall);

    if (ssl)
        Comm::SetSelect(details->fd, COMM_SELECT_READ, clientNegotiateSSL, connState, 0);
    else {
        char buf[MAX_IPSTRLEN];
        assert(bumpMode != Ssl::bumpNone && bumpMode != Ssl::bumpEnd);
        HttpRequest::Pointer fakeRequest(new HttpRequest);
        fakeRequest->SetHost(details->local.toStr(buf, sizeof(buf)));
        fakeRequest->port = details->local.port();
        fakeRequest->clientConnectionManager = connState;
        fakeRequest->client_addr = connState->clientConnection->remote;
#if FOLLOW_X_FORWARDED_FOR
        fakeRequest->indirect_client_addr = connState->clientConnection->remote;
#endif
        fakeRequest->my_addr = connState->clientConnection->local;
        fakeRequest->flags.interceptTproxy = ((connState->clientConnection->flags & COMM_TRANSPARENT) != 0 ) ;
        fakeRequest->flags.intercepted = ((connState->clientConnection->flags & COMM_INTERCEPTION) != 0);
        fakeRequest->myportname = connState->port->name;
        if (fakeRequest->flags.interceptTproxy) {
            if (Config.accessList.spoof_client_ip) {
                ACLFilledChecklist checklist(Config.accessList.spoof_client_ip, fakeRequest.getRaw(), NULL);
                fakeRequest->flags.spoofClientIp = (checklist.fastCheck() == ACCESS_ALLOWED);
            } else
                fakeRequest->flags.spoofClientIp = true;
        } else
            fakeRequest->flags.spoofClientIp = false;
        debugs(33, 4, HERE << details << " try to generate a Dynamic SSL CTX");
        connState->switchToHttps(fakeRequest.getRaw(), bumpMode);
    }
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
        debugs(33, 2, HERE << "sslBump needed for " << connState->clientConnection);
        connState->sslBumpMode = static_cast<Ssl::BumpMode>(answer.kind);
        httpsEstablish(connState, NULL, (Ssl::BumpMode)answer.kind);
    } else {
        debugs(33, 2, HERE << "sslBump not needed for " << connState->clientConnection);
        connState->sslBumpMode = Ssl::bumpNone;

        // fake a CONNECT request to force connState to tunnel
        static char ip[MAX_IPSTRLEN];
        static char reqStr[MAX_IPSTRLEN + 80];
        connState->clientConnection->local.toUrl(ip, sizeof(ip));
        snprintf(reqStr, sizeof(reqStr), "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ip, ip);
        bool ret = connState->handleReadData(reqStr, strlen(reqStr));
        if (ret)
            ret = connState->clientParseRequests();

        if (!ret) {
            debugs(33, 2, HERE << "Failed to start fake CONNECT request for ssl bumped connection: " << connState->clientConnection);
            connState->clientConnection->close();
        }
    }
}

/** handle a new HTTPS connection */
static void
httpsAccept(const CommAcceptCbParams &params)
{
    MasterXaction::Pointer xact = params.xaction;
    const AnyP::PortCfgPointer s = xact->squidPort;

    if (!s.valid()) {
        // it is possible the call or accept() was still queued when the port was reconfigured
        debugs(33, 2, "HTTPS accept failure: port reconfigured.");
        return;
    }

    if (params.flag != COMM_OK) {
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
    ConnStateData *connState = new ConnStateData(xact);

    if (s->flags.tunnelSslBumping) {
        debugs(33, 5, "httpsAccept: accept transparent connection: " << params.conn);

        if (!Config.accessList.ssl_bump) {
            httpsSslBumpAccessCheckDone(ACCESS_DENIED, connState);
            return;
        }

        // Create a fake HTTP request for ssl_bump ACL check,
        // using tproxy/intercept provided destination IP and port.
        HttpRequest *request = new HttpRequest();
        static char ip[MAX_IPSTRLEN];
        assert(params.conn->flags & (COMM_TRANSPARENT | COMM_INTERCEPTION));
        request->SetHost(params.conn->local.toStr(ip, sizeof(ip)));
        request->port = params.conn->local.port();
        request->myportname = s->name;

        ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(Config.accessList.ssl_bump, request, NULL);
        acl_checklist->src_addr = params.conn->remote;
        acl_checklist->my_addr = s->s;
        acl_checklist->nonBlockingCheck(httpsSslBumpAccessCheckDone, connState);
        return;
    } else {
        SSL_CTX *sslContext = s->staticSslContext.get();
        httpsEstablish(connState, sslContext, Ssl::bumpNone);
    }
}

void
ConnStateData::sslCrtdHandleReplyWrapper(void *data, const HelperReply &reply)
{
    ConnStateData * state_data = (ConnStateData *)(data);
    state_data->sslCrtdHandleReply(reply);
}

void
ConnStateData::sslCrtdHandleReply(const HelperReply &reply)
{
    if (reply.result == HelperReply::BrokenHelper) {
        debugs(33, 5, HERE << "Certificate for " << sslConnectHostOrIp << " cannot be generated. ssl_crtd response: " << reply);
    } else if (!reply.other().hasContent()) {
        debugs(1, DBG_IMPORTANT, HERE << "\"ssl_crtd\" helper returned <NULL> reply.");
    } else {
        Ssl::CrtdMessage reply_message(Ssl::CrtdMessage::REPLY);
        if (reply_message.parse(reply.other().content(), reply.other().contentSize()) != Ssl::CrtdMessage::OK) {
            debugs(33, 5, HERE << "Reply from ssl_crtd for " << sslConnectHostOrIp << " is incorrect");
        } else {
            if (reply.result != HelperReply::Okay) {
                debugs(33, 5, HERE << "Certificate for " << sslConnectHostOrIp << " cannot be generated. ssl_crtd response: " << reply_message.getBody());
            } else {
                debugs(33, 5, HERE << "Certificate for " << sslConnectHostOrIp << " was successfully recieved from ssl_crtd");
                SSL_CTX *ctx = Ssl::generateSslContextUsingPkeyAndCertFromMemory(reply_message.getBody().c_str(), *port);
                getSslContextDone(ctx, true);
                return;
            }
        }
    }
    getSslContextDone(NULL);
}

void ConnStateData::buildSslCertGenerationParams(Ssl::CertificateProperties &certProperties)
{
    certProperties.commonName =  sslCommonName.defined() ? sslCommonName.termedBuf() : sslConnectHostOrIp.termedBuf();

    // fake certificate adaptation requires bump-server-first mode
    if (!sslServerBump) {
        assert(port->signingCert.get());
        certProperties.signWithX509.resetAndLock(port->signingCert.get());
        if (port->signPkey.get())
            certProperties.signWithPkey.resetAndLock(port->signPkey.get());
        certProperties.signAlgorithm = Ssl::algSignTrusted;
        return;
    }

    // In case of an error while connecting to the secure server, use a fake
    // trusted certificate, with no mimicked fields and no adaptation
    // algorithms. There is nothing we can mimic so we want to minimize the
    // number of warnings the user will have to see to get to the error page.
    assert(sslServerBump->entry);
    if (sslServerBump->entry->isEmpty()) {
        if (X509 *mimicCert = sslServerBump->serverCert.get())
            certProperties.mimicCert.resetAndLock(mimicCert);

        ACLFilledChecklist checklist(NULL, sslServerBump->request.getRaw(),
                                     clientConnection != NULL ? clientConnection->rfc931 : dash_str);
        checklist.sslErrors = cbdataReference(sslServerBump->sslErrors);

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
    } else {// if (!sslServerBump->entry->isEmpty())
        // Use trusted certificate for a Squid-generated error
        // or the user would have to add a security exception
        // just to see the error page. We will close the connection
        // so that the trust is not extended to non-Squid content.
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
}

void
ConnStateData::getSslContextStart()
{
    assert(areAllContextsForThisConnection());
    freeAllContexts();
    /* careful: freeAllContexts() above frees request, host, etc. */

    if (port->generateHostCertificates) {
        Ssl::CertificateProperties certProperties;
        buildSslCertGenerationParams(certProperties);
        sslBumpCertKey = certProperties.dbKey().c_str();
        assert(sslBumpCertKey.defined() && sslBumpCertKey[0] != '\0');

        debugs(33, 5, HERE << "Finding SSL certificate for " << sslBumpCertKey << " in cache");
        Ssl::LocalContextStorage *ssl_ctx_cache = Ssl::TheGlobalContextStorage.getLocalStorage(port->s);
        SSL_CTX * dynCtx = NULL;
        Ssl::SSL_CTX_Pointer *cachedCtx = ssl_ctx_cache ? ssl_ctx_cache->get(sslBumpCertKey.termedBuf()) : NULL;
        if (cachedCtx && (dynCtx = cachedCtx->get())) {
            debugs(33, 5, HERE << "SSL certificate for " << sslBumpCertKey << " have found in cache");
            if (Ssl::verifySslCertificate(dynCtx, certProperties)) {
                debugs(33, 5, HERE << "Cached SSL certificate for " << sslBumpCertKey << " is valid");
                getSslContextDone(dynCtx);
                return;
            } else {
                debugs(33, 5, HERE << "Cached SSL certificate for " << sslBumpCertKey << " is out of date. Delete this certificate from cache");
                if (ssl_ctx_cache)
                    ssl_ctx_cache->del(sslBumpCertKey.termedBuf());
            }
        } else {
            debugs(33, 5, HERE << "SSL certificate for " << sslBumpCertKey << " haven't found in cache");
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
        dynCtx = Ssl::generateSslContext(certProperties, *port);
        getSslContextDone(dynCtx, true);
        return;
    }
    getSslContextDone(NULL);
}

void
ConnStateData::getSslContextDone(SSL_CTX * sslContext, bool isNew)
{
    // Try to add generated ssl context to storage.
    if (port->generateHostCertificates && isNew) {

        if (signAlgorithm == Ssl::algSignTrusted) {
            // Add signing certificate to the certificates chain
            X509 *cert = port->signingCert.get();
            if (SSL_CTX_add_extra_chain_cert(sslContext, cert)) {
                // increase the certificate lock
                CRYPTO_add(&(cert->references),1,CRYPTO_LOCK_X509);
            } else {
                const int ssl_error = ERR_get_error();
                debugs(33, DBG_IMPORTANT, "WARNING: can not add signing certificate to SSL context chain: " << ERR_error_string(ssl_error, NULL));
            }
            Ssl::addChainToSslContext(sslContext, port->certsToChain.get());
        }
        //else it is self-signed or untrusted do not attrach any certificate

        Ssl::LocalContextStorage *ssl_ctx_cache = Ssl::TheGlobalContextStorage.getLocalStorage(port->s);
        assert(sslBumpCertKey.defined() && sslBumpCertKey[0] != '\0');
        if (sslContext) {
            if (!ssl_ctx_cache || !ssl_ctx_cache->add(sslBumpCertKey.termedBuf(), new Ssl::SSL_CTX_Pointer(sslContext))) {
                // If it is not in storage delete after using. Else storage deleted it.
                fd_table[clientConnection->fd].dynamicSslContext = sslContext;
            }
        } else {
            debugs(33, 2, HERE << "Failed to generate SSL cert for " << sslConnectHostOrIp);
        }
    }

    // If generated ssl context = NULL, try to use static ssl context.
    if (!sslContext) {
        if (!port->staticSslContext) {
            debugs(83, DBG_IMPORTANT, "Closing SSL " << clientConnection->remote << " as lacking SSL context");
            clientConnection->close();
            return;
        } else {
            debugs(33, 5, HERE << "Using static ssl context.");
            sslContext = port->staticSslContext.get();
        }
    }

    if (!httpsCreate(clientConnection, sslContext))
        return;

    // bumped intercepted conns should already have Config.Timeout.request set
    // but forwarded connections may only have Config.Timeout.lifetime. [Re]set
    // to make sure the connection does not get stuck on non-SSL clients.
    typedef CommCbMemFunT<ConnStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(33, 5, TimeoutDialer,
                                     this, ConnStateData::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.request, timeoutCall);

    // Disable the client read handler until CachePeer selection is complete
    Comm::SetSelect(clientConnection->fd, COMM_SELECT_READ, NULL, NULL, 0);
    Comm::SetSelect(clientConnection->fd, COMM_SELECT_READ, clientNegotiateSSL, this, 0);
    switchedToHttps_ = true;
}

void
ConnStateData::switchToHttps(HttpRequest *request, Ssl::BumpMode bumpServerMode)
{
    assert(!switchedToHttps_);

    sslConnectHostOrIp = request->GetHost();
    sslCommonName = request->GetHost();

    // We are going to read new request
    flags.readMore = true;
    debugs(33, 5, HERE << "converting " << clientConnection << " to SSL");

    // If sslServerBump is set, then we have decided to deny CONNECT
    // and now want to switch to SSL to send the error to the client
    // without even peeking at the origin server certificate.
    if (bumpServerMode == Ssl::bumpServerFirst && !sslServerBump) {
        request->flags.sslPeek = true;
        sslServerBump = new Ssl::ServerBump(request);

        // will call httpsPeeked() with certificate and connection, eventually
        FwdState::fwdStart(clientConnection, sslServerBump->entry, sslServerBump->request.getRaw());
        return;
    }

    // otherwise, use sslConnectHostOrIp
    getSslContextStart();
}

void
ConnStateData::httpsPeeked(Comm::ConnectionPointer serverConnection)
{
    Must(sslServerBump != NULL);

    if (Comm::IsConnOpen(serverConnection)) {
        SSL *ssl = fd_table[serverConnection->fd].ssl;
        assert(ssl);
        Ssl::X509_Pointer serverCert(SSL_get_peer_certificate(ssl));
        assert(serverCert.get() != NULL);
        sslCommonName = Ssl::CommonHostName(serverCert.get());
        debugs(33, 5, HERE << "HTTPS server CN: " << sslCommonName <<
               " bumped: " << *serverConnection);

        pinConnection(serverConnection, NULL, NULL, false);

        debugs(33, 5, HERE << "bumped HTTPS server: " << sslConnectHostOrIp);
    } else {
        debugs(33, 5, HERE << "Error while bumping: " << sslConnectHostOrIp);
        Ip::Address intendedDest;
        intendedDest = sslConnectHostOrIp.termedBuf();
        const bool isConnectRequest = !port->flags.isIntercepted();

        // Squid serves its own error page and closes, so we want
        // a CN that causes no additional browser errors. Possible
        // only when bumping CONNECT with a user-typed address.
        if (intendedDest.isAnyAddr() || isConnectRequest)
            sslCommonName = sslConnectHostOrIp;
        else if (sslServerBump->serverCert.get())
            sslCommonName = Ssl::CommonHostName(sslServerBump->serverCert.get());

        //  copy error detail from bump-server-first request to CONNECT request
        if (currentobject != NULL && currentobject->http != NULL && currentobject->http->request)
            currentobject->http->request->detailError(sslServerBump->request->errType, sslServerBump->request->errDetail);
    }

    getSslContextStart();
}

#endif /* USE_SSL */

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
    AnyP::PortCfg *s = NULL;

    for (s = Config.Sockaddr.http; s; s = s->next) {
        if (MAXTCPLISTENPORTS == NHttpSockets) {
            debugs(1, DBG_IMPORTANT, "WARNING: You have too many 'http_port' lines.");
            debugs(1, DBG_IMPORTANT, "         The limit is " << MAXTCPLISTENPORTS << " HTTP ports.");
            continue;
        }

#if USE_SSL
        if (s->flags.tunnelSslBumping && !Config.accessList.ssl_bump) {
            debugs(33, DBG_IMPORTANT, "WARNING: No ssl_bump configured. Disabling ssl-bump on " << s->protocol << "_port " << s->s);
            s->flags.tunnelSslBumping = false;
        }

        if (s->flags.tunnelSslBumping &&
                !s->staticSslContext &&
                !s->generateHostCertificates) {
            debugs(1, DBG_IMPORTANT, "Will not bump SSL at http_port " << s->s << " due to SSL initialization failure.");
            s->flags.tunnelSslBumping = false;
        }
        if (s->flags.tunnelSslBumping) {
            // Create ssl_ctx cache for this port.
            Ssl::TheGlobalContextStorage.addLocalStorage(s->s, s->dynamicCertMemCacheSize == std::numeric_limits<size_t>::max() ? 4194304 : s->dynamicCertMemCacheSize);
        }
#endif

        // Fill out a Comm::Connection which IPC will open as a listener for us
        //  then pass back when active so we can start a TcpAcceptor subscription.
        s->listenConn = new Comm::Connection;
        s->listenConn->local = s->s;
        s->listenConn->flags = COMM_NONBLOCKING | (s->flags.tproxyIntercept ? COMM_TRANSPARENT : 0) | (s->flags.natIntercept ? COMM_INTERCEPTION : 0);

        // setup the subscriptions such that new connections accepted by listenConn are handled by HTTP
        typedef CommCbFunPtrCallT<CommAcceptCbPtrFun> AcceptCall;
        RefCount<AcceptCall> subCall = commCbCall(5, 5, "httpAccept", CommAcceptCbPtrFun(httpAccept, s));
        Subscription::Pointer sub = new CallSubscription<AcceptCall>(subCall);

        AsyncCall::Pointer listenCall = asyncCall(33,2, "clientListenerConnectionOpened",
                                        ListeningStartedDialer(&clientListenerConnectionOpened, s, Ipc::fdnHttpSocket, sub));
        Ipc::StartListening(SOCK_STREAM, IPPROTO_TCP, s->listenConn, Ipc::fdnHttpSocket, listenCall);

        HttpSockets[NHttpSockets] = -1; // set in clientListenerConnectionOpened
        ++NHttpSockets;
    }
}

#if USE_SSL
static void
clientHttpsConnectionsOpen(void)
{
    AnyP::PortCfg *s;

    for (s = Config.Sockaddr.https; s; s = s->next) {
        if (MAXTCPLISTENPORTS == NHttpSockets) {
            debugs(1, DBG_IMPORTANT, "Ignoring 'https_port' lines exceeding the limit.");
            debugs(1, DBG_IMPORTANT, "The limit is " << MAXTCPLISTENPORTS << " HTTPS ports.");
            continue;
        }

        if (!s->staticSslContext) {
            debugs(1, DBG_IMPORTANT, "Ignoring https_port " << s->s <<
                   " due to SSL initialization failure.");
            continue;
        }

        // TODO: merge with similar code in clientHttpConnectionsOpen()
        if (s->flags.tunnelSslBumping && !Config.accessList.ssl_bump) {
            debugs(33, DBG_IMPORTANT, "WARNING: No ssl_bump configured. Disabling ssl-bump on " << s->protocol << "_port " << s->s);
            s->flags.tunnelSslBumping = false;
        }

        if (s->flags.tunnelSslBumping && !s->staticSslContext && !s->generateHostCertificates) {
            debugs(1, DBG_IMPORTANT, "Will not bump SSL at http_port " << s->s << " due to SSL initialization failure.");
            s->flags.tunnelSslBumping = false;
        }

        if (s->flags.tunnelSslBumping) {
            // Create ssl_ctx cache for this port.
            Ssl::TheGlobalContextStorage.addLocalStorage(s->s, s->dynamicCertMemCacheSize == std::numeric_limits<size_t>::max() ? 4194304 : s->dynamicCertMemCacheSize);
        }

        // Fill out a Comm::Connection which IPC will open as a listener for us
        s->listenConn = new Comm::Connection;
        s->listenConn->local = s->s;
        s->listenConn->flags = COMM_NONBLOCKING | (s->flags.tproxyIntercept ? COMM_TRANSPARENT : 0) |
                               (s->flags.natIntercept ? COMM_INTERCEPTION : 0);

        // setup the subscriptions such that new connections accepted by listenConn are handled by HTTPS
        typedef CommCbFunPtrCallT<CommAcceptCbPtrFun> AcceptCall;
        RefCount<AcceptCall> subCall = commCbCall(5, 5, "httpsAccept", CommAcceptCbPtrFun(httpsAccept, s));
        Subscription::Pointer sub = new CallSubscription<AcceptCall>(subCall);

        AsyncCall::Pointer listenCall = asyncCall(33, 2, "clientListenerConnectionOpened",
                                        ListeningStartedDialer(&clientListenerConnectionOpened,
                                                               s, Ipc::fdnHttpsSocket, sub));
        Ipc::StartListening(SOCK_STREAM, IPPROTO_TCP, s->listenConn, Ipc::fdnHttpsSocket, listenCall);
        HttpSockets[NHttpSockets] = -1;
        ++NHttpSockets;
    }
}
#endif

/// process clientHttpConnectionsOpen result
static void
clientListenerConnectionOpened(AnyP::PortCfg *s, const Ipc::FdNoteId portTypeNote, const Subscription::Pointer &sub)
{
    if (!OpenedHttpSocket(s->listenConn, portTypeNote))
        return;

    Must(s);
    Must(Comm::IsConnOpen(s->listenConn));

    // TCP: setup a job to handle accept() with subscribed handler
    AsyncJob::Start(new Comm::TcpAcceptor(s->listenConn, FdNote(portTypeNote), sub));

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
#if USE_SSL
    clientHttpsConnectionsOpen();
#endif

    if (NHttpSockets < 1)
        fatal("No HTTP or HTTPS ports configured");
}

void
clientHttpConnectionsClose(void)
{
    for (AnyP::PortCfg *s = Config.Sockaddr.http; s; s = s->next) {
        if (s->listenConn != NULL) {
            debugs(1, DBG_IMPORTANT, "Closing HTTP port " << s->listenConn->local);
            s->listenConn->close();
            s->listenConn = NULL;
        }
    }

#if USE_SSL
    for (AnyP::PortCfg *s = Config.Sockaddr.https; s; s = s->next) {
        if (s->listenConn != NULL) {
            debugs(1, DBG_IMPORTANT, "Closing HTTPS port " << s->listenConn->local);
            s->listenConn->close();
            s->listenConn = NULL;
        }
    }
#endif

    // TODO see if we can drop HttpSockets array entirely */
    for (int i = 0; i < NHttpSockets; ++i) {
        HttpSockets[i] = -1;
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
            debugs(33, DBG_IMPORTANT, "varyEvaluateMatch: Oops. Not a Vary object on second attempt, '" <<
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
            debugs(33, DBG_IMPORTANT, "varyEvaluateMatch: Oops. Not a Vary match on second attempt, '" <<
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
            cbdataReferenceValid(conn) && conn != NULL && conn->clientConnection != NULL ? conn->clientConnection->rfc931 : dash_str);

    /*
     * hack for ident ACL. It needs to get full addresses, and a place to store
     * the ident result on persistent connections...
     */
    /* connection oriented auth also needs these two lines for it's operation. */
    return ch;
}

CBDATA_CLASS_INIT(ConnStateData);

bool
ConnStateData::transparent() const
{
    return clientConnection != NULL && (clientConnection->flags & (COMM_TRANSPARENT|COMM_INTERCEPTION));
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
        comm_read_cancel(clientConnection->fd, reader);
        reader = NULL;
    }
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
    const int64_t haveAvailable = static_cast<int64_t>(in.notYetUsed);

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
    assert(!in.bodyParser);
    in.bodyParser = new ChunkedCodingParser;
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
            ClientSocketContext::Pointer context = getCurrentContext();
            if (context != NULL && context->http && context->http->request)
                context->http->request->setContentLength(myPipe->bodySize());
        }
    }

    delete in.bodyParser;
    in.bodyParser = NULL;
}

char *
ConnStateData::In::addressToReadInto() const
{
    return buf + notYetUsed;
}

ConnStateData::In::In() : bodyParser(NULL),
        buf (NULL), notYetUsed (0), allocatedSize (0)
{}

ConnStateData::In::~In()
{
    if (allocatedSize)
        memFreeBuf(allocatedSize, buf);
    delete bodyParser; // TODO: pool
}

void
ConnStateData::sendControlMsg(HttpControlMsg msg)
{
    if (!isOpen()) {
        debugs(33, 3, HERE << "ignoring 1xx due to earlier closure");
        return;
    }

    ClientSocketContext::Pointer context = getCurrentContext();
    if (context != NULL) {
        context->writeControlMsg(msg); // will call msg.cbSuccess
        return;
    }

    debugs(33, 3, HERE << " closing due to missing context for 1xx");
    clientConnection->close();
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
    unpinConnection();
    if (sawZeroReply && clientConnection != NULL) {
        debugs(33, 3, "Closing client connection on pinned zero reply.");
        clientConnection->close();
    }
}

void
ConnStateData::pinConnection(const Comm::ConnectionPointer &pinServer, HttpRequest *request, CachePeer *aPeer, bool auth)
{
    char desc[FD_DESC_SZ];

    if (Comm::IsConnOpen(pinning.serverConnection)) {
        if (pinning.serverConnection->fd == pinServer->fd) {
            startPinnedConnectionMonitoring();
            return;
        }
    }

    unpinConnection(); // closes pinned connection, if any, and resets fields

    pinning.serverConnection = pinServer;

    debugs(33, 3, HERE << pinning.serverConnection);

    // when pinning an SSL bumped connection, the request may be NULL
    const char *pinnedHost = "[unknown]";
    if (request) {
        pinning.host = xstrdup(request->GetHost());
        pinning.port = request->port;
        pinnedHost = pinning.host;
    } else {
        pinning.port = pinServer->remote.port();
    }
    pinning.pinned = true;
    if (aPeer)
        pinning.peer = cbdataReference(aPeer);
    pinning.auth = auth;
    char stmp[MAX_IPSTRLEN];
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

    startPinnedConnectionMonitoring();
}

/// Assign a read handler to an idle pinned connection so that we can detect connection closures.
void
ConnStateData::startPinnedConnectionMonitoring()
{
    if (pinning.readHandler != NULL)
        return; // already monitoring

    typedef CommCbMemFunT<ConnStateData, CommIoCbParams> Dialer;
    pinning.readHandler = JobCallback(33, 3,
                                      Dialer, this, ConnStateData::clientPinnedConnectionRead);
    static char unusedBuf[8];
    comm_read(pinning.serverConnection, unusedBuf, sizeof(unusedBuf), pinning.readHandler);
}

void
ConnStateData::stopPinnedConnectionMonitoring()
{
    if (pinning.readHandler != NULL) {
        comm_read_cancel(pinning.serverConnection->fd, pinning.readHandler);
        pinning.readHandler = NULL;
    }
}

/// Our read handler called by Comm when the server either closes an idle pinned connection or
/// perhaps unexpectedly sends something on that idle (from Squid p.o.v.) connection.
void
ConnStateData::clientPinnedConnectionRead(const CommIoCbParams &io)
{
    pinning.readHandler = NULL; // Comm unregisters handlers before calling

    if (io.flag == COMM_ERR_CLOSING)
        return; // close handler will clean up

    // We could use getConcurrentRequestCount(), but this may be faster.
    const bool clientIsIdle = !getCurrentContext();

    debugs(33, 3, "idle pinned " << pinning.serverConnection << " read " <<
           io.size << (clientIsIdle ? " with idle client" : ""));

    assert(pinning.serverConnection == io.conn);
    pinning.serverConnection->close();

    // If we are still sending data to the client, do not close now. When we are done sending,
    // ClientSocketContext::keepaliveNextRequest() checks pinning.serverConnection and will close.
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
    else if (pinning.auth && pinning.host && request && strcasecmp(pinning.host, request->GetHost()) != 0)
        valid = false;
    else if (request && pinning.port != request->port)
        valid = false;
    else if (pinning.peer && !cbdataReferenceValid(pinning.peer))
        valid = false;
    else if (aPeer != pinning.peer)
        valid = false;

    if (!valid) {
        /* The pinning info is not safe, remove any pinning info */
        unpinConnection();
    }

    return pinning.serverConnection;
}

void
ConnStateData::unpinConnection()
{
    debugs(33, 3, HERE << pinning.serverConnection);

    if (pinning.peer)
        cbdataReferenceDone(pinning.peer);

    if (Comm::IsConnOpen(pinning.serverConnection)) {
        if (pinning.closeHandler != NULL) {
            comm_remove_close_handler(pinning.serverConnection->fd, pinning.closeHandler);
            pinning.closeHandler = NULL;
        }
        /// also close the server side socket, we should not use it for any future requests...
        // TODO: do not close if called from our close handler?
        pinning.serverConnection->close();
    }

    safe_free(pinning.host);

    pinning.zeroReply = false;

    /* NOTE: pinning.pinned should be kept. This combined with fd == -1 at the end of a request indicates that the host
     * connection has gone away */
}
