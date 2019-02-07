/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 26    Secure Sockets Layer Proxy */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/CbcPointer.h"
#include "CachePeer.h"
#include "cbdata.h"
#include "client_side.h"
#include "client_side_request.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "FwdState.h"
#include "globals.h"
#include "http.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ip/QosConfig.h"
#include "LogTags.h"
#include "MemBuf.h"
#include "neighbors.h"
#include "PeerSelectState.h"
#include "sbuf/SBuf.h"
#include "security/BlindPeerConnector.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#if USE_OPENSSL
#include "ssl/bio.h"
#include "ssl/ServerBump.h"
#endif
#include "tools.h"
#if USE_DELAY_POOLS
#include "DelayId.h"
#endif

#include <climits>
#include <cerrno>

/**
 * TunnelStateData is the state engine performing the tasks for
 * setup of a TCP tunnel from an existing open client FD to a server
 * then shuffling binary data between the resulting FD pair.
 */
/*
 * TODO 1: implement a read/write API on ConnStateData to send/receive blocks
 * of pre-formatted data. Then we can use that as the client side of the tunnel
 * instead of re-implementing it here and occasionally getting the ConnStateData
 * read/write state wrong.
 *
 * TODO 2: then convert this into a AsyncJob, possibly a child of 'Server'
 */
class TunnelStateData
{
    CBDATA_CLASS(TunnelStateData);

public:
    TunnelStateData(ClientHttpRequest *);
    ~TunnelStateData();
    TunnelStateData(const TunnelStateData &); // do not implement
    TunnelStateData &operator =(const TunnelStateData &); // do not implement

    class Connection;
    static void ReadClient(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data);
    static void ReadServer(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data);
    static void WriteClientDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data);
    static void WriteServerDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data);

    /// Starts reading peer response to our CONNECT request.
    void readConnectResponse();

    /// Called when we may be done handling a CONNECT exchange with the peer.
    void connectExchangeCheckpoint();

    bool noConnections() const;
    char *url;
    CbcPointer<ClientHttpRequest> http;
    HttpRequest::Pointer request;
    AccessLogEntryPointer al;
    Comm::ConnectionList serverDestinations;

    const char * getHost() const {
        return (server.conn != NULL && server.conn->getPeer() ? server.conn->getPeer()->host : request->url.host());
    };

    /// Whether we are writing a CONNECT request to a peer.
    bool waitingForConnectRequest() const { return connectReqWriting; }
    /// Whether we are reading a CONNECT response from a peer.
    bool waitingForConnectResponse() const { return connectRespBuf; }
    /// Whether we are waiting for the CONNECT request/response exchange with the peer.
    bool waitingForConnectExchange() const { return waitingForConnectRequest() || waitingForConnectResponse(); }

    /// Whether the client sent a CONNECT request to us.
    bool clientExpectsConnectResponse() const {
        // If we are forcing a tunnel after receiving a client CONNECT, then we
        // have already responded to that CONNECT before tunnel.cc started.
        if (request && request->flags.forceTunnel)
            return false;
#if USE_OPENSSL
        // We are bumping and we had already send "OK CONNECTED"
        if (http.valid() && http->getConn() && http->getConn()->serverBump() && http->getConn()->serverBump()->step > Ssl::bumpStep1)
            return false;
#endif
        return !(request != NULL &&
                 (request->flags.interceptTproxy || request->flags.intercepted));
    }

    /// Sends "502 Bad Gateway" error response to the client,
    /// if it is waiting for Squid CONNECT response, closing connections.
    void informUserOfPeerError(const char *errMsg, size_t);

    /// starts connecting to the next hop, either for the first time or while
    /// recovering from the previous connect failure
    void startConnecting();

    class Connection
    {

    public:
        Connection() : len (0), buf ((char *)xmalloc(SQUID_TCP_SO_RCVBUF)), size_ptr(NULL), delayedLoops(0),
            readPending(NULL), readPendingFunc(NULL) {}

        ~Connection();

        int bytesWanted(int lower=0, int upper = INT_MAX) const;
        void bytesIn(int const &);
#if USE_DELAY_POOLS

        void setDelayId(DelayId const &);
#endif

        void error(int const xerrno);
        int debugLevelForError(int const xerrno) const;
        void closeIfOpen();
        void dataSent (size_t amount);
        /// writes 'b' buffer, setting the 'writer' member to 'callback'.
        void write(const char *b, int size, AsyncCall::Pointer &callback, FREE * free_func);
        int len;
        char *buf;
        AsyncCall::Pointer writer; ///< pending Comm::Write callback
        uint64_t *size_ptr;      /* pointer to size in an ConnStateData for logging */

        Comm::ConnectionPointer conn;    ///< The currently connected connection.
        uint8_t delayedLoops; ///< how many times a read on this connection has been postponed.

        // XXX: make these an AsyncCall when event API can handle them
        TunnelStateData *readPending;
        EVH *readPendingFunc;
    private:
#if USE_DELAY_POOLS

        DelayId delayId;
#endif

    };

    Connection client, server;
    int *status_ptr;        ///< pointer for logging HTTP status
    LogTags *logTag_ptr;    ///< pointer for logging Squid processing code
    MemBuf *connectRespBuf; ///< accumulates peer CONNECT response when we need it
    bool connectReqWriting; ///< whether we are writing a CONNECT request to a peer
    SBuf preReadClientData;
    SBuf preReadServerData;
    time_t startTime; ///< object creation time, before any peer selection/connection attempts

    void copyRead(Connection &from, IOCB *completion);

    /// continue to set up connection to a peer, going async for SSL peers
    void connectToPeer();

private:
    /// Gives Security::PeerConnector access to Answer in the TunnelStateData callback dialer.
    class MyAnswerDialer: public CallDialer, public Security::PeerConnector::CbDialer
    {
    public:
        typedef void (TunnelStateData::*Method)(Security::EncryptorAnswer &);

        MyAnswerDialer(Method method, TunnelStateData *tunnel):
            method_(method), tunnel_(tunnel), answer_() {}

        /* CallDialer API */
        virtual bool canDial(AsyncCall &call) { return tunnel_.valid(); }
        void dial(AsyncCall &call) { ((&(*tunnel_))->*method_)(answer_); }
        virtual void print(std::ostream &os) const {
            os << '(' << tunnel_.get() << ", " << answer_ << ')';
        }

        /* Security::PeerConnector::CbDialer API */
        virtual Security::EncryptorAnswer &answer() { return answer_; }

    private:
        Method method_;
        CbcPointer<TunnelStateData> tunnel_;
        Security::EncryptorAnswer answer_;
    };

    /// callback handler after connection setup (including any encryption)
    void connectedToPeer(Security::EncryptorAnswer &answer);

public:
    bool keepGoingAfterRead(size_t len, Comm::Flag errcode, int xerrno, Connection &from, Connection &to);
    void copy(size_t len, Connection &from, Connection &to, IOCB *);
    void handleConnectResponse(const size_t chunkSize);
    void readServer(char *buf, size_t len, Comm::Flag errcode, int xerrno);
    void readClient(char *buf, size_t len, Comm::Flag errcode, int xerrno);
    void writeClientDone(char *buf, size_t len, Comm::Flag flag, int xerrno);
    void writeServerDone(char *buf, size_t len, Comm::Flag flag, int xerrno);

    static void ReadConnectResponseDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data);
    void readConnectResponseDone(char *buf, size_t len, Comm::Flag errcode, int xerrno);
    void copyClientBytes();
    void copyServerBytes();
};

static const char *const conn_established = "HTTP/1.1 200 Connection established\r\n\r\n";

static CNCB tunnelConnectDone;
static ERCB tunnelErrorComplete;
static CLCB tunnelServerClosed;
static CLCB tunnelClientClosed;
static CTCB tunnelTimeout;
static PSC tunnelPeerSelectComplete;
static EVH tunnelDelayedClientRead;
static EVH tunnelDelayedServerRead;
static void tunnelConnected(const Comm::ConnectionPointer &server, void *);
static void tunnelRelayConnectRequest(const Comm::ConnectionPointer &server, void *);

static void
tunnelServerClosed(const CommCloseCbParams &params)
{
    TunnelStateData *tunnelState = (TunnelStateData *)params.data;
    debugs(26, 3, HERE << tunnelState->server.conn);
    tunnelState->server.conn = NULL;
    tunnelState->server.writer = NULL;

    if (tunnelState->request != NULL)
        tunnelState->request->hier.stopPeerClock(false);

    if (tunnelState->noConnections()) {
        // ConnStateData pipeline should contain the CONNECT we are performing
        // but it may be invalid already (bug 4392)
        if (tunnelState->http.valid() && tunnelState->http->getConn()) {
            auto ctx = tunnelState->http->getConn()->pipeline.front();
            if (ctx != nullptr)
                ctx->finished();
        }
        delete tunnelState;
        return;
    }

    if (!tunnelState->client.writer) {
        tunnelState->client.conn->close();
        return;
    }
}

static void
tunnelClientClosed(const CommCloseCbParams &params)
{
    TunnelStateData *tunnelState = (TunnelStateData *)params.data;
    debugs(26, 3, HERE << tunnelState->client.conn);
    tunnelState->client.conn = NULL;
    tunnelState->client.writer = NULL;

    if (tunnelState->noConnections()) {
        // ConnStateData pipeline should contain the CONNECT we are performing
        // but it may be invalid already (bug 4392)
        if (tunnelState->http.valid() && tunnelState->http->getConn()) {
            auto ctx = tunnelState->http->getConn()->pipeline.front();
            if (ctx != nullptr)
                ctx->finished();
        }
        delete tunnelState;
        return;
    }

    if (!tunnelState->server.writer) {
        tunnelState->server.conn->close();
        return;
    }
}

TunnelStateData::TunnelStateData(ClientHttpRequest *clientRequest) :
    connectRespBuf(NULL),
    connectReqWriting(false),
    startTime(squid_curtime)
{
    debugs(26, 3, "TunnelStateData constructed this=" << this);
    client.readPendingFunc = &tunnelDelayedClientRead;
    server.readPendingFunc = &tunnelDelayedServerRead;

    assert(clientRequest);
    url = xstrdup(clientRequest->uri);
    request = clientRequest->request;
    server.size_ptr = &clientRequest->out.size;
    client.size_ptr = &clientRequest->al->http.clientRequestSz.payloadData;
    status_ptr = &clientRequest->al->http.code;
    logTag_ptr = &clientRequest->logType;
    al = clientRequest->al;
    http = clientRequest;

    client.conn = clientRequest->getConn()->clientConnection;
    comm_add_close_handler(client.conn->fd, tunnelClientClosed, this);

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, this));
    commSetConnTimeout(client.conn, Config.Timeout.lifetime, timeoutCall);
}

TunnelStateData::~TunnelStateData()
{
    debugs(26, 3, "TunnelStateData destructed this=" << this);
    assert(noConnections());
    xfree(url);
    serverDestinations.clear();
    delete connectRespBuf;
}

TunnelStateData::Connection::~Connection()
{
    if (readPending)
        eventDelete(readPendingFunc, readPending);

    safe_free(buf);
}

int
TunnelStateData::Connection::bytesWanted(int lowerbound, int upperbound) const
{
#if USE_DELAY_POOLS
    return delayId.bytesWanted(lowerbound, upperbound);
#else

    return upperbound;
#endif
}

void
TunnelStateData::Connection::bytesIn(int const &count)
{
    debugs(26, 3, HERE << "len=" << len << " + count=" << count);
#if USE_DELAY_POOLS
    delayId.bytesIn(count);
#endif

    len += count;
}

int
TunnelStateData::Connection::debugLevelForError(int const xerrno) const
{
#ifdef ECONNRESET

    if (xerrno == ECONNRESET)
        return 2;

#endif

    if (ignoreErrno(xerrno))
        return 3;

    return 1;
}

/* Read from server side and queue it for writing to the client */
void
TunnelStateData::ReadServer(const Comm::ConnectionPointer &c, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert(cbdataReferenceValid(tunnelState));
    debugs(26, 3, HERE << c);

    tunnelState->readServer(buf, len, errcode, xerrno);
}

void
TunnelStateData::readServer(char *, size_t len, Comm::Flag errcode, int xerrno)
{
    debugs(26, 3, HERE << server.conn << ", read " << len << " bytes, err=" << errcode);
    server.delayedLoops=0;

    /*
     * Bail out early on Comm::ERR_CLOSING
     * - close handlers will tidy up for us
     */

    if (errcode == Comm::ERR_CLOSING)
        return;

    if (len > 0) {
        server.bytesIn(len);
        statCounter.server.all.kbytes_in += len;
        statCounter.server.other.kbytes_in += len;
        request->hier.notePeerRead();
    }

    if (keepGoingAfterRead(len, errcode, xerrno, server, client))
        copy(len, server, client, WriteClientDone);
}

/// Called when we read [a part of] CONNECT response from the peer
void
TunnelStateData::readConnectResponseDone(char *, size_t len, Comm::Flag errcode, int xerrno)
{
    debugs(26, 3, server.conn << ", read " << len << " bytes, err=" << errcode);
    assert(waitingForConnectResponse());

    if (errcode == Comm::ERR_CLOSING)
        return;

    if (len > 0) {
        connectRespBuf->appended(len);
        server.bytesIn(len);
        statCounter.server.all.kbytes_in += len;
        statCounter.server.other.kbytes_in += len;
        request->hier.notePeerRead();
    }

    if (keepGoingAfterRead(len, errcode, xerrno, server, client))
        handleConnectResponse(len);
}

void
TunnelStateData::informUserOfPeerError(const char *errMsg, const size_t sz)
{
    server.len = 0;

    if (logTag_ptr)
        *logTag_ptr = LOG_TCP_TUNNEL;

    if (!clientExpectsConnectResponse()) {
        // closing the connection is the best we can do here
        debugs(50, 3, server.conn << " closing on error: " << errMsg);
        server.conn->close();
        return;
    }

    // if we have no reply suitable to relay, use 502 Bad Gateway
    if (!sz || sz > static_cast<size_t>(connectRespBuf->contentSize())) {
        ErrorState *err = new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw());
        *status_ptr = Http::scBadGateway;
        err->callback = tunnelErrorComplete;
        err->callback_data = this;
        errorSend(http->getConn()->clientConnection, err);
        return;
    }

    // if we need to send back the server response. write its headers to the client
    server.len = sz;
    memcpy(server.buf, connectRespBuf->content(), server.len);
    copy(server.len, server, client, TunnelStateData::WriteClientDone);
    // then close the server FD to prevent any relayed keep-alive causing CVE-2015-5400
    server.closeIfOpen();
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadConnectResponseDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    tunnelState->readConnectResponseDone(buf, len, errcode, xerrno);
}

/// Parses [possibly incomplete] CONNECT response and reacts to it.
/// If the tunnel is being closed or more response data is needed, returns false.
/// Otherwise, the caller should handle the remaining read data, if any.
void
TunnelStateData::handleConnectResponse(const size_t chunkSize)
{
    assert(waitingForConnectResponse());

    // Ideally, client and server should use MemBuf or better, but current code
    // never accumulates more than one read when shoveling data (XXX) so it does
    // not need to deal with MemBuf complexity. To keep it simple, we use a
    // dedicated MemBuf for accumulating CONNECT responses. TODO: When shoveling
    // is optimized, reuse server.buf for CONNEC response accumulation instead.

    /* mimic the basic parts of HttpStateData::processReplyHeader() */
    HttpReply rep;
    Http::StatusCode parseErr = Http::scNone;
    const bool eof = !chunkSize;
    connectRespBuf->terminate(); // HttpMsg::parse requires terminated string
    const bool parsed = rep.parse(connectRespBuf->content(), connectRespBuf->contentSize(), eof, &parseErr);
    if (!parsed) {
        if (parseErr > 0) { // unrecoverable parsing error
            informUserOfPeerError("malformed CONNECT response from peer", 0);
            return;
        }

        // need more data
        assert(!eof);
        assert(!parseErr);

        if (!connectRespBuf->hasSpace()) {
            informUserOfPeerError("huge CONNECT response from peer", 0);
            return;
        }

        // keep reading
        readConnectResponse();
        return;
    }

    // CONNECT response was successfully parsed
    request->hier.peer_reply_status = rep.sline.status();

    // bail if we did not get an HTTP 200 (Connection Established) response
    if (rep.sline.status() != Http::scOkay) {
        // if we ever decide to reuse the peer connection, we must extract the error response first
        *status_ptr = rep.sline.status(); // we are relaying peer response
        informUserOfPeerError("unsupported CONNECT response status code", rep.hdr_sz);
        return;
    }

    if (rep.hdr_sz < connectRespBuf->contentSize()) {
        // preserve bytes that the server already sent after the CONNECT response
        server.len = connectRespBuf->contentSize() - rep.hdr_sz;
        memcpy(server.buf, connectRespBuf->content()+rep.hdr_sz, server.len);
    } else {
        // reset; delay pools were using this field to throttle CONNECT response
        server.len = 0;
    }

    delete connectRespBuf;
    connectRespBuf = NULL;
    connectExchangeCheckpoint();
}

void
TunnelStateData::Connection::error(int const xerrno)
{
    debugs(50, debugLevelForError(xerrno), HERE << conn << ": read/write failure: " << xstrerr(xerrno));

    if (!ignoreErrno(xerrno))
        conn->close();
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadClient(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    tunnelState->readClient(buf, len, errcode, xerrno);
}

void
TunnelStateData::readClient(char *, size_t len, Comm::Flag errcode, int xerrno)
{
    debugs(26, 3, HERE << client.conn << ", read " << len << " bytes, err=" << errcode);
    client.delayedLoops=0;

    /*
     * Bail out early on Comm::ERR_CLOSING
     * - close handlers will tidy up for us
     */

    if (errcode == Comm::ERR_CLOSING)
        return;

    if (len > 0) {
        client.bytesIn(len);
        statCounter.client_http.kbytes_in += len;
    }

    if (keepGoingAfterRead(len, errcode, xerrno, client, server))
        copy(len, client, server, WriteServerDone);
}

/// Updates state after reading from client or server.
/// Returns whether the caller should use the data just read.
bool
TunnelStateData::keepGoingAfterRead(size_t len, Comm::Flag errcode, int xerrno, Connection &from, Connection &to)
{
    debugs(26, 3, HERE << "from={" << from.conn << "}, to={" << to.conn << "}");

    /* I think this is to prevent free-while-in-a-callback behaviour
     * - RBC 20030229
     * from.conn->close() / to.conn->close() done here trigger close callbacks which may free TunnelStateData
     */
    const CbcPointer<TunnelStateData> safetyLock(this);

    /* Bump the source connection read timeout on any activity */
    if (Comm::IsConnOpen(from.conn)) {
        AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                         CommTimeoutCbPtrFun(tunnelTimeout, this));
        commSetConnTimeout(from.conn, Config.Timeout.read, timeoutCall);
    }

    /* Bump the dest connection read timeout on any activity */
    /* see Bug 3659: tunnels can be weird, with very long one-way transfers */
    if (Comm::IsConnOpen(to.conn)) {
        AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                         CommTimeoutCbPtrFun(tunnelTimeout, this));
        commSetConnTimeout(to.conn, Config.Timeout.read, timeoutCall);
    }

    if (errcode)
        from.error (xerrno);
    else if (len == 0 || !Comm::IsConnOpen(to.conn)) {
        debugs(26, 3, HERE << "Nothing to write or client gone. Terminate the tunnel.");
        from.conn->close();

        /* Only close the remote end if we've finished queueing data to it */
        if (from.len == 0 && Comm::IsConnOpen(to.conn) ) {
            to.conn->close();
        }
    } else if (cbdataReferenceValid(this)) {
        return true;
    }

    return false;
}

void
TunnelStateData::copy(size_t len, Connection &from, Connection &to, IOCB *completion)
{
    debugs(26, 3, HERE << "Schedule Write");
    AsyncCall::Pointer call = commCbCall(5,5, "TunnelBlindCopyWriteHandler",
                                         CommIoCbPtrFun(completion, this));
    to.write(from.buf, len, call, NULL);
}

/* Writes data from the client buffer to the server side */
void
TunnelStateData::WriteServerDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));
    tunnelState->server.writer = NULL;

    tunnelState->writeServerDone(buf, len, flag, xerrno);
}

void
TunnelStateData::writeServerDone(char *, size_t len, Comm::Flag flag, int xerrno)
{
    debugs(26, 3, HERE  << server.conn << ", " << len << " bytes written, flag=" << flag);

    if (flag == Comm::ERR_CLOSING)
        return;

    request->hier.notePeerWrite();

    /* Error? */
    if (flag != Comm::OK) {
        debugs(26, 4, "to-server write failed: " << xerrno);
        server.error(xerrno); // may call comm_close
        return;
    }

    /* EOF? */
    if (len == 0) {
        debugs(26, 4, HERE << "No read input. Closing server connection.");
        server.conn->close();
        return;
    }

    /* Valid data */
    statCounter.server.all.kbytes_out += len;
    statCounter.server.other.kbytes_out += len;
    client.dataSent(len);

    /* If the other end has closed, so should we */
    if (!Comm::IsConnOpen(client.conn)) {
        debugs(26, 4, HERE << "Client gone away. Shutting down server connection.");
        server.conn->close();
        return;
    }

    const CbcPointer<TunnelStateData> safetyLock(this); /* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyClientBytes();
}

/* Writes data from the server buffer to the client side */
void
TunnelStateData::WriteClientDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));
    tunnelState->client.writer = NULL;

    tunnelState->writeClientDone(buf, len, flag, xerrno);
}

void
TunnelStateData::Connection::dataSent(size_t amount)
{
    debugs(26, 3, HERE << "len=" << len << " - amount=" << amount);
    assert(amount == (size_t)len);
    len =0;
    /* increment total object size */

    if (size_ptr)
        *size_ptr += amount;

}

void
TunnelStateData::Connection::write(const char *b, int size, AsyncCall::Pointer &callback, FREE * free_func)
{
    writer = callback;
    Comm::Write(conn, b, size, callback, free_func);
}

void
TunnelStateData::writeClientDone(char *, size_t len, Comm::Flag flag, int xerrno)
{
    debugs(26, 3, HERE << client.conn << ", " << len << " bytes written, flag=" << flag);

    if (flag == Comm::ERR_CLOSING)
        return;

    /* Error? */
    if (flag != Comm::OK) {
        debugs(26, 4, "from-client read failed: " << xerrno);
        client.error(xerrno); // may call comm_close
        return;
    }

    /* EOF? */
    if (len == 0) {
        debugs(26, 4, HERE << "Closing client connection due to 0 byte read.");
        client.conn->close();
        return;
    }

    /* Valid data */
    statCounter.client_http.kbytes_out += len;
    server.dataSent(len);

    /* If the other end has closed, so should we */
    if (!Comm::IsConnOpen(server.conn)) {
        debugs(26, 4, HERE << "Server has gone away. Terminating client connection.");
        client.conn->close();
        return;
    }

    CbcPointer<TunnelStateData> safetyLock(this);   /* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyServerBytes();
}

static void
tunnelTimeout(const CommTimeoutCbParams &io)
{
    TunnelStateData *tunnelState = static_cast<TunnelStateData *>(io.data);
    debugs(26, 3, HERE << io.conn);
    /* Temporary lock to protect our own feets (comm_close -> tunnelClientClosed -> Free) */
    CbcPointer<TunnelStateData> safetyLock(tunnelState);

    tunnelState->client.closeIfOpen();
    tunnelState->server.closeIfOpen();
}

void
TunnelStateData::Connection::closeIfOpen()
{
    if (Comm::IsConnOpen(conn))
        conn->close();
}

static void
tunnelDelayedClientRead(void *data)
{
    if (!data)
        return;

    TunnelStateData *tunnel = static_cast<TunnelStateData*>(data);
    tunnel->client.readPending = NULL;
    static uint64_t counter=0;
    debugs(26, 7, "Client read(2) delayed " << ++counter << " times");
    tunnel->copyRead(tunnel->client, TunnelStateData::ReadClient);
}

static void
tunnelDelayedServerRead(void *data)
{
    if (!data)
        return;

    TunnelStateData *tunnel = static_cast<TunnelStateData*>(data);
    tunnel->server.readPending = NULL;
    static uint64_t counter=0;
    debugs(26, 7, "Server read(2) delayed " << ++counter << " times");
    tunnel->copyRead(tunnel->server, TunnelStateData::ReadServer);
}

void
TunnelStateData::copyRead(Connection &from, IOCB *completion)
{
    assert(from.len == 0);
    // If only the minimum permitted read size is going to be attempted
    // then we schedule an event to try again in a few I/O cycles.
    // Allow at least 1 byte to be read every (0.3*10) seconds.
    int bw = from.bytesWanted(1, SQUID_TCP_SO_RCVBUF);
    if (bw == 1 && ++from.delayedLoops < 10) {
        from.readPending = this;
        eventAdd("tunnelDelayedServerRead", from.readPendingFunc, from.readPending, 0.3, true);
        return;
    }

    AsyncCall::Pointer call = commCbCall(5,4, "TunnelBlindCopyReadHandler",
                                         CommIoCbPtrFun(completion, this));
    comm_read(from.conn, from.buf, bw, call);
}

void
TunnelStateData::readConnectResponse()
{
    assert(waitingForConnectResponse());

    AsyncCall::Pointer call = commCbCall(5,4, "readConnectResponseDone",
                                         CommIoCbPtrFun(ReadConnectResponseDone, this));
    comm_read(server.conn, connectRespBuf->space(),
              server.bytesWanted(1, connectRespBuf->spaceSize()), call);
}

void
TunnelStateData::copyClientBytes()
{
    if (preReadClientData.length()) {
        size_t copyBytes = preReadClientData.length() > SQUID_TCP_SO_RCVBUF ? SQUID_TCP_SO_RCVBUF : preReadClientData.length();
        memcpy(client.buf, preReadClientData.rawContent(), copyBytes);
        preReadClientData.consume(copyBytes);
        client.bytesIn(copyBytes);
        if (keepGoingAfterRead(copyBytes, Comm::OK, 0, client, server))
            copy(copyBytes, client, server, TunnelStateData::WriteServerDone);
    } else
        copyRead(client, ReadClient);
}

void
TunnelStateData::copyServerBytes()
{
    if (preReadServerData.length()) {
        size_t copyBytes = preReadServerData.length() > SQUID_TCP_SO_RCVBUF ? SQUID_TCP_SO_RCVBUF : preReadServerData.length();
        memcpy(server.buf, preReadServerData.rawContent(), copyBytes);
        preReadServerData.consume(copyBytes);
        server.bytesIn(copyBytes);
        if (keepGoingAfterRead(copyBytes, Comm::OK, 0, server, client))
            copy(copyBytes, server, client, TunnelStateData::WriteClientDone);
    } else
        copyRead(server, ReadServer);
}

/**
 * Set the HTTP status for this request and sets the read handlers for client
 * and server side connections.
 */
static void
tunnelStartShoveling(TunnelStateData *tunnelState)
{
    assert(!tunnelState->waitingForConnectExchange());
    *tunnelState->status_ptr = Http::scOkay;
    if (tunnelState->logTag_ptr)
        *tunnelState->logTag_ptr = LOG_TCP_TUNNEL;
    if (cbdataReferenceValid(tunnelState)) {

        // Shovel any payload already pushed into reply buffer by the server response
        if (!tunnelState->server.len)
            tunnelState->copyServerBytes();
        else {
            debugs(26, DBG_DATA, "Tunnel server PUSH Payload: \n" << Raw("", tunnelState->server.buf, tunnelState->server.len) << "\n----------");
            tunnelState->copy(tunnelState->server.len, tunnelState->server, tunnelState->client, TunnelStateData::WriteClientDone);
        }

        if (tunnelState->http.valid() && tunnelState->http->getConn() && !tunnelState->http->getConn()->inBuf.isEmpty()) {
            SBuf * const in = &tunnelState->http->getConn()->inBuf;
            debugs(26, DBG_DATA, "Tunnel client PUSH Payload: \n" << *in << "\n----------");
            tunnelState->preReadClientData.append(*in);
            in->consume(); // ConnStateData buffer accounting after the shuffle.
        }
        tunnelState->copyClientBytes();
    }
}

/**
 * All the pieces we need to write to client and/or server connection
 * have been written.
 * Call the tunnelStartShoveling to start the blind pump.
 */
static void
tunnelConnectedWriteDone(const Comm::ConnectionPointer &conn, char *, size_t len, Comm::Flag flag, int, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, HERE << conn << ", flag=" << flag);
    tunnelState->client.writer = NULL;

    if (flag != Comm::OK) {
        *tunnelState->status_ptr = Http::scInternalServerError;
        tunnelErrorComplete(conn->fd, data, 0);
        return;
    }

    if (auto http = tunnelState->http.get()) {
        http->out.headers_sz += len;
        http->out.size += len;
    }

    tunnelStartShoveling(tunnelState);
}

/// Called when we are done writing CONNECT request to a peer.
static void
tunnelConnectReqWriteDone(const Comm::ConnectionPointer &conn, char *, size_t ioSize, Comm::Flag flag, int, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, conn << ", flag=" << flag);
    tunnelState->server.writer = NULL;
    assert(tunnelState->waitingForConnectRequest());

    tunnelState->request->hier.notePeerWrite();

    if (flag != Comm::OK) {
        *tunnelState->status_ptr = Http::scInternalServerError;
        tunnelErrorComplete(conn->fd, data, 0);
        return;
    }

    statCounter.server.all.kbytes_out += ioSize;
    statCounter.server.other.kbytes_out += ioSize;

    tunnelState->connectReqWriting = false;
    tunnelState->connectExchangeCheckpoint();
}

void
TunnelStateData::connectExchangeCheckpoint()
{
    if (waitingForConnectResponse()) {
        debugs(26, 5, "still reading CONNECT response on " << server.conn);
    } else if (waitingForConnectRequest()) {
        debugs(26, 5, "still writing CONNECT request on " << server.conn);
    } else {
        assert(!waitingForConnectExchange());
        debugs(26, 3, "done with CONNECT exchange on " << server.conn);
        tunnelConnected(server.conn, this);
    }
}

/*
 * handle the write completion from a proxy request to an upstream origin
 */
static void
tunnelConnected(const Comm::ConnectionPointer &server, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, HERE << server << ", tunnelState=" << tunnelState);

    if (!tunnelState->clientExpectsConnectResponse())
        tunnelStartShoveling(tunnelState); // ssl-bumped connection, be quiet
    else {
        *tunnelState->status_ptr = Http::scOkay;
        AsyncCall::Pointer call = commCbCall(5,5, "tunnelConnectedWriteDone",
                                             CommIoCbPtrFun(tunnelConnectedWriteDone, tunnelState));
        tunnelState->client.write(conn_established, strlen(conn_established), call, NULL);
    }
}

static void
tunnelErrorComplete(int fd/*const Comm::ConnectionPointer &*/, void *data, size_t)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, HERE << "FD " << fd);
    assert(tunnelState != NULL);
    /* temporary lock to save our own feets (comm_close -> tunnelClientClosed -> Free) */
    CbcPointer<TunnelStateData> safetyLock(tunnelState);

    if (Comm::IsConnOpen(tunnelState->client.conn))
        tunnelState->client.conn->close();

    if (Comm::IsConnOpen(tunnelState->server.conn))
        tunnelState->server.conn->close();
}

static void
tunnelConnectDone(const Comm::ConnectionPointer &conn, Comm::Flag status, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;

    if (status != Comm::OK) {
        debugs(26, 4, HERE << conn << ", comm failure recovery.");
        {
            assert(!tunnelState->serverDestinations.empty());
            const Comm::Connection &failedDest = *tunnelState->serverDestinations.front();
            if (CachePeer *peer = failedDest.getPeer())
                peerConnectFailed(peer);
            debugs(26, 4, "removing the failed one from " << tunnelState->serverDestinations.size() <<
                   " destinations: " << failedDest);
        }
        /* At this point only the TCP handshake has failed. no data has been passed.
         * we are allowed to re-try the TCP-level connection to alternate IPs for CONNECT.
         */
        tunnelState->serverDestinations.erase(tunnelState->serverDestinations.begin());
        if (!tunnelState->serverDestinations.empty() && FwdState::EnoughTimeToReForward(tunnelState->startTime)) {
            debugs(26, 4, "re-forwarding");
            tunnelState->startConnecting();
        } else {
            debugs(26, 4, HERE << "terminate with error.");
            ErrorState *err = new ErrorState(ERR_CONNECT_FAIL, Http::scServiceUnavailable, tunnelState->request.getRaw());
            *tunnelState->status_ptr = Http::scServiceUnavailable;
            err->xerrno = xerrno;
            // on timeout is this still:    err->xerrno = ETIMEDOUT;
            err->port = conn->remote.port();
            err->callback = tunnelErrorComplete;
            err->callback_data = tunnelState;
            errorSend(tunnelState->client.conn, err);
            if (tunnelState->request != NULL)
                tunnelState->request->hier.stopPeerClock(false);
        }
        return;
    }

#if USE_DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (conn->getPeer() && conn->getPeer()->options.no_delay)
        tunnelState->server.setDelayId(DelayId());
#endif

    netdbPingSite(tunnelState->request->url.host());

    tunnelState->request->hier.resetPeerNotes(conn, tunnelState->getHost());

    tunnelState->server.conn = conn;
    tunnelState->request->peer_host = conn->getPeer() ? conn->getPeer()->host : NULL;
    comm_add_close_handler(conn->fd, tunnelServerClosed, tunnelState);

    debugs(26, 4, HERE << "determine post-connect handling pathway.");
    if (conn->getPeer()) {
        tunnelState->request->peer_login = conn->getPeer()->login;
        tunnelState->request->peer_domain = conn->getPeer()->domain;
        tunnelState->request->flags.auth_no_keytab = conn->getPeer()->options.auth_no_keytab;
        tunnelState->request->flags.proxying = !(conn->getPeer()->options.originserver);
    } else {
        tunnelState->request->peer_login = NULL;
        tunnelState->request->peer_domain = NULL;
        tunnelState->request->flags.auth_no_keytab = false;
        tunnelState->request->flags.proxying = false;
    }

    if (tunnelState->request->flags.proxying)
        tunnelState->connectToPeer();
    else {
        tunnelConnected(conn, tunnelState);
    }

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(conn, Config.Timeout.read, timeoutCall);
}

void
tunnelStart(ClientHttpRequest * http)
{
    debugs(26, 3, HERE);
    /* Create state structure. */
    TunnelStateData *tunnelState = NULL;
    ErrorState *err = NULL;
    HttpRequest *request = http->request;
    char *url = http->uri;

    /*
     * client_addr.isNoAddr()  indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if (Config.accessList.miss && !request->client_addr.isNoAddr()) {
        /*
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         * default is to allow.
         */
        ACLFilledChecklist ch(Config.accessList.miss, request, NULL);
        ch.al = http->al;
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        ch.syncAle(request, http->log_uri);
        if (ch.fastCheck().denied()) {
            debugs(26, 4, HERE << "MISS access forbidden.");
            err = new ErrorState(ERR_FORWARDING_DENIED, Http::scForbidden, request);
            http->al->http.code = Http::scForbidden;
            errorSend(http->getConn()->clientConnection, err);
            return;
        }
    }

    debugs(26, 3, request->method << ' ' << url << ' ' << request->http_ver);
    ++statCounter.server.all.requests;
    ++statCounter.server.other.requests;

    tunnelState = new TunnelStateData(http);
#if USE_DELAY_POOLS
    //server.setDelayId called from tunnelConnectDone after server side connection established
#endif

    peerSelect(&(tunnelState->serverDestinations), request, http->al,
               NULL,
               tunnelPeerSelectComplete,
               tunnelState);
}

void
TunnelStateData::connectToPeer()
{
    if (CachePeer *p = server.conn->getPeer()) {
        if (p->secure.encryptTransport) {
            AsyncCall::Pointer callback = asyncCall(5,4,
                                                    "TunnelStateData::ConnectedToPeer",
                                                    MyAnswerDialer(&TunnelStateData::connectedToPeer, this));
            auto *connector = new Security::BlindPeerConnector(request, server.conn, callback, al);
            AsyncJob::Start(connector); // will call our callback
            return;
        }
    }

    Security::EncryptorAnswer nil;
    connectedToPeer(nil);
}

void
TunnelStateData::connectedToPeer(Security::EncryptorAnswer &answer)
{
    if (ErrorState *error = answer.error.get()) {
        *status_ptr = error->httpStatus;
        error->callback = tunnelErrorComplete;
        error->callback_data = this;
        errorSend(client.conn, error);
        answer.error.clear(); // preserve error for errorSendComplete()
        return;
    }

    tunnelRelayConnectRequest(server.conn, this);
}

static void
tunnelRelayConnectRequest(const Comm::ConnectionPointer &srv, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert(!tunnelState->waitingForConnectExchange());
    HttpHeader hdr_out(hoRequest);
    Http::StateFlags flags;
    debugs(26, 3, HERE << srv << ", tunnelState=" << tunnelState);
    flags.proxying = tunnelState->request->flags.proxying;
    MemBuf mb;
    mb.init();
    mb.appendf("CONNECT %s HTTP/1.1\r\n", tunnelState->url);
    HttpStateData::httpBuildRequestHeader(tunnelState->request.getRaw(),
                                          NULL,         /* StoreEntry */
                                          tunnelState->al,          /* AccessLogEntry */
                                          &hdr_out,
                                          flags);           /* flags */
    hdr_out.packInto(&mb);
    hdr_out.clean();
    mb.append("\r\n", 2);

    debugs(11, 2, "Tunnel Server REQUEST: " << tunnelState->server.conn <<
           ":\n----------\n" << mb.buf << "\n----------");

    AsyncCall::Pointer writeCall = commCbCall(5,5, "tunnelConnectReqWriteDone",
                                   CommIoCbPtrFun(tunnelConnectReqWriteDone,
                                           tunnelState));

    tunnelState->server.write(mb.buf, mb.size, writeCall, mb.freeFunc());
    tunnelState->connectReqWriting = true;

    tunnelState->connectRespBuf = new MemBuf;
    // SQUID_TCP_SO_RCVBUF: we should not accumulate more than regular I/O buffer
    // can hold since any CONNECT response leftovers have to fit into server.buf.
    // 2*SQUID_TCP_SO_RCVBUF: HttpMsg::parse() zero-terminates, which uses space.
    tunnelState->connectRespBuf->init(SQUID_TCP_SO_RCVBUF, 2*SQUID_TCP_SO_RCVBUF);
    tunnelState->readConnectResponse();

    assert(tunnelState->waitingForConnectExchange());

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(srv, Config.Timeout.read, timeoutCall);
}

static Comm::ConnectionPointer
borrowPinnedConnection(HttpRequest *request, Comm::ConnectionPointer &serverDestination)
{
    // pinned_connection may become nil after a pconn race
    if (ConnStateData *pinned_connection = request ? request->pinnedConnection() : nullptr) {
        Comm::ConnectionPointer serverConn = pinned_connection->borrowPinnedConnection(request, serverDestination->getPeer());
        return serverConn;
    }

    return nullptr;
}

static void
tunnelPeerSelectComplete(Comm::ConnectionList *peer_paths, ErrorState *err, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;

    bool bail = false;
    if (!peer_paths || peer_paths->empty()) {
        debugs(26, 3, HERE << "No paths found. Aborting CONNECT");
        bail = true;
    }

    if (!bail && tunnelState->serverDestinations[0]->peerType == PINNED) {
        Comm::ConnectionPointer serverConn = borrowPinnedConnection(tunnelState->request.getRaw(), tunnelState->serverDestinations[0]);
        debugs(26,7, "pinned peer connection: " << serverConn);
        if (Comm::IsConnOpen(serverConn)) {
            tunnelConnectDone(serverConn, Comm::OK, 0, (void *)tunnelState);
            return;
        }
        bail = true;
    }

    if (bail) {
        if (!err) {
            err = new ErrorState(ERR_CANNOT_FORWARD, Http::scServiceUnavailable, tunnelState->request.getRaw());
        }
        *tunnelState->status_ptr = err->httpStatus;
        err->callback = tunnelErrorComplete;
        err->callback_data = tunnelState;
        errorSend(tunnelState->client.conn, err);
        return;
    }
    delete err;

    if (tunnelState->request != NULL)
        tunnelState->request->hier.startPeerClock();

    debugs(26, 3, "paths=" << peer_paths->size() << ", p[0]={" << (*peer_paths)[0] << "}, serverDest[0]={" <<
           tunnelState->serverDestinations[0] << "}");

    tunnelState->startConnecting();
}

void
TunnelStateData::startConnecting()
{
    Comm::ConnectionPointer &dest = serverDestinations.front();
    GetMarkingsToServer(request.getRaw(), *dest);

    const time_t connectTimeout = dest->connectTimeout(startTime);
    AsyncCall::Pointer call = commCbCall(26,3, "tunnelConnectDone", CommConnectCbPtrFun(tunnelConnectDone, this));
    Comm::ConnOpener *cs = new Comm::ConnOpener(dest, call, connectTimeout);
    cs->setHost(url);
    AsyncJob::Start(cs);
}

CBDATA_CLASS_INIT(TunnelStateData);

bool
TunnelStateData::noConnections() const
{
    return !Comm::IsConnOpen(server.conn) && !Comm::IsConnOpen(client.conn);
}

#if USE_DELAY_POOLS
void
TunnelStateData::Connection::setDelayId(DelayId const &newDelay)
{
    delayId = newDelay;
}

#endif

#if USE_OPENSSL
void
switchToTunnel(HttpRequest *request, Comm::ConnectionPointer &clientConn, Comm::ConnectionPointer &srvConn)
{
    debugs(26,5, "Revert to tunnel FD " << clientConn->fd << " with FD " << srvConn->fd);

    /* Create state structure. */
    ++statCounter.server.all.requests;
    ++statCounter.server.other.requests;

    auto conn = request->clientConnectionManager.get();
    Must(conn);
    Http::StreamPointer context = conn->pipeline.front();
    Must(context && context->http);

    debugs(26, 3, request->method << " " << context->http->uri << " " << request->http_ver);

    TunnelStateData *tunnelState = new TunnelStateData(context->http);

    fd_table[clientConn->fd].read_method = &default_read_method;
    fd_table[clientConn->fd].write_method = &default_write_method;

    request->hier.resetPeerNotes(srvConn, tunnelState->getHost());

    tunnelState->server.conn = srvConn;

#if USE_DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (srvConn->getPeer() && srvConn->getPeer()->options.no_delay)
        tunnelState->server.setDelayId(DelayId::DelayClient(context->http));
#endif

    request->peer_host = srvConn->getPeer() ? srvConn->getPeer()->host : nullptr;
    comm_add_close_handler(srvConn->fd, tunnelServerClosed, tunnelState);

    debugs(26, 4, "determine post-connect handling pathway.");
    if (srvConn->getPeer()) {
        request->peer_login = srvConn->getPeer()->login;
        request->peer_domain = srvConn->getPeer()->domain;
        request->flags.auth_no_keytab = srvConn->getPeer()->options.auth_no_keytab;
        request->flags.proxying = !(srvConn->getPeer()->options.originserver);
    } else {
        request->peer_login = nullptr;
        request->peer_domain = nullptr;
        request->flags.auth_no_keytab = false;
        request->flags.proxying = false;
    }

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(srvConn, Config.Timeout.read, timeoutCall);
    fd_table[srvConn->fd].read_method = &default_read_method;
    fd_table[srvConn->fd].write_method = &default_write_method;

    auto ssl = fd_table[srvConn->fd].ssl.get();
    assert(ssl);
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    tunnelState->preReadServerData = srvBio->rBufData();
    tunnelStartShoveling(tunnelState);
}
#endif //USE_OPENSSL

