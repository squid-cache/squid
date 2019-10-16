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
#include "clients/HttpTunneler.h"
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
#include "HappyConnOpener.h"
#include "http.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ip/QosConfig.h"
#include "LogTags.h"
#include "MemBuf.h"
#include "neighbors.h"
#include "PeerSelectState.h"
#include "ResolvedPeers.h"
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
class TunnelStateData: public PeerSelectionInitiator
{
    CBDATA_CHILD(TunnelStateData);

public:
    TunnelStateData(ClientHttpRequest *);
    virtual ~TunnelStateData();
    TunnelStateData(const TunnelStateData &); // do not implement
    TunnelStateData &operator =(const TunnelStateData &); // do not implement

    class Connection;
    static void ReadClient(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data);
    static void ReadServer(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag errcode, int xerrno, void *data);
    static void WriteClientDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data);
    static void WriteServerDone(const Comm::ConnectionPointer &, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data);

    bool noConnections() const;
    char *url;
    CbcPointer<ClientHttpRequest> http;
    HttpRequest::Pointer request;
    AccessLogEntryPointer al;

    const char * getHost() const {
        return (server.conn != NULL && server.conn->getPeer() ? server.conn->getPeer()->host : request->url.host());
    };

    /// Whether the client sent a CONNECT request to us.
    bool clientExpectsConnectResponse() const {
        // If we are forcing a tunnel after receiving a client CONNECT, then we
        // have already responded to that CONNECT before tunnel.cc started.
        if (request && request->flags.forceTunnel)
            return false;
#if USE_OPENSSL
        // We are bumping and we had already send "OK CONNECTED"
        if (http.valid() && http->getConn() && http->getConn()->serverBump() && http->getConn()->serverBump()->at(XactionStep::tlsBump2, XactionStep::tlsBump3))
            return false;
#endif
        return !(request != NULL &&
                 (request->flags.interceptTproxy || request->flags.intercepted));
    }

    /// starts connecting to the next hop, either for the first time or while
    /// recovering from the previous connect failure
    void startConnecting();

    /// called when negotiations with the peer have been successfully completed
    void notePeerReadyToShovel();

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

        bool monitorsClosures() const { return bool(closer); }

        /// (re)sets a new close handler to the given method
        template <typename Method>
        void resetCloseHandler(Method method, const char *name, TunnelStateData *tunnelState);

        /// forgets the close handler (of the likely recently closed connection)
        void resetCloseHandler() { closer = nullptr; }

        int len;
        char *buf;
        AsyncCall::Pointer writer; ///< pending Comm::Write callback
        uint64_t *size_ptr;      /* pointer to size in an ConnStateData for logging */

        Comm::ConnectionPointer conn;    ///< The currently connected connection.
        uint8_t delayedLoops; ///< how many times a read on this connection has been postponed.

        // XXX: make these an AsyncCall when event API can handle them
        TunnelStateData *readPending;
        EVH *readPendingFunc;

#if USE_DELAY_POOLS

        DelayId delayId;
#endif

    private:
        /// the registered close handler for the connection
        AsyncCall::Pointer closer;
    };

    Connection client, server;
    int *status_ptr;        ///< pointer for logging HTTP status
    LogTags *logTag_ptr;    ///< pointer for logging Squid processing code

    SBuf preReadClientData;
    SBuf preReadServerData;
    time_t startTime; ///< object creation time, before any peer selection/connection attempts
    /// Whether we are waiting for the CONNECT request/response exchange with the peer.
    bool waitingForConnectExchange;
    HappyConnOpenerPointer connOpener; ///< current connection opening job
    ResolvedPeersPointer destinations; ///< paths for forwarding the request
    bool destinationsFound; ///< At least one candidate path found
    /// whether another destination may be still attempted if the TCP connection
    /// was unexpectedly closed
    bool retriable;

    // AsyncCalls which we set and may need cancelling.
    struct {
        AsyncCall::Pointer connector;  ///< a call linking us to the ConnOpener producing serverConn.
    } calls;

    void copyRead(Connection &from, IOCB *completion);

    /// continue to set up connection to a peer, going async for SSL peers
    void connectToPeer();

    /* PeerSelectionInitiator API */
    virtual void noteDestination(Comm::ConnectionPointer conn) override;
    virtual void noteDestinationsEnd(ErrorState *selectionError) override;

    void syncHierNote(const Comm::ConnectionPointer &server, const char *origin);

    /// called when a connection has been successfully established or
    /// when all candidate destinations have been tried and all have failed
    void noteConnection(HappyConnOpenerAnswer &);

    /// whether we are waiting for HappyConnOpener
    /// same as calls.connector but may differ from connOpener.valid()
    bool opening() const { return connOpener.set(); }

    void cancelOpening(const char *reason);

    /// Start using an established connection
    void connectDone(const Comm::ConnectionPointer &conn, const char *origin, const bool reused);

    void notifyConnOpener();

    void saveError(ErrorState *finalError);
    bool hasError() const { return savedError; }
    void sendError(ErrorState *finalError, const char *reason);

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

    void usePinned();

    /// callback handler after connection setup (including any encryption)
    void connectedToPeer(Security::EncryptorAnswer &answer);

    /// details of the "last tunneling attempt" failure (if it failed)
    ErrorState *savedError = nullptr;

    /// resumes operations after the (possibly failed) HTTP CONNECT exchange
    void tunnelEstablishmentDone(Http::TunnelerAnswer &answer);

    void deleteThis();

public:
    bool keepGoingAfterRead(size_t len, Comm::Flag errcode, int xerrno, Connection &from, Connection &to);
    void copy(size_t len, Connection &from, Connection &to, IOCB *);
    void readServer(char *buf, size_t len, Comm::Flag errcode, int xerrno);
    void readClient(char *buf, size_t len, Comm::Flag errcode, int xerrno);
    void writeClientDone(char *buf, size_t len, Comm::Flag flag, int xerrno);
    void writeServerDone(char *buf, size_t len, Comm::Flag flag, int xerrno);

    void copyClientBytes();
    void copyServerBytes();

    /// client-to-Squid connection closure cleanup; may destroy us
    void handleClientClosure();

    /// non-retriable Squid-to-server connection closure cleanup; may destroy us
    void handleServerClosure();
};

static ERCB tunnelErrorComplete;
static CLCB tunnelClientClosed;
static CTCB tunnelTimeout;
static EVH tunnelDelayedClientRead;
static EVH tunnelDelayedServerRead;

/// destroys the tunnel (after performing potentially-throwing cleanup)
void
TunnelStateData::deleteThis()
{
    assert(noConnections());
    // ConnStateData pipeline should contain the CONNECT we are performing
    // but it may be invalid already (bug 4392)
    if (const auto h = http.valid()) {
        if (const auto c = h->getConn())
            if (const auto ctx = c->pipeline.front())
                ctx->finished();
    }
    delete this;
}

void
TunnelStateData::handleServerClosure()
{
    server.conn = nullptr;
    server.writer = nullptr;

    if (request)
        request->hier.stopPeerClock(false);

    if (noConnections())
        return deleteThis();

    if (!client.writer)
        client.conn->close();
}

void
TunnelStateData::handleClientClosure()
{
    client.conn = nullptr;
    client.writer = nullptr;

    if (noConnections())
        return deleteThis();

    if (!server.writer)
        server.conn->close();
}

/// handles closures of the Squid-to-server connection
static void
tunnelServerClosed(const CommCloseCbParams &params)
{
    const auto tunnelState = reinterpret_cast<TunnelStateData *>(params.data);
    debugs(26, 3, tunnelState->server.conn);
    tunnelState->server.resetCloseHandler();

    if (tunnelState->retriable) {
        if (!tunnelState->destinations->empty()) {
            // XXX: opening() cannot be true when we have a (closing) connection
            if (!tunnelState->opening())
                tunnelState->startConnecting(); // try connecting to another destination
            return;
        }

        if (tunnelState->subscribed) {
            debugs(26, 4, "wait for more destinations to try");
            return;
        }

        if (!tunnelState->hasError()) {
            const auto anErr = new ErrorState(ERR_CANNOT_FORWARD, Http::scInternalServerError,
                    tunnelState->request.getRaw(), tunnelState->al);
            tunnelState->saveError(anErr);
        } // else use actual error from last connection attempt
    }

    tunnelState->handleServerClosure();
}

static void
tunnelClientClosed(const CommCloseCbParams &params)
{
    const auto tunnelState = reinterpret_cast<TunnelStateData *>(params.data);
    debugs(26, 3, tunnelState->client.conn);
    tunnelState->client.resetCloseHandler();
    tunnelState->handleClientClosure();
}

TunnelStateData::TunnelStateData(ClientHttpRequest *clientRequest) :
    startTime(squid_curtime),
    waitingForConnectExchange(false),
    destinations(new ResolvedPeers()),
    destinationsFound(false),
    retriable(true)
{
    debugs(26, 3, "TunnelStateData constructed this=" << this);
    client.readPendingFunc = &tunnelDelayedClientRead;
    server.readPendingFunc = &tunnelDelayedServerRead;

    assert(clientRequest);
    url = xstrdup(clientRequest->uri);
    request = clientRequest->request;
    Must(request);
    server.size_ptr = &clientRequest->out.size;
    client.size_ptr = &clientRequest->al->http.clientRequestSz.payloadData;
    status_ptr = &clientRequest->al->http.code;
    logTag_ptr = &clientRequest->logType;
    al = clientRequest->al;
    http = clientRequest;

    client.conn = clientRequest->getConn()->clientConnection;
    client.resetCloseHandler(tunnelClientClosed, "tunnelClientClosed", this);

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, this));
    commSetConnTimeout(client.conn, Config.Timeout.lifetime, timeoutCall);
}

TunnelStateData::~TunnelStateData()
{
    debugs(26, 3, "TunnelStateData destructed this=" << this);
    assert(noConnections());
    xfree(url);
    if (opening())
        cancelOpening("~TunnelStateData");
    delete savedError;
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

/// update "hierarchy" annotations with a new (possibly failed) destination
/// \param origin the name of the origin server we were trying to reach
void
TunnelStateData::syncHierNote(const Comm::ConnectionPointer &conn, const char *origin)
{
    request->hier.resetPeerNotes(conn, origin);
    if (al)
        al->hier.resetPeerNotes(conn, origin);
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

template <typename Method>
void
TunnelStateData::Connection::resetCloseHandler(Method method, const char *name, TunnelStateData *tunnelState)
{
    Must(Comm::IsConnOpen(conn));
    if (closer)
        comm_remove_close_handler(conn->fd, closer);
    closer = commCbCall(5, 4, name, CommCloseCbPtrFun(method, tunnelState));
    comm_add_close_handler(conn->fd, closer);
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
    assert(!tunnelState->waitingForConnectExchange);
    *tunnelState->status_ptr = Http::scOkay;
    if (tunnelState->logTag_ptr)
        tunnelState->logTag_ptr->update(LOG_TCP_TUNNEL);
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

void
TunnelStateData::tunnelEstablishmentDone(Http::TunnelerAnswer &answer)
{
    server.len = 0;

    if (logTag_ptr)
        logTag_ptr->update(LOG_TCP_TUNNEL);

    if (answer.peerResponseStatus != Http::scNone)
        *status_ptr = answer.peerResponseStatus;

    waitingForConnectExchange = false;

    if (answer.positive()) {
        // copy any post-200 OK bytes to our buffer
        preReadServerData = answer.leftovers;
        notePeerReadyToShovel();
        return;
    }

    // TODO: Reuse to-peer connections after a CONNECT error response.

    // TODO: We can and, hence, should close now, but tunnelServerClosed()
    // cannot yet tell whether ErrorState is still writing an error response.
    // server.closeIfOpen();

    if (!clientExpectsConnectResponse()) {
        // closing the non-HTTP client connection is the best we can do
        debugs(50, 3, server.conn << " closing on CONNECT-to-peer error");
        server.closeIfOpen();
        return;
    }

    ErrorState *error = answer.squidError.get();
    Must(error);
    answer.squidError.clear(); // preserve error for errorSendComplete()
    sendError(error, "tunneler returns error");
}

void
TunnelStateData::notePeerReadyToShovel()
{
    if (!clientExpectsConnectResponse())
        tunnelStartShoveling(this); // ssl-bumped connection, be quiet
    else {
        *status_ptr = Http::scOkay;
        AsyncCall::Pointer call = commCbCall(5,5, "tunnelConnectedWriteDone",
                                             CommIoCbPtrFun(tunnelConnectedWriteDone, this));
        al->reply = HttpReply::MakeConnectionEstablished();
        const auto mb = al->reply->pack();
        client.write(mb->content(), mb->contentSize(), call, mb->freeFunc());
        delete mb;
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

void
TunnelStateData::noteConnection(HappyConnOpener::Answer &answer)
{
    calls.connector = nullptr;
    connOpener.clear();

    if (const auto error = answer.error.get()) {
        syncHierNote(answer.conn, request->url.host());
        saveError(error);
        answer.error.clear(); // savedError has it now
        sendError(savedError, "tried all destinations");
        return;
    }

    connectDone(answer.conn, request->url.host(), answer.reused);
}

void
TunnelStateData::connectDone(const Comm::ConnectionPointer &conn, const char *origin, const bool reused)
{
    Must(Comm::IsConnOpen(conn));
    server.conn = conn;
    server.resetCloseHandler(tunnelServerClosed, "tunnelServerClosed", this);

    if (reused)
        ResetMarkingsToServer(request.getRaw(), *conn);
    // else Comm::ConnOpener already applied proper/current markings

    syncHierNote(server.conn, request->url.host());

    request->hier.resetPeerNotes(conn, origin);
    if (al)
        al->hier.resetPeerNotes(conn, origin);

#if USE_DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (conn->getPeer() && conn->getPeer()->options.no_delay)
        server.setDelayId(DelayId());
#endif

    netdbPingSite(request->url.host());

    request->peer_host = conn->getPeer() ? conn->getPeer()->host : nullptr;

    bool toOrigin = false; // same semantics as StateFlags::toOrigin
    if (const auto * const peer = conn->getPeer()) {
        request->prepForPeering(*peer);
        toOrigin = peer->options.originserver;
    } else {
        request->prepForDirect();
        toOrigin = true;
    }

    if (!toOrigin) {
        connectToPeer();
    } else {
        retriable = false;
        notePeerReadyToShovel();
    }

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, this));
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
            err = new ErrorState(ERR_FORWARDING_DENIED, Http::scForbidden, request, http->al);
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
    tunnelState->server.setDelayId(DelayId::DelayClient(http));
#endif
    tunnelState->startSelectingDestinations(request, http->al, nullptr);
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
        saveError(error);
        answer.error.clear();
        Must(server.monitorsClosures()); // closure notification (is already pending or) will happen
        if (IsConnOpen(server.conn))
            server.conn->close();
        return; // tunnelServerClosed() will retry as needed
    }

    retriable = false;

    assert(!waitingForConnectExchange);

    AsyncCall::Pointer callback = asyncCall(5,4,
                                            "TunnelStateData::tunnelEstablishmentDone",
                                            Http::Tunneler::CbDialer<TunnelStateData>(&TunnelStateData::tunnelEstablishmentDone, this));
    const auto tunneler = new Http::Tunneler(server.conn, request, callback, Config.Timeout.lifetime, al);
#if USE_DELAY_POOLS
    tunneler->setDelayId(server.delayId);
#endif
    AsyncJob::Start(tunneler);
    waitingForConnectExchange = true;
    // and wait for the tunnelEstablishmentDone() call
}

void
TunnelStateData::noteDestination(Comm::ConnectionPointer path)
{
    destinationsFound = true;

    if (!path) { // decided to use a pinned connection
        // We can call usePinned() without fear of clashing with an earlier
        // forwarding attempt because PINNED must be the first destination.
        assert(destinations->empty());
        usePinned();
        return;
    }

    destinations->addPath(path);

    if (Comm::IsConnOpen(server.conn)) {
        // We are already using a previously opened connection but also
        // receiving destinations in case we need to re-forward.
        Must(!opening());
        return;
    }

    if (opening()) {
        notifyConnOpener();
        return; // and continue to wait for tunnelConnectDone() callback
    }

    startConnecting();
}

void
TunnelStateData::noteDestinationsEnd(ErrorState *selectionError)
{
    PeerSelectionInitiator::subscribed = false;
    destinations->destinationsFinalized = true;
    if (!destinationsFound) {

        if (selectionError)
            return sendError(selectionError, "path selection has failed");

        if (savedError)
            return sendError(savedError, "all found paths have failed");

        return sendError(new ErrorState(ERR_CANNOT_FORWARD, Http::scServiceUnavailable, request.getRaw(), al),
                         "path selection found no paths");
    }
    // else continue to use one of the previously noted destinations;
    // if all of them fail, tunneling as whole will fail
    Must(!selectionError); // finding at least one path means selection succeeded

    if (Comm::IsConnOpen(server.conn)) {
        // We are already using a previously opened connection but also
        // receiving destinations in case we need to re-forward.
        Must(!opening());
        return;
    }

    Must(opening()); // or we would be stuck with nothing to do or wait for
    notifyConnOpener();
}

/// remembers an error to be used if there will be no more connection attempts
void
TunnelStateData::saveError(ErrorState *error)
{
    debugs(26, 4, savedError << " ? " << error);
    assert(error);
    delete savedError; // may be nil
    savedError = error;
}

/// Starts sending the given error message to the client, leading to the
/// eventual transaction termination. Call with savedError to send savedError.
void
TunnelStateData::sendError(ErrorState *finalError, const char *reason)
{
    debugs(26, 3, "aborting transaction for " << reason);

    if (request)
        request->hier.stopPeerClock(false);

    if (opening())
        cancelOpening(reason);

    assert(finalError);

    // get rid of any cached error unless that is what the caller is sending
    if (savedError != finalError)
        delete savedError; // may be nil
    savedError = nullptr;

    // we cannot try other destinations after responding with an error
    PeerSelectionInitiator::subscribed = false; // may already be false

    *status_ptr = finalError->httpStatus;
    finalError->callback = tunnelErrorComplete;
    finalError->callback_data = this;
    errorSend(client.conn, finalError);
}

/// Notify connOpener that we no longer need connections. We do not have to do
/// this -- connOpener would eventually notice on its own, but notifying reduces
/// waste and speeds up spare connection opening for other transactions (that
/// could otherwise wait for this transaction to use its spare allowance).
void
TunnelStateData::cancelOpening(const char *reason)
{
    assert(calls.connector);
    calls.connector->cancel(reason);
    calls.connector = nullptr;
    notifyConnOpener();
    connOpener.clear();
}

void
TunnelStateData::startConnecting()
{
    if (request)
        request->hier.startPeerClock();

    assert(!destinations->empty());

    calls.connector = asyncCall(17, 5, "TunnelStateData::noteConnection", HappyConnOpener::CbDialer<TunnelStateData>(&TunnelStateData::noteConnection, this));
    const auto cs = new HappyConnOpener(destinations, calls.connector, request, startTime, 0, al);
    cs->setHost(request->url.host());
    cs->setRetriable(false);
    cs->allowPersistent(false);
    destinations->notificationPending = true; // start() is async
    connOpener = cs;
    AsyncJob::Start(cs);
}

/// send request on an existing connection dedicated to the requesting client
void
TunnelStateData::usePinned()
{
    Must(request);
    const auto connManager = request->pinnedConnection();
    try {
        const auto serverConn = ConnStateData::BorrowPinnedConnection(request.getRaw(), al);
        debugs(26, 7, "pinned peer connection: " << serverConn);

        // Set HttpRequest pinned related flags for consistency even if
        // they are not really used by tunnel.cc code.
        request->flags.pinned = true;
        if (connManager->pinnedAuth())
            request->flags.auth = true;

        // the server may close the pinned connection before this request
        const auto reused = true;
        connectDone(serverConn, connManager->pinning.host, reused);
    } catch (ErrorState * const error) {
        syncHierNote(nullptr, connManager ? connManager->pinning.host : request->url.host());
        // a PINNED path failure is fatal; do not wait for more paths
        sendError(error, "pinned path failure");
        return;
    }

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

/// makes sure connOpener knows that destinations have changed
void
TunnelStateData::notifyConnOpener()
{
    if (destinations->notificationPending) {
        debugs(17, 7, "reusing pending notification");
    } else {
        destinations->notificationPending = true;
        CallJobHere(17, 5, connOpener, HappyConnOpener, noteCandidatesChange);
    }
}

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
    tunnelState->retriable = false;

    // tunnelStartShoveling() drains any buffered from-client data (inBuf)
    fd_table[clientConn->fd].useDefaultIo();

    request->hier.resetPeerNotes(srvConn, tunnelState->getHost());

    tunnelState->server.conn = srvConn;
    tunnelState->server.resetCloseHandler(tunnelServerClosed, "tunnelServerClosed", tunnelState);

#if USE_DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (!srvConn->getPeer() || !srvConn->getPeer()->options.no_delay)
        tunnelState->server.setDelayId(DelayId::DelayClient(context->http));
#endif

    request->peer_host = srvConn->getPeer() ? srvConn->getPeer()->host : nullptr;

    debugs(26, 4, "determine post-connect handling pathway.");
    if (const auto peer = srvConn->getPeer())
        request->prepForPeering(*peer);
    else
        request->prepForDirect();

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(srvConn, Config.Timeout.read, timeoutCall);

    // we drain any already buffered from-server data below (rBufData)
    fd_table[srvConn->fd].useDefaultIo();

    auto ssl = fd_table[srvConn->fd].ssl.get();
    assert(ssl);
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    tunnelState->preReadServerData = srvBio->rBufData();
    tunnelStartShoveling(tunnelState);
}
#endif //USE_OPENSSL

