
/*
 * DEBUG: section 26    Secure Sockets Layer Proxy
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

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/CbcPointer.h"
#include "base/Vector.h"
#include "CachePeer.h"
#include "client_side_request.h"
#include "client_side.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fde.h"
#include "http.h"
#include "HttpRequest.h"
#include "HttpStateFlags.h"
#include "ip/QosConfig.h"
#include "MemBuf.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "tools.h"
#if USE_DELAY_POOLS
#include "DelayId.h"
#endif

#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

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

public:
    TunnelStateData();
    ~TunnelStateData();
    TunnelStateData(const TunnelStateData &); // do not implement
    TunnelStateData &operator =(const TunnelStateData &); // do not implement

    class Connection;
    static void ReadClient(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    static void ReadServer(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    static void WriteClientDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t flag, int xerrno, void *data);
    static void WriteServerDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t flag, int xerrno, void *data);

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
        return (server.conn != NULL && server.conn->getPeer() ? server.conn->getPeer()->host : request->GetHost());
    };

    /// Whether we are writing a CONNECT request to a peer.
    bool waitingForConnectRequest() const { return connectReqWriting; }
    /// Whether we are reading a CONNECT response from a peer.
    bool waitingForConnectResponse() const { return connectRespBuf; }
    /// Whether we are waiting for the CONNECT request/response exchange with the peer.
    bool waitingForConnectExchange() const { return waitingForConnectRequest() || waitingForConnectResponse(); }

    /// Whether the client sent a CONNECT request to us.
    bool clientExpectsConnectResponse() const {
        return !(request != NULL &&
                 (request->flags.interceptTproxy || request->flags.intercepted));
    }

    class Connection
    {

    public:
        Connection() : len (0), buf ((char *)xmalloc(SQUID_TCP_SO_RCVBUF)), size_ptr(NULL) {}

        ~Connection();

        int bytesWanted(int lower=0, int upper = INT_MAX) const;
        void bytesIn(int const &);
#if USE_DELAY_POOLS

        void setDelayId(DelayId const &);
#endif

        void error(int const xerrno);
        int debugLevelForError(int const xerrno) const;
        /// handles a non-I/O error associated with this Connection
        void logicError(const char *errMsg);
        void closeIfOpen();
        void dataSent (size_t amount);
        int len;
        char *buf;
        int64_t *size_ptr;		/* pointer to size in an ConnStateData for logging */

        Comm::ConnectionPointer conn;    ///< The currently connected connection.

    private:
#if USE_DELAY_POOLS

        DelayId delayId;
#endif

    };

    Connection client, server;
    int *status_ptr;		/* pointer to status for logging */
    MemBuf *connectRespBuf; ///< accumulates peer CONNECT response when we need it
    bool connectReqWriting; ///< whether we are writing a CONNECT request to a peer

    void copyRead(Connection &from, IOCB *completion);

private:
    CBDATA_CLASS2(TunnelStateData);
    bool keepGoingAfterRead(size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to);
    void copy(size_t len, Connection &from, Connection &to, IOCB *);
    void handleConnectResponse(const size_t chunkSize);
    void readServer(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void readClient(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno);
    void writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno);

    static void ReadConnectResponseDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    void readConnectResponseDone(char *buf, size_t len, comm_err_t errcode, int xerrno);
};

static const char *const conn_established = "HTTP/1.1 200 Connection established\r\n\r\n";

static CNCB tunnelConnectDone;
static ERCB tunnelErrorComplete;
static CLCB tunnelServerClosed;
static CLCB tunnelClientClosed;
static CTCB tunnelTimeout;
static PSC tunnelPeerSelectComplete;
static void tunnelConnected(const Comm::ConnectionPointer &server, void *);
static void tunnelRelayConnectRequest(const Comm::ConnectionPointer &server, void *);

static void
tunnelServerClosed(const CommCloseCbParams &params)
{
    TunnelStateData *tunnelState = (TunnelStateData *)params.data;
    debugs(26, 3, HERE << tunnelState->server.conn);
    tunnelState->server.conn = NULL;

    if (tunnelState->noConnections()) {
        delete tunnelState;
        return;
    }

    if (!tunnelState->server.len) {
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

    if (tunnelState->noConnections()) {
        delete tunnelState;
        return;
    }

    if (!tunnelState->client.len) {
        tunnelState->server.conn->close();
        return;
    }
}

TunnelStateData::TunnelStateData() :
        url(NULL),
        http(),
        request(NULL),
        status_ptr(NULL),
        connectRespBuf(NULL),
        connectReqWriting(false)
{
    debugs(26, 3, "TunnelStateData constructed this=" << this);
}

TunnelStateData::~TunnelStateData()
{
    debugs(26, 3, "TunnelStateData destructed this=" << this);
    assert(noConnections());
    xfree(url);
    serverDestinations.clean();
    delete connectRespBuf;
}

TunnelStateData::Connection::~Connection()
{
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
TunnelStateData::ReadServer(const Comm::ConnectionPointer &c, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert(cbdataReferenceValid(tunnelState));
    debugs(26, 3, HERE << c);

    tunnelState->readServer(buf, len, errcode, xerrno);
}

void
TunnelStateData::readServer(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    debugs(26, 3, HERE << server.conn << ", read " << len << " bytes, err=" << errcode);

    /*
     * Bail out early on COMM_ERR_CLOSING
     * - close handlers will tidy up for us
     */

    if (errcode == COMM_ERR_CLOSING)
        return;

    if (len > 0) {
        server.bytesIn(len);
        kb_incr(&(statCounter.server.all.kbytes_in), len);
        kb_incr(&(statCounter.server.other.kbytes_in), len);
    }

    if (keepGoingAfterRead(len, errcode, xerrno, server, client))
        copy(len, server, client, WriteClientDone);
}

/// Called when we read [a part of] CONNECT response from the peer
void
TunnelStateData::readConnectResponseDone(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    debugs(26, 3, server.conn << ", read " << len << " bytes, err=" << errcode);
    assert(waitingForConnectResponse());

    if (errcode == COMM_ERR_CLOSING)
        return;

    if (len > 0) {
        connectRespBuf->appended(len);
        server.bytesIn(len);
        kb_incr(&(statCounter.server.all.kbytes_in), len);
        kb_incr(&(statCounter.server.other.kbytes_in), len);
    }

    if (keepGoingAfterRead(len, errcode, xerrno, server, client))
        handleConnectResponse(len);
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadConnectResponseDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
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
    const bool parsed = rep.parse(connectRespBuf, eof, &parseErr);
    if (!parsed) {
        if (parseErr > 0) { // unrecoverable parsing error
            server.logicError("malformed CONNECT response from peer");
            return;
        }

        // need more data
        assert(!eof);
        assert(!parseErr);

        if (!connectRespBuf->hasSpace()) {
            server.logicError("huge CONNECT response from peer");
            return;
        }

        // keep reading
        readConnectResponse();
        return;
    }

    // CONNECT response was successfully parsed
    *status_ptr = rep.sline.status();

    // bail if we did not get an HTTP 200 (Connection Established) response
    if (rep.sline.status() != Http::scOkay) {
        server.logicError("unsupported CONNECT response status code");
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
TunnelStateData::Connection::logicError(const char *errMsg)
{
    debugs(50, 3, conn << " closing on error: " << errMsg);
    conn->close();
}

void
TunnelStateData::Connection::error(int const xerrno)
{
    /* XXX fixme xstrerror and xerrno... */
    errno = xerrno;

    debugs(50, debugLevelForError(xerrno), HERE << conn << ": read/write failure: " << xstrerror());

    if (!ignoreErrno(xerrno))
        conn->close();
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadClient(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    tunnelState->readClient(buf, len, errcode, xerrno);
}

void
TunnelStateData::readClient(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    debugs(26, 3, HERE << client.conn << ", read " << len << " bytes, err=" << errcode);

    /*
     * Bail out early on COMM_ERR_CLOSING
     * - close handlers will tidy up for us
     */

    if (errcode == COMM_ERR_CLOSING)
        return;

    if (len > 0) {
        client.bytesIn(len);
        kb_incr(&(statCounter.client_http.kbytes_in), len);
    }

    if (keepGoingAfterRead(len, errcode, xerrno, client, server))
        copy(len, client, server, WriteServerDone);
}

/// Updates state after reading from client or server.
/// Returns whether the caller should use the data just read.
bool
TunnelStateData::keepGoingAfterRead(size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to)
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
    Comm::Write(to.conn, from.buf, len, call, NULL);
}

/* Writes data from the client buffer to the server side */
void
TunnelStateData::WriteServerDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    tunnelState->writeServerDone(buf, len, flag, xerrno);
}

void
TunnelStateData::writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, HERE  << server.conn << ", " << len << " bytes written, flag=" << flag);

    /* Error? */
    if (flag != COMM_OK) {
        if (flag != COMM_ERR_CLOSING) {
            debugs(26, 4, HERE << "calling TunnelStateData::server.error(" << xerrno <<")");
            server.error(xerrno); // may call comm_close
        }
        return;
    }

    /* EOF? */
    if (len == 0) {
        debugs(26, 4, HERE << "No read input. Closing server connection.");
        server.conn->close();
        return;
    }

    /* Valid data */
    kb_incr(&(statCounter.server.all.kbytes_out), len);
    kb_incr(&(statCounter.server.other.kbytes_out), len);
    client.dataSent(len);

    /* If the other end has closed, so should we */
    if (!Comm::IsConnOpen(client.conn)) {
        debugs(26, 4, HERE << "Client gone away. Shutting down server connection.");
        server.conn->close();
        return;
    }

    const CbcPointer<TunnelStateData> safetyLock(this);	/* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyRead(client, ReadClient);
}

/* Writes data from the server buffer to the client side */
void
TunnelStateData::WriteClientDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

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
TunnelStateData::writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, HERE << client.conn << ", " << len << " bytes written, flag=" << flag);

    /* Error? */
    if (flag != COMM_OK) {
        if (flag != COMM_ERR_CLOSING) {
            debugs(26, 4, HERE << "Closing client connection due to comm flags.");
            client.error(xerrno); // may call comm_close
        }
        return;
    }

    /* EOF? */
    if (len == 0) {
        debugs(26, 4, HERE << "Closing client connection due to 0 byte read.");
        client.conn->close();
        return;
    }

    /* Valid data */
    kb_incr(&(statCounter.client_http.kbytes_out), len);
    server.dataSent(len);

    /* If the other end has closed, so should we */
    if (!Comm::IsConnOpen(server.conn)) {
        debugs(26, 4, HERE << "Server has gone away. Terminating client connection.");
        client.conn->close();
        return;
    }

    CbcPointer<TunnelStateData> safetyLock(this);	/* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyRead(server, ReadServer);
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

void
TunnelStateData::copyRead(Connection &from, IOCB *completion)
{
    assert(from.len == 0);
    AsyncCall::Pointer call = commCbCall(5,4, "TunnelBlindCopyReadHandler",
                                         CommIoCbPtrFun(completion, this));
    comm_read(from.conn, from.buf, from.bytesWanted(1, SQUID_TCP_SO_RCVBUF), call);
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

/**
 * Set the HTTP status for this request and sets the read handlers for client
 * and server side connections.
 */
static void
tunnelStartShoveling(TunnelStateData *tunnelState)
{
    assert(!tunnelState->waitingForConnectExchange());
    *tunnelState->status_ptr = Http::scOkay;
    if (cbdataReferenceValid(tunnelState)) {

        // Shovel any payload already pushed into reply buffer by the server response
        if (!tunnelState->server.len)
            tunnelState->copyRead(tunnelState->server, TunnelStateData::ReadServer);
        else {
            debugs(26, DBG_DATA, "Tunnel server PUSH Payload: \n" << Raw("", tunnelState->server.buf, tunnelState->server.len) << "\n----------");
            tunnelState->copy(tunnelState->server.len, tunnelState->server, tunnelState->client, TunnelStateData::WriteClientDone);
        }

        // Bug 3371: shovel any payload already pushed into ConnStateData by the client request
        if (tunnelState->http.valid() && tunnelState->http->getConn() && tunnelState->http->getConn()->in.notYetUsed) {
            struct ConnStateData::In *in = &tunnelState->http->getConn()->in;
            debugs(26, DBG_DATA, "Tunnel client PUSH Payload: \n" << Raw("", in->buf, in->notYetUsed) << "\n----------");

            // We just need to ensure the bytes from ConnStateData are in client.buf already to deliver
            memcpy(tunnelState->client.buf, in->buf, in->notYetUsed);
            // NP: readClient() takes care of buffer length accounting.
            tunnelState->readClient(tunnelState->client.buf, in->notYetUsed, COMM_OK, 0);
            in->notYetUsed = 0; // ConnStateData buffer accounting after the shuffle.
        } else
            tunnelState->copyRead(tunnelState->client, TunnelStateData::ReadClient);
    }
}

/**
 * All the pieces we need to write to client and/or server connection
 * have been written.
 * Call the tunnelStartShoveling to start the blind pump.
 */
static void
tunnelConnectedWriteDone(const Comm::ConnectionPointer &conn, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, HERE << conn << ", flag=" << flag);

    if (flag != COMM_OK) {
        *tunnelState->status_ptr = Http::scInternalServerError;
        tunnelErrorComplete(conn->fd, data, 0);
        return;
    }

    tunnelStartShoveling(tunnelState);
}

/// Called when we are done writing CONNECT request to a peer.
static void
tunnelConnectReqWriteDone(const Comm::ConnectionPointer &conn, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, conn << ", flag=" << flag);
    assert(tunnelState->waitingForConnectRequest());

    if (flag != COMM_OK) {
        *tunnelState->status_ptr = Http::scInternalServerError;
        tunnelErrorComplete(conn->fd, data, 0);
        return;
    }

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
        AsyncCall::Pointer call = commCbCall(5,5, "tunnelConnectedWriteDone",
                                             CommIoCbPtrFun(tunnelConnectedWriteDone, tunnelState));
        Comm::Write(tunnelState->client.conn, conn_established, strlen(conn_established), call, NULL);
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
tunnelConnectDone(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;

    if (status != COMM_OK) {
        debugs(26, 4, HERE << conn << ", comm failure recovery.");
        /* At this point only the TCP handshake has failed. no data has been passed.
         * we are allowed to re-try the TCP-level connection to alternate IPs for CONNECT.
         */
        tunnelState->serverDestinations.shift();
        if (status != COMM_TIMEOUT && tunnelState->serverDestinations.size() > 0) {
            /* Try another IP of this destination host */

            if (Ip::Qos::TheConfig.isAclTosActive()) {
                tunnelState->serverDestinations[0]->tos = GetTosToServer(tunnelState->request.getRaw());
            }

#if SO_MARK && USE_LIBCAP
            tunnelState->serverDestinations[0]->nfmark = GetNfmarkToServer(tunnelState->request.getRaw());
#endif

            debugs(26, 4, HERE << "retry with : " << tunnelState->serverDestinations[0]);
            AsyncCall::Pointer call = commCbCall(26,3, "tunnelConnectDone", CommConnectCbPtrFun(tunnelConnectDone, tunnelState));
            Comm::ConnOpener *cs = new Comm::ConnOpener(tunnelState->serverDestinations[0], call, Config.Timeout.connect);
            cs->setHost(tunnelState->url);
            AsyncJob::Start(cs);
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
        }
        return;
    }

#if USE_DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (conn->getPeer() && conn->getPeer()->options.no_delay)
        tunnelState->server.setDelayId(DelayId());
#endif

    tunnelState->request->hier.note(conn, tunnelState->getHost());

    tunnelState->server.conn = conn;
    tunnelState->request->peer_host = conn->getPeer() ? conn->getPeer()->host : NULL;
    comm_add_close_handler(conn->fd, tunnelServerClosed, tunnelState);

    debugs(26, 4, HERE << "determine post-connect handling pathway.");
    if (conn->getPeer()) {
        tunnelState->request->peer_login = conn->getPeer()->login;
        tunnelState->request->flags.proxying = !(conn->getPeer()->options.originserver);
    } else {
        tunnelState->request->peer_login = NULL;
        tunnelState->request->flags.proxying = false;
    }

    if (tunnelState->request->flags.proxying)
        tunnelRelayConnectRequest(conn, tunnelState);
    else {
        tunnelConnected(conn, tunnelState);
    }

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(conn, Config.Timeout.read, timeoutCall);
}

tos_t GetTosToServer(HttpRequest * request);
nfmark_t GetNfmarkToServer(HttpRequest * request);

void
tunnelStart(ClientHttpRequest * http, int64_t * size_ptr, int *status_ptr, const AccessLogEntryPointer &al)
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
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        if (ch.fastCheck() == ACCESS_DENIED) {
            debugs(26, 4, HERE << "MISS access forbidden.");
            err = new ErrorState(ERR_FORWARDING_DENIED, Http::scForbidden, request);
            *status_ptr = Http::scForbidden;
            errorSend(http->getConn()->clientConnection, err);
            return;
        }
    }

    debugs(26, 3, HERE << "'" << RequestMethodStr(request->method) << " " << url << " " << request->http_ver << "'");
    ++statCounter.server.all.requests;
    ++statCounter.server.other.requests;

    tunnelState = new TunnelStateData;
#if USE_DELAY_POOLS
    tunnelState->server.setDelayId(DelayId::DelayClient(http));
#endif
    tunnelState->url = xstrdup(url);
    tunnelState->request = request;
    tunnelState->server.size_ptr = size_ptr;
    tunnelState->status_ptr = status_ptr;
    tunnelState->client.conn = http->getConn()->clientConnection;
    tunnelState->http = http;
    tunnelState->al = al;

    comm_add_close_handler(tunnelState->client.conn->fd,
                           tunnelClientClosed,
                           tunnelState);

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(tunnelState->client.conn, Config.Timeout.lifetime, timeoutCall);

    peerSelect(&(tunnelState->serverDestinations), request,
               NULL,
               tunnelPeerSelectComplete,
               tunnelState);
}

static void
tunnelRelayConnectRequest(const Comm::ConnectionPointer &srv, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert(!tunnelState->waitingForConnectExchange());
    HttpHeader hdr_out(hoRequest);
    Packer p;
    HttpStateFlags flags;
    debugs(26, 3, HERE << srv << ", tunnelState=" << tunnelState);
    memset(&flags, '\0', sizeof(flags));
    flags.proxying = tunnelState->request->flags.proxying;
    MemBuf mb;
    mb.init();
    mb.Printf("CONNECT %s HTTP/1.1\r\n", tunnelState->url);
    HttpStateData::httpBuildRequestHeader(tunnelState->request.getRaw(),
                                          NULL,			/* StoreEntry */
                                          tunnelState->al,			/* AccessLogEntry */
                                          &hdr_out,
                                          flags);			/* flags */
    packerToMemInit(&p, &mb);
    hdr_out.packInto(&p);
    hdr_out.clean();
    packerClean(&p);
    mb.append("\r\n", 2);

    debugs(11, 2, "Tunnel Server REQUEST: " << tunnelState->server.conn << ":\n----------\n" <<
           Raw("tunnelRelayConnectRequest", mb.content(), mb.contentSize()) << "\n----------");

    if (tunnelState->clientExpectsConnectResponse()) {
        // hack: blindly tunnel peer response (to our CONNECT request) to the client as ours.
        AsyncCall::Pointer writeCall = commCbCall(5,5, "tunnelConnectedWriteDone",
                                       CommIoCbPtrFun(tunnelConnectedWriteDone, tunnelState));
        Comm::Write(srv, &mb, writeCall);
    } else {
        // we have to eat the connect response from the peer (so that the client
        // does not see it) and only then start shoveling data to the client
        AsyncCall::Pointer writeCall = commCbCall(5,5, "tunnelConnectReqWriteDone",
                                       CommIoCbPtrFun(tunnelConnectReqWriteDone,
                                                      tunnelState));
        Comm::Write(srv, &mb, writeCall);
        tunnelState->connectReqWriting = true;

        tunnelState->connectRespBuf = new MemBuf;
        // SQUID_TCP_SO_RCVBUF: we should not accumulate more than regular I/O buffer
        // can hold since any CONNECT response leftovers have to fit into server.buf.
        // 2*SQUID_TCP_SO_RCVBUF: HttpMsg::parse() zero-terminates, which uses space.
        tunnelState->connectRespBuf->init(SQUID_TCP_SO_RCVBUF, 2*SQUID_TCP_SO_RCVBUF);
        tunnelState->readConnectResponse();

        assert(tunnelState->waitingForConnectExchange());
    }

    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "tunnelTimeout",
                                     CommTimeoutCbPtrFun(tunnelTimeout, tunnelState));
    commSetConnTimeout(srv, Config.Timeout.read, timeoutCall);
}

static void
tunnelPeerSelectComplete(Comm::ConnectionList *peer_paths, ErrorState *err, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;

    if (peer_paths == NULL || peer_paths->size() < 1) {
        debugs(26, 3, HERE << "No paths found. Aborting CONNECT");
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

    if (Ip::Qos::TheConfig.isAclTosActive()) {
        tunnelState->serverDestinations[0]->tos = GetTosToServer(tunnelState->request.getRaw());
    }

#if SO_MARK && USE_LIBCAP
    tunnelState->serverDestinations[0]->nfmark = GetNfmarkToServer(tunnelState->request.getRaw());
#endif

    debugs(26, 3, HERE << "paths=" << peer_paths->size() << ", p[0]={" << (*peer_paths)[0] << "}, serverDest[0]={" <<
           tunnelState->serverDestinations[0] << "}");

    AsyncCall::Pointer call = commCbCall(26,3, "tunnelConnectDone", CommConnectCbPtrFun(tunnelConnectDone, tunnelState));
    Comm::ConnOpener *cs = new Comm::ConnOpener(tunnelState->serverDestinations[0], call, Config.Timeout.connect);
    cs->setHost(tunnelState->url);
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
