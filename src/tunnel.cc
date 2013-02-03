
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
#include "Array.h"
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

class TunnelStateData
{

public:

    class Connection;
    void *operator new(size_t);
    void operator delete (void *);
    static void ReadClient(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    static void ReadServer(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    static void WriteClientDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t flag, int xerrno, void *data);
    static void WriteServerDone(const Comm::ConnectionPointer &, char *buf, size_t len, comm_err_t flag, int xerrno, void *data);

    bool noConnections() const;
    char *url;
    HttpRequest *request;
    Comm::ConnectionList serverDestinations;

    const char * getHost() const {
        return (server.conn != NULL && server.conn->getPeer() ? server.conn->getPeer()->host : request->GetHost());
    };

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
    void copyRead(Connection &from, IOCB *completion);

private:
    CBDATA_CLASS(TunnelStateData);
    void copy (size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to, IOCB *);
    void readServer(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void readClient(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno);
    void writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno);
};

static const char *const conn_established = "HTTP/1.1 200 Connection established\r\n\r\n";

static CNCB tunnelConnectDone;
static ERCB tunnelErrorComplete;
static CLCB tunnelServerClosed;
static CLCB tunnelClientClosed;
static CTCB tunnelTimeout;
static PSC tunnelPeerSelectComplete;
static void tunnelStateFree(TunnelStateData * tunnelState);
static void tunnelConnected(const Comm::ConnectionPointer &server, void *);
static void tunnelRelayConnectRequest(const Comm::ConnectionPointer &server, void *);

static void
tunnelServerClosed(const CommCloseCbParams &params)
{
    TunnelStateData *tunnelState = (TunnelStateData *)params.data;
    debugs(26, 3, HERE << tunnelState->server.conn);
    tunnelState->server.conn = NULL;

    if (tunnelState->noConnections()) {
        tunnelStateFree(tunnelState);
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
        tunnelStateFree(tunnelState);
        return;
    }

    if (!tunnelState->client.len) {
        tunnelState->server.conn->close();
        return;
    }
}

static void
tunnelStateFree(TunnelStateData * tunnelState)
{
    debugs(26, 3, HERE << "tunnelState=" << tunnelState);
    assert(tunnelState != NULL);
    assert(tunnelState->noConnections());
    safe_free(tunnelState->url);
    tunnelState->serverDestinations.clean();
    HTTPMSGUNLOCK(tunnelState->request);
    delete tunnelState;
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

    copy (len, errcode, xerrno, server, client, WriteClientDone);
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

    copy (len, errcode, xerrno, client, server, WriteServerDone);
}

void
TunnelStateData::copy (size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to, IOCB *completion)
{
    debugs(26, 3, HERE << "from={" << from.conn << "}, to={" << to.conn << "}");

    /* I think this is to prevent free-while-in-a-callback behaviour
     * - RBC 20030229
     * from.conn->close() / to.conn->close() done here trigger close callbacks which may free TunnelStateData
     */
    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

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
        debugs(26, 3, HERE << "Schedule Write");
        AsyncCall::Pointer call = commCbCall(5,5, "TunnelBlindCopyWriteHandler",
                                             CommIoCbPtrFun(completion, this));
        Comm::Write(to.conn, from.buf, len, call, NULL);
    }

    cbdataInternalUnlock(this);	/* ??? */
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

    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyRead(client, ReadClient);

    cbdataInternalUnlock(this);	/* ??? */
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

    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyRead(server, ReadServer);

    cbdataInternalUnlock(this);	/* ??? */
}

static void
tunnelTimeout(const CommTimeoutCbParams &io)
{
    TunnelStateData *tunnelState = static_cast<TunnelStateData *>(io.data);
    debugs(26, 3, HERE << io.conn);
    /* Temporary lock to protect our own feets (comm_close -> tunnelClientClosed -> Free) */
    cbdataInternalLock(tunnelState);

    tunnelState->client.closeIfOpen();
    tunnelState->server.closeIfOpen();
    cbdataInternalUnlock(tunnelState);
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

/**
 * Set the HTTP status for this request and sets the read handlers for client
 * and server side connections.
 */
static void
tunnelStartShoveling(TunnelStateData *tunnelState)
{
    *tunnelState->status_ptr = HTTP_OK;
    if (cbdataReferenceValid(tunnelState)) {
        tunnelState->copyRead(tunnelState->server, TunnelStateData::ReadServer);
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
        *tunnelState->status_ptr = HTTP_INTERNAL_SERVER_ERROR;
        tunnelErrorComplete(conn->fd, data, 0);
        return;
    }

    tunnelStartShoveling(tunnelState);
}

/*
 * handle the write completion from a proxy request to an upstream origin
 */
static void
tunnelConnected(const Comm::ConnectionPointer &server, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, HERE << server << ", tunnelState=" << tunnelState);

    if (tunnelState->request && (tunnelState->request->flags.spoofClientIp || tunnelState->request->flags.intercepted))
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
    cbdataInternalLock(tunnelState);

    if (Comm::IsConnOpen(tunnelState->client.conn))
        tunnelState->client.conn->close();

    if (Comm::IsConnOpen(tunnelState->server.conn))
        tunnelState->server.conn->close();

    cbdataInternalUnlock(tunnelState);
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
                tunnelState->serverDestinations[0]->tos = GetTosToServer(tunnelState->request);
            }

#if SO_MARK && USE_LIBCAP
            tunnelState->serverDestinations[0]->nfmark = GetNfmarkToServer(tunnelState->request);
#endif

            debugs(26, 4, HERE << "retry with : " << tunnelState->serverDestinations[0]);
            AsyncCall::Pointer call = commCbCall(26,3, "tunnelConnectDone", CommConnectCbPtrFun(tunnelConnectDone, tunnelState));
            Comm::ConnOpener *cs = new Comm::ConnOpener(tunnelState->serverDestinations[0], call, Config.Timeout.connect);
            cs->setHost(tunnelState->url);
            AsyncJob::Start(cs);
        } else {
            debugs(26, 4, HERE << "terminate with error.");
            ErrorState *err = new ErrorState(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, tunnelState->request);
            *tunnelState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
            err->xerrno = xerrno;
            // on timeout is this still:    err->xerrno = ETIMEDOUT;
            err->port = conn->remote.GetPort();
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
        tunnelState->request->flags.proxying = (conn->getPeer()->options.originserver?0:1);
    } else {
        tunnelState->request->peer_login = NULL;
        tunnelState->request->flags.proxying = 0;
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
tunnelStart(ClientHttpRequest * http, int64_t * size_ptr, int *status_ptr)
{
    debugs(26, 3, HERE);
    /* Create state structure. */
    TunnelStateData *tunnelState = NULL;
    ErrorState *err = NULL;
    HttpRequest *request = http->request;
    char *url = http->uri;

    /*
     * client_addr.IsNoAddr()  indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if (Config.accessList.miss && !request->client_addr.IsNoAddr()) {
        /*
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         * default is to allow.
         */
        ACLFilledChecklist ch(Config.accessList.miss, request, NULL);
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        if (ch.fastCheck() == ACCESS_DENIED) {
            debugs(26, 4, HERE << "MISS access forbidden.");
            err = new ErrorState(ERR_FORWARDING_DENIED, HTTP_FORBIDDEN, request);
            *status_ptr = HTTP_FORBIDDEN;
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
    tunnelState->request = HTTPMSGLOCK(request);
    tunnelState->server.size_ptr = size_ptr;
    tunnelState->status_ptr = status_ptr;
    tunnelState->client.conn = http->getConn()->clientConnection;

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
    HttpHeader hdr_out(hoRequest);
    Packer p;
    HttpStateFlags flags;
    debugs(26, 3, HERE << srv << ", tunnelState=" << tunnelState);
    memset(&flags, '\0', sizeof(flags));
    flags.proxying = tunnelState->request->flags.proxying;
    MemBuf mb;
    mb.init();
    mb.Printf("CONNECT %s HTTP/1.1\r\n", tunnelState->url);
    HttpStateData::httpBuildRequestHeader(tunnelState->request,
                                          NULL,			/* StoreEntry */
                                          NULL,			/* AccessLogEntry */
                                          &hdr_out,
                                          flags);			/* flags */
    packerToMemInit(&p, &mb);
    hdr_out.packInto(&p);
    hdr_out.clean();
    packerClean(&p);
    mb.append("\r\n", 2);

    AsyncCall::Pointer writeCall = commCbCall(5,5, "tunnelConnectedWriteDone",
                                   CommIoCbPtrFun(tunnelConnectedWriteDone, tunnelState));
    Comm::Write(srv, &mb, writeCall);

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
            err = new ErrorState(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, tunnelState->request);
        }
        *tunnelState->status_ptr = err->httpStatus;
        err->callback = tunnelErrorComplete;
        err->callback_data = tunnelState;
        errorSend(tunnelState->client.conn, err);
        return;
    }
    delete err;

    if (Ip::Qos::TheConfig.isAclTosActive()) {
        tunnelState->serverDestinations[0]->tos = GetTosToServer(tunnelState->request);
    }

#if SO_MARK && USE_LIBCAP
    tunnelState->serverDestinations[0]->nfmark = GetNfmarkToServer(tunnelState->request);
#endif

    debugs(26, 3, HERE << "paths=" << peer_paths->size() << ", p[0]={" << (*peer_paths)[0] << "}, serverDest[0]={" <<
           tunnelState->serverDestinations[0] << "}");

    AsyncCall::Pointer call = commCbCall(26,3, "tunnelConnectDone", CommConnectCbPtrFun(tunnelConnectDone, tunnelState));
    Comm::ConnOpener *cs = new Comm::ConnOpener(tunnelState->serverDestinations[0], call, Config.Timeout.connect);
    cs->setHost(tunnelState->url);
    AsyncJob::Start(cs);
}

CBDATA_CLASS_INIT(TunnelStateData);

void *
TunnelStateData::operator new (size_t)
{
    CBDATA_INIT_TYPE(TunnelStateData);
    TunnelStateData *result = cbdataAlloc(TunnelStateData);
    return result;
}

void
TunnelStateData::operator delete (void *address)
{
    TunnelStateData *t = static_cast<TunnelStateData *>(address);
    cbdataFree(t);
}

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
