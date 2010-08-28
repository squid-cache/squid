/*
 * $Id$
 *
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
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "client_side.h"
#include "client_side_request.h"
#if DELAY_POOLS
#include "DelayId.h"
#endif
#include "errorpage.h"
#include "fde.h"
#include "HttpRequest.h"
#include "http.h"
#include "MemBuf.h"
#include "PeerSelectState.h"

class TunnelStateData
{

public:

    class Connection;
    void *operator new(size_t);
    void operator delete (void *);
    static void ReadClient(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    static void ReadServer(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    static void WriteClientDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data);
    static void WriteServerDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data);

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
#if DELAY_POOLS

        void setDelayId(DelayId const &);
#endif

        void error(int const xerrno);
        int debugLevelForError(int const xerrno) const;
        void closeIfOpen();
        void dataSent(size_t amount);
        int len;
        char *buf;
        int64_t *size_ptr;		/* pointer to size in an ConnStateData for logging */

        Comm::ConnectionPointer conn;    ///< The currently connected connection.

    private:
#if DELAY_POOLS

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

static const char *const conn_established = "HTTP/1.0 200 Connection established\r\n\r\n";

static CNCB tunnelConnectDone;
static ERCB tunnelErrorComplete;
static PF tunnelServerClosed;
static PF tunnelClientClosed;
static PF tunnelTimeout;
static PSC tunnelPeerSelectComplete;
static void tunnelStateFree(TunnelStateData * tunnelState);
static void tunnelConnected(Comm::ConnectionPointer &server, void *);
static void tunnelRelayConnectRequest(Comm::ConnectionPointer &server, void *);

static void
tunnelServerClosed(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, "tunnelServerClosed: FD " << fd);
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
tunnelClientClosed(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, "tunnelClientClosed: FD " << fd);
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
    debugs(26, 3, "tunnelStateFree: tunnelState=" << tunnelState);
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
#if DELAY_POOLS
    return delayId.bytesWanted(lowerbound, upperbound);
#else

    return upperbound;
#endif
}

void
TunnelStateData::Connection::bytesIn(int const &count)
{
#if DELAY_POOLS
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
TunnelStateData::ReadServer(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    assert(errcode == COMM_ERR_CLOSING || fd == tunnelState->server.conn->fd);
    tunnelState->readServer(buf, len, errcode, xerrno);
}

void
TunnelStateData::readServer(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    /*
     * Bail out early on COMM_ERR_CLOSING
     * - close handlers will tidy up for us
     */

    if (errcode == COMM_ERR_CLOSING)
        return;

    debugs(26, 3, "tunnelReadServer: FD " << server.conn->fd << ", read   " << len << " bytes");

    if (len > 0) {
        server.bytesIn(len);
        kb_incr(&statCounter.server.all.kbytes_in, len);
        kb_incr(&statCounter.server.other.kbytes_in, len);
    }

    copy (len, errcode, xerrno, server, client, WriteClientDone);
}

void
TunnelStateData::Connection::error(int const xerrno)
{
    /* XXX fixme xstrerror and xerrno... */
    errno = xerrno;

    debugs(50, debugLevelForError(xerrno), "TunnelStateData::Connection::error: FD " << conn->fd <<
           ": read/write failure: " << xstrerror());

    if (!ignoreErrno(xerrno))
        conn->close();
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadClient(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    tunnelState->readClient(buf, len, errcode, xerrno);
}

void
TunnelStateData::readClient(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    /*
     * Bail out early on COMM_ERR_CLOSING
     * - close handlers will tidy up for us
     */

    if (errcode == COMM_ERR_CLOSING)
        return;

    debugs(26, 3, "tunnelReadClient: FD " << client.conn << ", read " << len << " bytes");

    if (len > 0) {
        client.bytesIn(len);
        kb_incr(&statCounter.client_http.kbytes_in, len);
    }

    copy(len, errcode, xerrno, client, server, WriteServerDone);
}

void
TunnelStateData::copy(size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to, IOCB *completion)
{
    /* I think this is to prevent free-while-in-a-callback behaviour
     * - RBC 20030229
     * from.conn->close() / to.conn->close() done here trigger close callbacks which may free TunnelStateData
     */
    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    /* Bump the source connection read timeout on any activity */
    if (Comm::IsConnOpen(from.conn))
        commSetTimeout(from.conn->fd, Config.Timeout.read, tunnelTimeout, this);

    if (len < 0 || errcode)
        from.error (xerrno);
    else if (len == 0 || !Comm::IsConnOpen(to.conn)) {
        from.conn->close();

        /* Only close the remote end if we've finished queueing data to it */
        if (from.len == 0 && Comm::IsConnOpen(to.conn) ) {
            to.conn->close();
        }
    } else if (cbdataReferenceValid(this))
        comm_write(to.conn->fd, from.buf, len, completion, this, NULL);

    cbdataInternalUnlock(this);	/* ??? */
}

/* Writes data from the client buffer to the server side */
void
TunnelStateData::WriteServerDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    assert(fd == tunnelState->server.conn->fd);
    tunnelState->writeServerDone(buf, len, flag, xerrno);
}

void
TunnelStateData::writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "tunnelWriteServer: FD " << server.conn->fd << ", " << len << " bytes written");

    if (flag == COMM_ERR_CLOSING)
        return;

    /* Error? */
    if (len < 0 || flag != COMM_OK) {
        server.error(xerrno); // may call comm_close
        return;
    }

    /* EOF? */
    if (len == 0) {
        server.conn->close();
        return;
    }

    /* Valid data */
    kb_incr(&statCounter.server.all.kbytes_out, len);
    kb_incr(&statCounter.server.other.kbytes_out, len);
    client.dataSent(len);

    /* If the other end has closed, so should we */
    if (!Comm::IsConnOpen(client.conn)) {
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
TunnelStateData::WriteClientDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    assert(fd == tunnelState->client.conn->fd);
    tunnelState->writeClientDone(buf, len, flag, xerrno);
}

void
TunnelStateData::Connection::dataSent (size_t amount)
{
    assert(amount == (size_t)len);
    len =0;
    /* increment total object size */

    if (size_ptr)
        *size_ptr += amount;
}

void
TunnelStateData::writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "tunnelWriteClient: FD " << client.conn->fd << ", " << len << " bytes written");

    if (flag == COMM_ERR_CLOSING)
        return;

    /* Error? */
    if (len < 0 || flag != COMM_OK) {
        client.error(xerrno); // may call comm_close
        return;
    }

    /* EOF? */
    if (len == 0) {
        client.conn->close();
        return;
    }

    /* Valid data */
    kb_incr(&statCounter.client_http.kbytes_out, len);
    server.dataSent(len);

    /* If the other end has closed, so should we */
    if (!Comm::IsConnOpen(server.conn)) {
        client.conn->close();
        return;
    }

    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyRead(server, ReadServer);

    cbdataInternalUnlock(this);	/* ??? */
}

static void
tunnelTimeout(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, "tunnelTimeout: FD " << fd);
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
    comm_read(from.conn->fd, from.buf, from.bytesWanted(1, SQUID_TCP_SO_RCVBUF), completion, this);
}

static void
tunnelConnectedWriteDone(int fd, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;

    if (flag != COMM_OK) {
        tunnelErrorComplete(fd, data, 0);
        return;
    }

    if (cbdataReferenceValid(tunnelState)) {
        tunnelState->copyRead(tunnelState->server, TunnelStateData::ReadServer);
        tunnelState->copyRead(tunnelState->client, TunnelStateData::ReadClient);
    }
}

static void
tunnelConnected(Comm::ConnectionPointer &server, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, HERE << "FD " << server->fd << " tunnelState=" << tunnelState);
    *tunnelState->status_ptr = HTTP_OK;
    comm_write(tunnelState->client.conn->fd, conn_established, strlen(conn_established),
               tunnelConnectedWriteDone, tunnelState, NULL);
}

static void
tunnelErrorComplete(int fdnotused, void *data, size_t sizenotused)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
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
tunnelConnectDone(Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    HttpRequest *request = tunnelState->request;
    ErrorState *err = NULL;

#if DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (conn->getPeer() && conn->getPeer()->options.no_delay)
        tunnelState->server.setDelayId(DelayId());
#endif

    if (conn != NULL && conn->getPeer())
        hierarchyNote(&tunnelState->request->hier, conn->peerType, conn->getPeer()->host);
    else if (Config.onoff.log_ip_on_direct)
        hierarchyNote(&tunnelState->request->hier, conn->peerType, fd_table[conn->fd].ipaddr);
    else
        hierarchyNote(&tunnelState->request->hier, conn->peerType, tunnelState->getHost());

    // TODO: merge this into hierarchyNote with a conn parameter instead of peerType
    request->hier.peer_local_port = conn->local.GetPort(); // for %<lp logging

    if (status != COMM_OK) {
        /* At this point only the TCP handshake has failed. no data has been passed.
         * we are allowed to re-try the TCP-level connection to alternate IPs for CONNECT.
         */
        tunnelState->serverDestinations.shift();
        if (status != COMM_TIMEOUT && tunnelState->serverDestinations.size() > 0) {
            /* Try another IP of this destination host */
            AsyncCall::Pointer call = commCbCall(26,3, "tunnelConnectDone", CommConnectCbPtrFun(tunnelConnectDone, tunnelState));
            Comm::ConnOpener *cs = new Comm::ConnOpener(tunnelState->serverDestinations[0], call, Config.Timeout.connect);
            cs->setHost(tunnelState->url);
            AsyncJob::Start(cs);
        } else {
            err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
            *tunnelState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
            err->xerrno = xerrno;
            // on timeout is this still:    err->xerrno = ETIMEDOUT;
            err->port = conn->remote.GetPort();
            err->callback = tunnelErrorComplete;
            err->callback_data = tunnelState;
            errorSend(tunnelState->client.conn->fd, err);
        }
        return;
    }

    tunnelState->server.conn = conn;
    request->peer_host = conn->getPeer() ? conn->getPeer()->host : NULL;
    comm_add_close_handler(conn->fd, tunnelServerClosed, tunnelState);

    if (conn->getPeer()) {
        tunnelState->request->peer_login = conn->getPeer()->login;
        tunnelState->request->flags.proxying = 1;
    } else {
        tunnelState->request->peer_login = NULL;
        tunnelState->request->flags.proxying = 0;
    }

    if (conn->getPeer())
        tunnelRelayConnectRequest(conn, tunnelState);
    else {
        tunnelConnected(conn, tunnelState);
    }

    commSetTimeout(conn->fd, Config.Timeout.read, tunnelTimeout, tunnelState);
}

void
tunnelStart(ClientHttpRequest * http, int64_t * size_ptr, int *status_ptr)
{
    /* Create state structure. */
    TunnelStateData *tunnelState = NULL;
    ErrorState *err = NULL;
    int answer;
    HttpRequest *request = http->request;
    char *url = http->uri;

    /*
     * client_addr.IsNoAddr()  indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if (!request->client_addr.IsNoAddr() && Config.accessList.miss) {
        /*
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         * default is to allow.
         */
        ACLFilledChecklist ch(Config.accessList.miss, request, NULL);
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        answer = ch.fastCheck();

        if (answer == 0) {
            err = errorCon(ERR_FORWARDING_DENIED, HTTP_FORBIDDEN, request);
            *status_ptr = HTTP_FORBIDDEN;
            errorSend(http->getConn()->clientConn->fd, err);
            return;
        }
    }

    debugs(26, 3, "tunnelStart: '" << RequestMethodStr(request->method) << " " << url << "'");
    statCounter.server.all.requests++;
    statCounter.server.other.requests++;

    tunnelState = new TunnelStateData;
#if DELAY_POOLS
    tunnelState->server.setDelayId(DelayId::DelayClient(http));
#endif
    tunnelState->url = xstrdup(url);
    tunnelState->request = HTTPMSGLOCK(request);
    tunnelState->server.size_ptr = size_ptr;
    tunnelState->status_ptr = status_ptr;
    tunnelState->client.conn = http->getConn()->clientConn;

    comm_add_close_handler(tunnelState->client.conn->fd,
                           tunnelClientClosed,
                           tunnelState);
    commSetTimeout(tunnelState->client.conn->fd,
                   Config.Timeout.lifetime,
                   tunnelTimeout,
                   tunnelState);

    peerSelect(&(tunnelState->serverDestinations), request,
               NULL,
               tunnelPeerSelectComplete,
               tunnelState);
}

static void
tunnelRelayConnectRequest(Comm::ConnectionPointer &server, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    HttpHeader hdr_out(hoRequest);
    Packer p;
    http_state_flags flags;
    debugs(26, 3, HERE << "FD " << server->fd << " tunnelState=" << tunnelState);
    memset(&flags, '\0', sizeof(flags));
    flags.proxying = tunnelState->request->flags.proxying;
    MemBuf mb;
    mb.init();
    mb.Printf("CONNECT %s HTTP/1.1\r\n", tunnelState->url);
    HttpStateData::httpBuildRequestHeader(tunnelState->request,
                                          tunnelState->request,
                                          NULL,			/* StoreEntry */
                                          &hdr_out,
                                          flags);			/* flags */
    packerToMemInit(&p, &mb);
    hdr_out.packInto(&p);
    hdr_out.clean();
    packerClean(&p);
    mb.append("\r\n", 2);

    comm_write_mbuf(tunnelState->server.conn->fd, &mb, tunnelConnectedWriteDone, tunnelState);
    commSetTimeout(tunnelState->server.conn->fd, Config.Timeout.read, tunnelTimeout, tunnelState);
}

static void
tunnelPeerSelectComplete(Comm::ConnectionList *peer_paths, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;

    if (peer_paths == NULL || peer_paths->size() < 1) {
        ErrorState *err;
        err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, tunnelState->request);
        *tunnelState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
        err->callback = tunnelErrorComplete;
        err->callback_data = tunnelState;
        errorSend(tunnelState->client.conn->fd, err);
        return;
    }

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

#if DELAY_POOLS
void
TunnelStateData::Connection::setDelayId(DelayId const &newDelay)
{
    delayId = newDelay;
}

#endif
