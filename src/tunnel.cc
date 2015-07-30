
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
#include "errorpage.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "fde.h"
#include "comm.h"
#include "client_side_request.h"
#include "acl/FilledChecklist.h"
#if DELAY_POOLS
#include "DelayId.h"
#endif
#include "client_side.h"
#include "MemBuf.h"
#include "http.h"
#include "ip/tools.h"

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

    /// Starts reading peer response to our CONNECT request.
    void readConnectResponse();

    /// Called when we may be done handling a CONNECT exchange with the peer.
    void connectExchangeCheckpoint();

    bool noConnections() const;
    char *url;
    char *host;			/* either request->host or proxy host */
    unsigned short port;
    HttpRequest *request;
    FwdServer *servers;

    /// Whether we are writing a CONNECT request to a peer.
    bool waitingForConnectRequest() const { return connectReqWriting; }
    /// Whether we are reading a CONNECT response from a peer.
    bool waitingForConnectResponse() const { return connectRespBuf; }
    /// Whether we are waiting for the CONNECT request/response exchange with the peer.
    bool waitingForConnectExchange() const { return waitingForConnectRequest() || waitingForConnectResponse(); }

    /// Whether the client sent a CONNECT request to us.
    bool clientExpectsConnectResponse() const {
        return !(request != NULL &&
		 (request->flags.spoof_client_ip || request->flags.intercepted));
    }

    /// Sends "502 Bad Gateway" error response to the client,
    /// if it is waiting for Squid CONNECT response, closing connections.
    void informUserOfPeerError(const char *errMsg);

    class Connection
    {

    public:
        Connection() : len (0),buf ((char *)xmalloc(SQUID_TCP_SO_RCVBUF)), size_ptr(NULL), fd_(-1) {}

        ~Connection();
        int const & fd() const { return fd_;}

        void fd(int const newFD);
        int bytesWanted(int lower=0, int upper = INT_MAX) const;
        void bytesIn(int const &);
#if DELAY_POOLS

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
        int64_t *size_ptr;		/* pointer to size in an ConnStateData for logging */
        AsyncCall::Pointer writer; ///< pending Comm::Write callback

    private:
        int fd_;
#if DELAY_POOLS

        DelayId delayId;
#endif

    };

    Connection client, server;
    int *status_ptr;		/* pointer to status for logging */
    MemBuf *connectRespBuf; ///< accumulates peer CONNECT response when we need it
    bool connectReqWriting; ///< whether we are writing a CONNECT request to a peer

    void copyRead(Connection &from, IOCB *completion);

private:
    CBDATA_CLASS(TunnelStateData);
    bool keepGoingAfterRead(size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to);
    void copy (size_t len, Connection &from, Connection &to, IOCB *);
    void handleConnectResponse(const size_t chunkSize);
    void readServer(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void readClient(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno);
    void writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno);

    static void ReadConnectResponseDone(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data);
    void readConnectResponseDone(char *buf, size_t len, comm_err_t errcode, int xerrno);
};

#define fd_closed(fd) (fd == -1 || fd_table[fd].closing())

static const char *const conn_established = "HTTP/1.0 200 Connection established\r\n\r\n";

static CNCB tunnelConnectDone;
static ERCB tunnelErrorComplete;
static PF tunnelServerClosed;
static PF tunnelClientClosed;
static PF tunnelTimeout;
static PSC tunnelPeerSelectComplete;
static void tunnelStateFree(TunnelStateData * tunnelState);
static void tunnelConnected(int fd, void *);
static void tunnelProxyConnected(int fd, void *);

static void
tunnelServerClosed(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, "tunnelServerClosed: FD " << fd);
    assert(fd == tunnelState->server.fd());
    tunnelState->server.fd(-1);
    tunnelState->server.writer = NULL;

    if (tunnelState->noConnections()) {
        tunnelStateFree(tunnelState);
        return;
    }

    if (!tunnelState->client.writer) {
        comm_close(tunnelState->client.fd());
        return;
    }
}

static void
tunnelClientClosed(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, "tunnelClientClosed: FD " << fd);
    assert(fd == tunnelState->client.fd());
    tunnelState->client.fd(-1);
    tunnelState->client.writer = NULL;

    if (tunnelState->noConnections()) {
        tunnelStateFree(tunnelState);
        return;
    }

    if (!tunnelState->server.writer) {
        comm_close(tunnelState->server.fd());
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
    FwdState::serversFree(&tunnelState->servers);
    safe_free(tunnelState->host);
    HTTPMSGUNLOCK(tunnelState->request);
    delete tunnelState;
}

TunnelStateData::Connection::~Connection()
{
    safe_free (buf);
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

    assert(fd == tunnelState->server.fd());
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

    debugs(26, 3, "tunnelReadServer: FD " << server.fd() << ", read   " << len << " bytes");

    if (len > 0) {
        server.bytesIn(len);
        kb_incr(&statCounter.server.all.kbytes_in, len);
        kb_incr(&statCounter.server.other.kbytes_in, len);
    }

    if (keepGoingAfterRead(len, errcode, xerrno, server, client))
        copy (len, server, client, WriteClientDone);
}

/// Called when we read [a part of] CONNECT response from the peer
void
TunnelStateData::readConnectResponseDone(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    debugs(26, 3, server.fd() << ", read " << len << " bytes, err=" << errcode);
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

void
TunnelStateData::informUserOfPeerError(const char *errMsg)
{
    server.len = 0;
    if (!clientExpectsConnectResponse()) {
        // closing the connection is the best we can do here
        debugs(50, 3, server.fd() << " closing on error: " << errMsg);
        close(server.fd());
        return;
    }
    ErrorState *err = errorCon(ERR_CONNECT_FAIL, HTTP_BAD_GATEWAY, request);
    err->callback = tunnelErrorComplete;
    err->callback_data = this;
    *status_ptr = HTTP_BAD_GATEWAY;
    errorSend(client.fd(), err);
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadConnectResponseDone(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
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
    HttpReply *rep = new HttpReply;
    http_status parseErr = HTTP_STATUS_NONE;
    int eof = !chunkSize;
    const bool parsed = rep->parse(connectRespBuf, eof, &parseErr);
    if (!parsed) {
        if (parseErr > 0) { // unrecoverable parsing error
            informUserOfPeerError("malformed CONNECT response from peer");
            return;
        }

        // need more data
        assert(!eof);
        assert(!parseErr);

        if (!connectRespBuf->hasSpace()) {
            informUserOfPeerError("huge CONNECT response from peer");
            return;
        }

        // keep reading
        readConnectResponse();
        return;
    }

    // CONNECT response was successfully parsed
    *status_ptr = rep->sline.status;

    // bail if we did not get an HTTP 200 (Connection Established) response
    if (rep->sline.status != HTTP_OK) {
        informUserOfPeerError("unsupported CONNECT response status code");
        return;
    }

    if (rep->hdr_sz < connectRespBuf->contentSize()) {
        // preserve bytes that the server already sent after the CONNECT response
        server.len = connectRespBuf->contentSize() - rep->hdr_sz;
        memcpy(server.buf, connectRespBuf->content() + rep->hdr_sz, server.len);
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
    /* XXX fixme xstrerror and xerrno... */
    errno = xerrno;

    debugs(50, debugLevelForError(xerrno), "TunnelStateData::Connection::error: FD " << fd() <<
           ": read/write failure: " << xstrerror());

    if (!ignoreErrno(xerrno))
        comm_close(fd());
}

/* Read from client side and queue it for writing to the server */
void
TunnelStateData::ReadClient(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    assert(fd == tunnelState->client.fd());
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

    debugs(26, 3, "tunnelReadClient: FD " << client.fd() << ", read " << len << " bytes");

    if (len > 0) {
        client.bytesIn(len);
        kb_incr(&statCounter.client_http.kbytes_in, len);
    }

    if (keepGoingAfterRead(len, errcode, xerrno, client, server)) 
        copy (len, client, server, WriteServerDone);
}

/// Updates state after reading from client or server.
/// Returns whether the caller should use the data just read.
bool
TunnelStateData::keepGoingAfterRead(size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to)
{
    /* I think this is to prevent free-while-in-a-callback behaviour
     * - RBC 20030229
     */
    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    /* Bump the source connection timeout on any activity */
    if (!fd_closed(from.fd()))
        commSetTimeout(from.fd(), Config.Timeout.read, tunnelTimeout, this);

    /* Bump the dest connection read timeout on any activity */
    /* see Bug 3659: tunnels can be weird, with very long one-way transfers */
    if (!fd_closed(to.fd()))
        commSetTimeout(to.fd(), Config.Timeout.read, tunnelTimeout, this);

    if (errcode)
        from.error (xerrno);
    else if (len == 0 || fd_closed(to.fd())) {
        comm_close(from.fd());
        /* Only close the remote end if we've finished queueing data to it */

        if (from.len == 0 && !fd_closed(to.fd()) ) {
            comm_close(to.fd());
        }
    } else if (cbdataReferenceValid(this)) {
    	cbdataInternalUnlock(this);	/* ??? */
	return true;
    }

    cbdataInternalUnlock(this);	/* ??? */
    return false;
}

void
TunnelStateData::copy (size_t len, Connection &from, Connection &to, IOCB *completion)
{
    debugs(26, 3, HERE << "Schedule Write");
    AsyncCall::Pointer call = commCbCall(5,5, "TunnelBlindCopyWriteHandler",
                                         CommIoCbPtrFun(completion, this));
    to.write(from.buf, len, call, NULL);
}

/* Writes data from the client buffer to the server side */
void
TunnelStateData::WriteServerDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert (cbdataReferenceValid (tunnelState));

    assert(fd == tunnelState->server.fd());
    tunnelState->writeServerDone(buf, len, flag, xerrno);
}

void
TunnelStateData::writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "tunnelWriteServer: FD " << server.fd() << ", " << len << " bytes written");

    /* Error? */
    if (flag != COMM_OK) {
        if (flag != COMM_ERR_CLOSING)
            server.error(xerrno); // may call comm_close
        return;
    }

    /* EOF? */
    if (len == 0) {
        comm_close(server.fd());
        return;
    }

    /* Valid data */
    kb_incr(&statCounter.server.all.kbytes_out, len);
    kb_incr(&statCounter.server.other.kbytes_out, len);
    client.dataSent(len);

    /* If the other end has closed, so should we */
    if (fd_closed(client.fd())) {
        comm_close(server.fd());
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

    assert(fd == tunnelState->client.fd());
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
TunnelStateData::Connection::write(const char *b, int size, AsyncCall::Pointer &callback, FREE * free_func)
{
    writer = callback;
    comm_write(fd(), b, size, callback, free_func);
}

void
TunnelStateData::writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "tunnelWriteClient: FD " << client.fd() << ", " << len << " bytes written");

    /* Error? */
    if (flag != COMM_OK) {
        if (flag != COMM_ERR_CLOSING)
            client.error(xerrno); // may call comm_close
        return;
    }

    /* EOF? */
    if (len == 0) {
        comm_close(client.fd());
        return;
    }

    /* Valid data */
    kb_incr(&statCounter.client_http.kbytes_out, len);
    server.dataSent(len);

    /* If the other end has closed, so should we */
    if (fd_closed(server.fd())) {
        comm_close(client.fd());
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
    if (!fd_closed(fd()))
        comm_close(fd());
}

void
TunnelStateData::copyRead(Connection &from, IOCB *completion)
{
    assert(from.len == 0);
    comm_read(from.fd(), from.buf, from.bytesWanted(1, SQUID_TCP_SO_RCVBUF), completion, this);
}

static void
tunnelConnectTimeout(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    HttpRequest *request = tunnelState->request;
    ErrorState *err = NULL;

    if (tunnelState->servers) {
        if (tunnelState->servers->_peer)
            hierarchyNote(&tunnelState->request->hier, tunnelState->servers->code,
                          tunnelState->servers->_peer->name);
        else if (Config.onoff.log_ip_on_direct)
            hierarchyNote(&tunnelState->request->hier, tunnelState->servers->code,
                          fd_table[tunnelState->server.fd()].ipaddr);
        else
            hierarchyNote(&tunnelState->request->hier, tunnelState->servers->code,
                          tunnelState->host);
    } else
        debugs(26, 1, "tunnelConnectTimeout(): tunnelState->servers is NULL");

    err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);

    *tunnelState->status_ptr = HTTP_SERVICE_UNAVAILABLE;

    err->xerrno = ETIMEDOUT;

    err->port = tunnelState->port;

    err->callback = tunnelErrorComplete;

    err->callback_data = tunnelState;

    errorSend(tunnelState->client.fd(), err);
    comm_close(fd);
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

/*
 * handle the write completion from a proxy request to an upstream proxy
 */
static void
tunnelProxyConnectedWriteDone(int fd, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, fd << ", flag=" << flag);
    tunnelState->server.writer = NULL;
    assert(tunnelState->waitingForConnectRequest());

    if (flag != COMM_OK) {
        *tunnelState->status_ptr = HTTP_INTERNAL_SERVER_ERROR;
        tunnelErrorComplete(fd, data, 0);
        return;
    }

    tunnelState->connectReqWriting = false;
    tunnelState->connectExchangeCheckpoint();
}

void
TunnelStateData::connectExchangeCheckpoint()
{
    if (waitingForConnectResponse()) {
        debugs(26, 5, "still reading CONNECT response on " << server.fd());
    } else if (waitingForConnectRequest()) {
        debugs(26, 5, "still writing CONNECT request on " << server.fd());
    } else {
        assert(!waitingForConnectExchange());
        debugs(26, 3, "done with CONNECT exchange on " << server.fd());
        tunnelConnected(server.fd(), this);
    }
}

static void
tunnelConnected(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    debugs(26, 3, "tunnelConnected: FD " << fd << " tunnelState=" << tunnelState);
    *tunnelState->status_ptr = HTTP_OK;
    comm_write(tunnelState->client.fd(), conn_established, strlen(conn_established),
               tunnelConnectedWriteDone, tunnelState, NULL);
}

static void
tunnelErrorComplete(int fdnotused, void *data, size_t sizenotused)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    assert(tunnelState != NULL);
    /* temporary lock to save our own feets (comm_close -> tunnelClientClosed -> Free) */
    cbdataInternalLock(tunnelState);

    if (!fd_closed(tunnelState->client.fd()))
        comm_close(tunnelState->client.fd());

    if (!fd_closed(tunnelState->server.fd()))
        comm_close(tunnelState->server.fd());

    cbdataInternalUnlock(tunnelState);
}


static void
tunnelConnectDone(int fdnotused, const DnsLookupDetails &dns, comm_err_t status, int xerrno, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    HttpRequest *request = tunnelState->request;
    ErrorState *err = NULL;

    request->recordLookup(dns);

    if (tunnelState->servers->_peer)
        hierarchyNote(&tunnelState->request->hier, tunnelState->servers->code,
                      tunnelState->servers->_peer->name);
    else if (Config.onoff.log_ip_on_direct)
        hierarchyNote(&tunnelState->request->hier, tunnelState->servers->code,
                      fd_table[tunnelState->server.fd()].ipaddr);
    else
        hierarchyNote(&tunnelState->request->hier, tunnelState->servers->code,
                      tunnelState->host);

    if (status == COMM_ERR_DNS) {
        debugs(26, 4, "tunnelConnect: Unknown host: " << tunnelState->host);
        err = errorCon(ERR_DNS_FAIL, HTTP_NOT_FOUND, request);
        *tunnelState->status_ptr = HTTP_NOT_FOUND;
        err->dnsError = dns.error;
        err->callback = tunnelErrorComplete;
        err->callback_data = tunnelState;
        errorSend(tunnelState->client.fd(), err);
    } else if (status != COMM_OK) {
        err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
        *tunnelState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
        err->xerrno = xerrno;
        err->port = tunnelState->port;
        err->callback = tunnelErrorComplete;
        err->callback_data = tunnelState;
        errorSend(tunnelState->client.fd(), err);
    } else {
        if (tunnelState->servers->_peer && !tunnelState->servers->_peer->options.originserver)
            tunnelProxyConnected(tunnelState->server.fd(), tunnelState);
        else {
            tunnelConnected(tunnelState->server.fd(), tunnelState);
        }

        commSetTimeout(tunnelState->server.fd(),
                       Config.Timeout.read,
                       tunnelTimeout,
                       tunnelState);
    }
}

void
tunnelStart(ClientHttpRequest * http, int64_t * size_ptr, int *status_ptr)
{
    /* Create state structure. */
    TunnelStateData *tunnelState = NULL;
    int sock;
    ErrorState *err = NULL;
    int answer;
    int fd = http->getConn()->fd;
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
            errorSend(fd, err);
            return;
        }
    }

    debugs(26, 3, "tunnelStart: '" << RequestMethodStr(request->method) << " " << url << "'");
    statCounter.server.all.requests++;
    statCounter.server.other.requests++;
    /* Create socket. */
    IpAddress temp = getOutgoingAddr(request,NULL);

    // if IPv6 is disabled try to force IPv4-only outgoing.
    if (!Ip::EnableIpv6 && !temp.SetIPv4()) {
        debugs(50, 4, "tunnelStart: IPv6 is Disabled. Tunnel failed from " << temp);
        ErrorState *anErr = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
        anErr->xerrno = EAFNOSUPPORT;
        errorSend(fd, anErr);
        return;
    }

    // if IPv6 is split-stack, prefer IPv4
    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK) {
        // NP: This is not a great choice of default,
        // but with the current Internet being IPv4-majority has a higher success rate.
        // if setting to IPv4 fails we dont care, that just means to use IPv6 outgoing.
        temp.SetIPv4();
    }

    int flags = COMM_NONBLOCKING;
    if (request->flags.spoof_client_ip) {
        flags |= COMM_TRANSPARENT;
    }
    sock = comm_openex(SOCK_STREAM,
                       IPPROTO_TCP,
                       temp,
                       flags,
                       getOutgoingTOS(request),
                       url);

    if (sock == COMM_ERROR) {
        debugs(26, 4, "tunnelStart: Failed because we're out of sockets.");
        err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        *status_ptr = HTTP_INTERNAL_SERVER_ERROR;
        err->xerrno = errno;
        errorSend(fd, err);
        return;
    }

    // record local IP:port for %<la and %<lp logging
    if (comm_local_port(sock))
        request->hier.peer_local_addr = fd_table[sock].local_addr;

    tunnelState = new TunnelStateData;
#if DELAY_POOLS

    tunnelState->server.setDelayId(DelayId::DelayClient(http));
#endif

    tunnelState->url = xstrdup(url);
    tunnelState->request = HTTPMSGLOCK(request);
    tunnelState->server.size_ptr = size_ptr;
    tunnelState->status_ptr = status_ptr;
    tunnelState->client.fd(fd);
    tunnelState->server.fd(sock);
    comm_add_close_handler(tunnelState->server.fd(),
                           tunnelServerClosed,
                           tunnelState);
    comm_add_close_handler(tunnelState->client.fd(),
                           tunnelClientClosed,
                           tunnelState);
    commSetTimeout(tunnelState->client.fd(),
                   Config.Timeout.lifetime,
                   tunnelTimeout,
                   tunnelState);
    commSetTimeout(tunnelState->server.fd(),
                   Config.Timeout.connect,
                   tunnelConnectTimeout,
                   tunnelState);
    peerSelect(request,
               NULL,
               tunnelPeerSelectComplete,
               tunnelState);
}

static void
tunnelProxyConnected(int fd, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    HttpHeader hdr_out(hoRequest);
    Packer p;
    http_state_flags flags;
    debugs(26, 3, "tunnelProxyConnected: FD " << fd << " tunnelState=" << tunnelState);
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

    comm_write_mbuf(tunnelState->server.fd(), &mb, tunnelProxyConnectedWriteDone, tunnelState);
    tunnelState->connectReqWriting = true;

    tunnelState->connectRespBuf = new MemBuf;
    // SQUID_TCP_SO_RCVBUF: we should not accumulate more than regular I/O buffer
    // can hold since any CONNECT response leftovers have to fit into server.buf.
    // 2*SQUID_TCP_SO_RCVBUF: HttpMsg::parse() zero-terminates, which uses space.
    tunnelState->connectRespBuf->init(SQUID_TCP_SO_RCVBUF, 2*SQUID_TCP_SO_RCVBUF);

    // Start accumulating answer
    tunnelState->readConnectResponse();

    commSetTimeout(tunnelState->server.fd(), Config.Timeout.read, tunnelTimeout, tunnelState);
}

void
TunnelStateData::readConnectResponse()
{
    assert(waitingForConnectResponse());

    AsyncCall::Pointer call = commCbCall(5,4, "readConnectResponseDone",
                                         CommIoCbPtrFun(ReadConnectResponseDone, this));
    comm_read(server.fd(), connectRespBuf->space(),
              server.bytesWanted(1, connectRespBuf->spaceSize()), call);
}

static void
tunnelPeerSelectComplete(FwdServer * fs, void *data)
{
    TunnelStateData *tunnelState = (TunnelStateData *)data;
    HttpRequest *request = tunnelState->request;
    peer *g = NULL;

    if (fs == NULL) {
        ErrorState *err;
        err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, request);
        *tunnelState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
        err->callback = tunnelErrorComplete;
        err->callback_data = tunnelState;
        errorSend(tunnelState->client.fd(), err);
        return;
    }

    tunnelState->servers = fs;
    tunnelState->host = fs->_peer ? xstrdup(fs->_peer->host) : xstrdup(request->GetHost());

    if (fs->_peer == NULL) {
        tunnelState->port = request->port;
    } else if (fs->_peer->http_port != 0) {
        tunnelState->port = fs->_peer->http_port;
    } else if ((g = peerFindByName(fs->_peer->host))) {
        tunnelState->port = g->http_port;
    } else {
        tunnelState->port = CACHE_HTTP_PORT;
    }

    if (fs->_peer) {
        tunnelState->request->peer_login = fs->_peer->login;
        tunnelState->request->flags.proxying = (fs->_peer->options.originserver?0:1);
    } else {
        tunnelState->request->peer_login = NULL;
        tunnelState->request->flags.proxying = 0;
    }

#if DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since tunnel is nice and simple */
    if (g && g->options.no_delay)
        tunnelState->server.setDelayId(DelayId());

#endif

    commConnectStart(tunnelState->server.fd(),
                     tunnelState->host,
                     tunnelState->port,
                     tunnelConnectDone,
                     tunnelState);
}

CBDATA_CLASS_INIT(TunnelStateData);

void *
TunnelStateData::operator new (size_t)
{
    CBDATA_INIT_TYPE(TunnelStateData);
    TunnelStateData *result = cbdataAlloc(TunnelStateData);
    result->connectReqWriting = false;
    result->connectRespBuf = NULL;
    return result;
}

void
TunnelStateData::operator delete (void *address)
{
    TunnelStateData *t = static_cast<TunnelStateData *>(address);
    delete t->connectRespBuf;
    cbdataFree(t);
}

void
TunnelStateData::Connection::fd(int const newFD)
{
    fd_ = newFD;
}

bool
TunnelStateData::noConnections() const
{
    return fd_closed(server.fd()) && fd_closed(client.fd());
}

#if DELAY_POOLS
void
TunnelStateData::Connection::setDelayId(DelayId const &newDelay)
{
    delayId = newDelay;
}

#endif
