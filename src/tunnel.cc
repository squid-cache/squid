
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
    char *host;			/* either request->host or proxy host */
    u_short port;
    HttpRequest *request;
    FwdServer *servers;

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
        int len;
        char *buf;
        int64_t *size_ptr;		/* pointer to size in an ConnStateData for logging */

    private:
        int fd_;
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

    if (tunnelState->noConnections()) {
        tunnelStateFree(tunnelState);
        return;
    }

    if (!tunnelState->server.len) {
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

    if (tunnelState->noConnections()) {
        tunnelStateFree(tunnelState);
        return;
    }

    if (!tunnelState->client.len) {
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
    tunnelState->host = NULL;
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

    copy (len, errcode, xerrno, server, client, WriteClientDone);
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

    copy (len, errcode, xerrno, client, server, WriteServerDone);
}

void
TunnelStateData::copy (size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to, IOCB *completion)
{
    /* I think this is to prevent free-while-in-a-callback behaviour
     * - RBC 20030229
     */
    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    /* Bump the server connection timeout on any activity */
    if (!fd_closed(server.fd()))
        commSetTimeout(server.fd(), Config.Timeout.read, tunnelTimeout, this);

    if (len < 0 || errcode)
        from.error (xerrno);
    else if (len == 0 || fd_closed(to.fd())) {
        comm_close(from.fd());
        /* Only close the remote end if we've finished queueing data to it */

        if (from.len == 0 && !fd_closed(to.fd()) ) {
            comm_close(to.fd());
        }
    } else if (cbdataReferenceValid(this))
        comm_write(to.fd(), from.buf, len, completion, this, NULL);

    cbdataInternalUnlock(this);	/* ??? */
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

    if (flag == COMM_ERR_CLOSING)
        return;

    /* Error? */
    if (len < 0 || flag != COMM_OK) {
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
TunnelStateData::writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "tunnelWriteClient: FD " << client.fd() << ", " << len << " bytes written");

    if (flag == COMM_ERR_CLOSING)
        return;

    /* Error? */
    if (len < 0 || flag != COMM_OK) {
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
                          tunnelState->servers->_peer->host);
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
    tunnelConnectedWriteDone(fd, buf, size, flag, xerrno, data);
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

    if (fd_closed(tunnelState->server.fd()))
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
                      tunnelState->servers->_peer->host);
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
        if (tunnelState->servers->_peer)
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
    /*
     * Disable the client read handler until peer selection is complete
     * Take control away from client_side.c.
     */
    commSetSelect(tunnelState->client.fd(), COMM_SELECT_READ, NULL, NULL, 0);
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
    commSetTimeout(tunnelState->server.fd(), Config.Timeout.read, tunnelTimeout, tunnelState);
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
    tunnelState->host = fs->_peer ? fs->_peer->host : xstrdup(request->GetHost());

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
        tunnelState->request->flags.proxying = 1;
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
    return result;
}

void
TunnelStateData::operator delete (void *address)
{
    TunnelStateData *t = static_cast<TunnelStateData *>(address);
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
