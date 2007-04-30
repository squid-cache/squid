
/*
 * $Id: tunnel.cc,v 1.168 2007/04/30 16:56:09 wessels Exp $
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
#include "ACLChecklist.h"
#if DELAY_POOLS
#include "DelayId.h"
#endif
#include "client_side.h"
#include "MemBuf.h"
#include "http.h"

class SslStateData
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
        Connection() : len (0),buf ((char *)xmalloc(SQUID_TCP_SO_RCVBUF)), size_ptr(NULL), fd_(-1){}

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
        size_t *size_ptr;		/* pointer to size in an ConnStateData for logging */

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
    CBDATA_CLASS(SslStateData);
    void copy (size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to, IOCB *);
    void readServer(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void readClient(char *buf, size_t len, comm_err_t errcode, int xerrno);
    void writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno);
    void writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno);
};

static const char *const conn_established = "HTTP/1.0 200 Connection established\r\n\r\n";

static CNCB sslConnectDone;
static ERCB sslErrorComplete;
static PF sslServerClosed;
static PF sslClientClosed;
static PF sslTimeout;
static PSC sslPeerSelectComplete;
static void sslStateFree(SslStateData * sslState);
static void sslConnected(int fd, void *);
static void sslProxyConnected(int fd, void *);

static void
sslServerClosed(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    debugs(26, 3, "sslServerClosed: FD " << fd);
    assert(fd == sslState->server.fd());
    sslState->server.fd(-1);

    if (sslState->noConnections())
        sslStateFree(sslState);
}

static void
sslClientClosed(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    debugs(26, 3, "sslClientClosed: FD " << fd);
    assert(fd == sslState->client.fd());
    sslState->client.fd(-1);

    if (sslState->noConnections())
        sslStateFree(sslState);
}

static void
sslStateFree(SslStateData * sslState)
{
    debugs(26, 3, "sslStateFree: sslState=" << sslState);
    assert(sslState != NULL);
    assert(sslState->noConnections());
    safe_free(sslState->url);
    FwdState::serversFree(&sslState->servers);
    sslState->host = NULL;
    HTTPMSGUNLOCK(sslState->request);
    delete sslState;
}

SslStateData::Connection::~Connection()
{
    safe_free (buf);
}

int
SslStateData::Connection::bytesWanted(int lowerbound, int upperbound) const
{
#if DELAY_POOLS
    return delayId.bytesWanted(lowerbound, upperbound);
#else

    return upperbound;
#endif
}

void
SslStateData::Connection::bytesIn(int const &count)
{
#if DELAY_POOLS
    delayId.bytesIn(count);
#endif

    len += count;
}

int
SslStateData::Connection::debugLevelForError(int const xerrno) const
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
SslStateData::ReadServer(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    assert (cbdataReferenceValid (sslState));

    assert(fd == sslState->server.fd());
    sslState->readServer(buf, len, errcode, xerrno);
}

void
SslStateData::readServer(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    /*
     * Bail out early on COMM_ERR_CLOSING
     * - close handlers will tidy up for us 
     */

    if (errcode == COMM_ERR_CLOSING)
        return;

    debugs(26, 3, "sslReadServer: FD " << server.fd() << ", read   " << len << " bytes");

    if (len > 0) {
        server.bytesIn(len);
        kb_incr(&statCounter.server.all.kbytes_in, len);
        kb_incr(&statCounter.server.other.kbytes_in, len);
    }

    copy (len, errcode, xerrno, server, client, WriteClientDone);
}

void
SslStateData::Connection::error(int const xerrno)
{
    /* XXX fixme xstrerror and xerrno... */
    errno = xerrno;

    if (xerrno == COMM_ERR_CLOSING)
        return;

    debugs(50, debugLevelForError(xerrno), "sslReadServer: FD " << fd() << 
           ": read failure: " << xstrerror());

    if (!ignoreErrno(xerrno))
        comm_close(fd());
}

/* Read from client side and queue it for writing to the server */
void
SslStateData::ReadClient(int fd, char *buf, size_t len, comm_err_t errcode, int xerrno, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    assert (cbdataReferenceValid (sslState));

    assert(fd == sslState->client.fd());
    sslState->readClient(buf, len, errcode, xerrno);
}

void
SslStateData::readClient(char *buf, size_t len, comm_err_t errcode, int xerrno)
{
    /*
     * Bail out early on COMM_ERR_CLOSING
     * - close handlers will tidy up for us 
     */

    if (errcode == COMM_ERR_CLOSING)
        return;

    debugs(26, 3, "sslReadClient: FD " << client.fd() << ", read " << len << " bytes");

    if (len > 0) {
        client.bytesIn(len);
        kb_incr(&statCounter.client_http.kbytes_in, len);
    }

    copy (len, errcode, xerrno, client, server, WriteServerDone);
}

void
SslStateData::copy (size_t len, comm_err_t errcode, int xerrno, Connection &from, Connection &to, IOCB *completion)
{
    /* I think this is to prevent free-while-in-a-callback behaviour
     * - RBC 20030229 
     */
    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    if (len < 0 || errcode)
        from.error (xerrno);
    else if (len == 0 || to.fd() == -1) {
        comm_close(from.fd());
        /* Only close the remote end if we've finished queueing data to it */

        if (from.len == 0 && to.fd() != -1) {
            comm_close(to.fd());
        }
    } else if (cbdataReferenceValid(this))
        comm_write(to.fd(), from.buf, len, completion, this, NULL);

    cbdataInternalUnlock(this);	/* ??? */
}

/* Writes data from the client buffer to the server side */
void
SslStateData::WriteServerDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    assert (cbdataReferenceValid (sslState));

    assert(fd == sslState->server.fd());
    sslState->writeServerDone(buf, len, flag, xerrno);
}

void
SslStateData::writeServerDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "sslWriteServer: FD " << server.fd() << ", " << len << " bytes written");

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
    if (client.fd() == -1) {
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
SslStateData::WriteClientDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    assert (cbdataReferenceValid (sslState));

    assert(fd == sslState->client.fd());
    sslState->writeClientDone(buf, len, flag, xerrno);
}

void
SslStateData::Connection::dataSent (size_t amount)
{
    assert(amount == (size_t)len);
    len =0;
    /* increment total object size */

    if (size_ptr)
        *size_ptr += amount;
}

void
SslStateData::writeClientDone(char *buf, size_t len, comm_err_t flag, int xerrno)
{
    debugs(26, 3, "sslWriteClient: FD " << client.fd() << ", " << len << " bytes written");

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
    if (server.fd() == -1) {
        comm_close(client.fd());
        return;
    }

    cbdataInternalLock(this);	/* ??? should be locked by the caller... */

    if (cbdataReferenceValid(this))
        copyRead(server, ReadServer);

    cbdataInternalUnlock(this);	/* ??? */
}

static void
sslTimeout(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    debugs(26, 3, "sslTimeout: FD " << fd);
    /* Temporary lock to protect our own feets (comm_close -> sslClientClosed -> Free) */
    cbdataInternalLock(sslState);

    sslState->client.closeIfOpen();
    sslState->server.closeIfOpen();
    cbdataInternalUnlock(sslState);
}

void
SslStateData::Connection::closeIfOpen()
{
    if (fd() != -1)
        comm_close(fd());
}

void
SslStateData::copyRead(Connection &from, IOCB *completion)
{
    assert(from.len == 0);
    comm_read(from.fd(), from.buf, from.bytesWanted(1, SQUID_TCP_SO_RCVBUF), completion, this);
}

static void
sslConnectTimeout(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    HttpRequest *request = sslState->request;
    ErrorState *err = NULL;

    if (sslState->servers->_peer)
        hierarchyNote(&sslState->request->hier, sslState->servers->code,
                      sslState->servers->_peer->host);
    else if (Config.onoff.log_ip_on_direct)
        hierarchyNote(&sslState->request->hier, sslState->servers->code,
                      fd_table[sslState->server.fd()].ipaddr);
    else
        hierarchyNote(&sslState->request->hier, sslState->servers->code,
                      sslState->host);

    comm_close(fd);

    err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);

    *sslState->status_ptr = HTTP_SERVICE_UNAVAILABLE;

    err->xerrno = ETIMEDOUT;

    err->port = sslState->port;

    err->callback = sslErrorComplete;

    err->callback_data = sslState;

    errorSend(sslState->client.fd(), err);
}

static void
sslConnectedWriteDone(int fd, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    SslStateData *sslState = (SslStateData *)data;

    if (flag != COMM_OK) {
        sslErrorComplete(fd, data, 0);
        return;
    }

    if (cbdataReferenceValid(sslState)) {
        sslState->copyRead(sslState->server, SslStateData::ReadServer);
        sslState->copyRead(sslState->client, SslStateData::ReadClient);
    }
}

/*
 * handle the write completion from a proxy request to an upstream proxy
 */
static void
sslProxyConnectedWriteDone(int fd, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    sslConnectedWriteDone(fd, buf, size, flag, xerrno, data);
}

static void
sslConnected(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    debugs(26, 3, "sslConnected: FD " << fd << " sslState=" << sslState);
    *sslState->status_ptr = HTTP_OK;
    comm_write(sslState->client.fd(), conn_established, strlen(conn_established),
               sslConnectedWriteDone, sslState, NULL);
}

static void
sslErrorComplete(int fdnotused, void *data, size_t sizenotused)
{
    SslStateData *sslState = (SslStateData *)data;
    assert(sslState != NULL);
    /* temporary lock to save our own feets (comm_close -> sslClientClosed -> Free) */
    cbdataInternalLock(sslState);

    if (sslState->client.fd() > -1)
        comm_close(sslState->client.fd());

    if (sslState->server.fd() > -1)
        comm_close(sslState->server.fd());

    cbdataInternalUnlock(sslState);
}


static void
sslConnectDone(int fdnotused, comm_err_t status, int xerrno, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    HttpRequest *request = sslState->request;
    ErrorState *err = NULL;

    if (sslState->servers->_peer)
        hierarchyNote(&sslState->request->hier, sslState->servers->code,
                      sslState->servers->_peer->host);
    else if (Config.onoff.log_ip_on_direct)
        hierarchyNote(&sslState->request->hier, sslState->servers->code,
                      fd_table[sslState->server.fd()].ipaddr);
    else
        hierarchyNote(&sslState->request->hier, sslState->servers->code,
                      sslState->host);

    if (status == COMM_ERR_DNS) {
        debugs(26, 4, "sslConnect: Unknown host: " << sslState->host);
        err = errorCon(ERR_DNS_FAIL, HTTP_NOT_FOUND, request);
        *sslState->status_ptr = HTTP_NOT_FOUND;
        err->dnsserver_msg = xstrdup(dns_error_message);
        err->callback = sslErrorComplete;
        err->callback_data = sslState;
        errorSend(sslState->client.fd(), err);
    } else if (status != COMM_OK) {
        err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
        *sslState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
        err->xerrno = xerrno;
        err->port = sslState->port;
        err->callback = sslErrorComplete;
        err->callback_data = sslState;
        errorSend(sslState->client.fd(), err);
    } else {
        if (sslState->servers->_peer)
            sslProxyConnected(sslState->server.fd(), sslState);
        else {
            sslConnected(sslState->server.fd(), sslState);
        }

        commSetTimeout(sslState->server.fd(),
                       Config.Timeout.read,
                       sslTimeout,
                       sslState);
    }
}

void
sslStart(ClientHttpRequest * http, size_t * size_ptr, int *status_ptr)
{
    /* Create state structure. */
    SslStateData *sslState = NULL;
    int sock;
    ErrorState *err = NULL;
    int answer;
    int fd = http->getConn()->fd;
    HttpRequest *request = http->request;
    char *url = http->uri;
    /*
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if (request->client_addr.s_addr != no_addr.s_addr) {
        /*
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         */
        ACLChecklist ch;
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        ch.my_port = request->my_port;
        ch.request = HTTPMSGLOCK(request);
        ch.accessList = cbdataReference(Config.accessList.miss);
        /* cbdataReferenceDone() happens in either fastCheck() or ~ACLCheckList */
        answer = ch.fastCheck();

        if (answer == 0) {
            err = errorCon(ERR_FORWARDING_DENIED, HTTP_FORBIDDEN, request);
            *status_ptr = HTTP_FORBIDDEN;
            errorSend(fd, err);
            return;
        }
    }

    debugs(26, 3, "sslStart: '" << RequestMethodStr[request->method] << " " << url << "'");
    statCounter.server.all.requests++;
    statCounter.server.other.requests++;
    /* Create socket. */
    sock = comm_openex(SOCK_STREAM,
                       IPPROTO_TCP,
                       getOutgoingAddr(request),
                       0,
                       COMM_NONBLOCKING,
                       getOutgoingTOS(request),
                       url);

    if (sock == COMM_ERROR) {
        debugs(26, 4, "sslStart: Failed because we're out of sockets.");
        err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        *status_ptr = HTTP_INTERNAL_SERVER_ERROR;
        err->xerrno = errno;
        errorSend(fd, err);
        return;
    }

    sslState = new SslStateData;
#if DELAY_POOLS

    sslState->server.setDelayId(DelayId::DelayClient(http));
#endif

    sslState->url = xstrdup(url);
    sslState->request = HTTPMSGLOCK(request);
    sslState->server.size_ptr = size_ptr;
    sslState->status_ptr = status_ptr;
    sslState->client.fd(fd);
    sslState->server.fd(sock);
    comm_add_close_handler(sslState->server.fd(),
                           sslServerClosed,
                           sslState);
    comm_add_close_handler(sslState->client.fd(),
                           sslClientClosed,
                           sslState);
    commSetTimeout(sslState->client.fd(),
                   Config.Timeout.lifetime,
                   sslTimeout,
                   sslState);
    commSetTimeout(sslState->server.fd(),
                   Config.Timeout.connect,
                   sslConnectTimeout,
                   sslState);
    peerSelect(request,
               NULL,
               sslPeerSelectComplete,
               sslState);
    /*
     * Disable the client read handler until peer selection is complete
     * Take control away from client_side.c.
     */
    commSetSelect(sslState->client.fd(), COMM_SELECT_READ, NULL, NULL, 0);
}

static void
sslProxyConnected(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    HttpHeader hdr_out(hoRequest);
    Packer p;
    http_state_flags flags;
    debugs(26, 3, "sslProxyConnected: FD " << fd << " sslState=" << sslState);
    memset(&flags, '\0', sizeof(flags));
    flags.proxying = sslState->request->flags.proxying;
    MemBuf mb;
    mb.init();
    mb.Printf("CONNECT %s HTTP/1.0\r\n", sslState->url);
    HttpStateData::httpBuildRequestHeader(sslState->request,
                                          sslState->request,
                                          NULL,			/* StoreEntry */
                                          &hdr_out,
                                          flags);			/* flags */
    packerToMemInit(&p, &mb);
    hdr_out.packInto(&p);
    hdr_out.clean();
    packerClean(&p);
    mb.append("\r\n", 2);

    comm_write_mbuf(sslState->server.fd(), &mb, sslProxyConnectedWriteDone, sslState);
    commSetTimeout(sslState->server.fd(), Config.Timeout.read, sslTimeout, sslState);
}

static void
sslPeerSelectComplete(FwdServer * fs, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    HttpRequest *request = sslState->request;
    peer *g = NULL;

    if (fs == NULL) {
        ErrorState *err;
        err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, request);
        *sslState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
        err->callback = sslErrorComplete;
        err->callback_data = sslState;
        errorSend(sslState->client.fd(), err);
        return;
    }

    sslState->servers = fs;
    sslState->host = fs->_peer ? fs->_peer->host : request->host;

    if (fs->_peer == NULL) {
        sslState->port = request->port;
    } else if (fs->_peer->http_port != 0) {
        sslState->port = fs->_peer->http_port;
    } else if ((g = peerFindByName(fs->_peer->host))) {
        sslState->port = g->http_port;
    } else {
        sslState->port = CACHE_HTTP_PORT;
    }

    if (fs->_peer) {
        sslState->request->peer_login = fs->_peer->login;
        sslState->request->flags.proxying = 1;
    } else {
        sslState->request->peer_login = NULL;
        sslState->request->flags.proxying = 0;
    }

#if DELAY_POOLS
    /* no point using the delayIsNoDelay stuff since ssl is nice and simple */
    if (g && g->options.no_delay)
        sslState->server.setDelayId(DelayId());

#endif

    commConnectStart(sslState->server.fd(),
                     sslState->host,
                     sslState->port,
                     sslConnectDone,
                     sslState);
}

CBDATA_CLASS_INIT(SslStateData);

void *
SslStateData::operator new (size_t)
{
    CBDATA_INIT_TYPE(SslStateData);
    SslStateData *result = cbdataAlloc(SslStateData);
    return result;
}

void
SslStateData::operator delete (void *address)
{
    SslStateData *t = static_cast<SslStateData *>(address);
    cbdataFree(t);
}

void
SslStateData::Connection::fd(int const newFD)
{
    fd_ = newFD;
}

bool
SslStateData::noConnections() const
{
    return (server.fd() == -1) && (client.fd() == -1);
}

#if DELAY_POOLS
void
SslStateData::Connection::setDelayId(DelayId const &newDelay)
{
    delayId = newDelay;
}

#endif
