
/*
 * $Id: ssl.cc,v 1.88 1998/08/20 22:30:01 wessels Exp $
 *
 * DEBUG: section 26    Secure Sockets Layer Proxy
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

typedef struct {
    char *url;
    char *host;			/* either request->host or proxy host */
    u_short port;
    request_t *request;
    struct {
	int fd;
	int len;
	char *buf;
    } client, server;
    size_t *size_ptr;		/* pointer to size in an ConnStateData for logging */
    int proxying;
} SslStateData;

static const char *const conn_established = "HTTP/1.0 200 Connection established\r\n\r\n";

static CNCB sslConnectDone;
static ERCB sslErrorComplete;
static PF sslServerClosed;
static PF sslClientClosed;
static PF sslReadClient;
static PF sslReadServer;
static PF sslTimeout;
static PF sslWriteClient;
static PF sslWriteServer;
static PSC sslPeerSelectComplete;
static PSC sslPeerSelectFail;
static void sslStateFree(SslStateData * sslState);
static void sslConnected(int fd, void *);
static void sslProxyConnected(int fd, void *);
static void sslSetSelect(SslStateData * sslState);
#if DELAY_POOLS
static DEFER sslDeferServerRead;
#endif

static void
sslServerClosed(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslServerClosed: FD %d\n", fd);
    assert(fd == sslState->server.fd);
    sslState->server.fd = -1;
    if (sslState->client.fd == -1)
	sslStateFree(sslState);
}

static void
sslClientClosed(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslClientClosed: FD %d\n", fd);
    assert(fd == sslState->client.fd);
    sslState->client.fd = -1;
    if (sslState->server.fd == -1)
	sslStateFree(sslState);
}

static void
sslStateFree(SslStateData * sslState)
{
    debug(26, 3) ("sslStateFree: sslState=%p\n", sslState);
    assert(sslState != NULL);
    assert(sslState->client.fd == -1);
    assert(sslState->server.fd == -1);
    safe_free(sslState->server.buf);
    safe_free(sslState->client.buf);
    safe_free(sslState->url);
    sslState->host = NULL;
    requestUnlink(sslState->request);
    sslState->request = NULL;
    cbdataFree(sslState);
}

#if DELAY_POOLS
static int
sslDeferServerRead(int fdnotused, void *data)
{
    request_t *r = data;
    return delayBytesWanted(r->delay_id, 0, 1) == 0;
}
#endif

static void
sslSetSelect(SslStateData * sslState)
{
    size_t read_sz = SQUID_TCP_SO_RCVBUF;
    assert(sslState->server.fd > -1 || sslState->client.fd > -1);
    if (sslState->client.fd > -1) {
	if (sslState->server.len > 0) {
	    commSetSelect(sslState->client.fd,
		COMM_SELECT_WRITE,
		sslWriteClient,
		sslState,
		0);
	}
	if (sslState->client.len < read_sz) {
	    commSetSelect(sslState->client.fd,
		COMM_SELECT_READ,
		sslReadClient,
		sslState,
		Config.Timeout.read);
	}
    } else if (sslState->client.len == 0) {
	comm_close(sslState->server.fd);
    }
    if (sslState->server.fd > -1) {
	if (sslState->client.len > 0) {
	    commSetSelect(sslState->server.fd,
		COMM_SELECT_WRITE,
		sslWriteServer,
		sslState,
		0);
	}
#if DELAY_POOLS
	/* If this was allowed to return 0, there would be a possibility
	 * of the socket becoming "hung" with data accumulating but no
	 * write handler (server.len==0) and no read handler (!(0<0)) and
	 * no data flowing in the other direction.  Hence the argument of
	 * 1 as min.
	 */
	read_sz = delayBytesWanted(sslState->request->delay_id, 1, read_sz);
#endif
	if (sslState->server.len < read_sz) {
	    /* Have room to read more */
	    commSetSelect(sslState->server.fd,
		COMM_SELECT_READ,
		sslReadServer,
		sslState,
		Config.Timeout.read);
	}
    } else if (sslState->client.fd == -1) {
	/* client already closed, nothing more to do */
    } else if (sslState->server.len == 0) {
	comm_close(sslState->client.fd);
    }
}

/* Read from server side and queue it for writing to the client */
static void
sslReadServer(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    size_t read_sz = SQUID_TCP_SO_RCVBUF - sslState->server.len;
    assert(fd == sslState->server.fd);
    debug(26, 3) ("sslReadServer: FD %d, reading %d bytes at offset %d\n",
	fd, read_sz, sslState->server.len);
    errno = 0;
#if DELAY_POOLS
    read_sz = delayBytesWanted(sslState->request->delay_id, 1, read_sz);
#endif
    len = read(fd, sslState->server.buf + sslState->server.len, read_sz);
    debug(26, 3) ("sslReadServer: FD %d, read   %d bytes\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
#if DELAY_POOLS
	delayBytesIn(sslState->request->delay_id, len);
#endif
	kb_incr(&Counter.server.all.kbytes_in, len);
	kb_incr(&Counter.server.other.kbytes_in, len);
	sslState->server.len += len;
    }
    cbdataLock(sslState);
    if (len < 0) {
	debug(50, 1) ("sslReadServer: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    } else if (len == 0) {
	comm_close(sslState->server.fd);
    }
    if (cbdataValid(sslState))
	sslSetSelect(sslState);
    cbdataUnlock(sslState);
}

/* Read from client side and queue it for writing to the server */
static void
sslReadClient(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    assert(fd == sslState->client.fd);
    debug(26, 3) ("sslReadClient: FD %d, reading %d bytes at offset %d\n",
	fd, SQUID_TCP_SO_RCVBUF - sslState->client.len,
	sslState->client.len);
    len = read(fd,
	sslState->client.buf + sslState->client.len,
	SQUID_TCP_SO_RCVBUF - sslState->client.len);
    debug(26, 3) ("sslReadClient: FD %d, read   %d bytes\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
	kb_incr(&Counter.client_http.kbytes_in, len);
	sslState->client.len += len;
    }
    cbdataLock(sslState);
    if (len < 0) {
	debug(50, 1) ("sslReadClient: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    } else if (len == 0) {
	comm_close(fd);
    }
    if (cbdataValid(sslState))
	sslSetSelect(sslState);
    cbdataUnlock(sslState);
}

/* Writes data from the client buffer to the server side */
static void
sslWriteServer(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    assert(fd == sslState->server.fd);
    debug(26, 3) ("sslWriteServer: FD %d, %d bytes to write\n",
	fd, sslState->client.len);
    len = write(fd,
	sslState->client.buf,
	sslState->client.len);
    debug(26, 3) ("sslWriteServer: FD %d, %d bytes written\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_WRITE);
	kb_incr(&Counter.server.all.kbytes_out, len);
	kb_incr(&Counter.server.other.kbytes_out, len);
	assert(len <= sslState->client.len);
	sslState->client.len -= len;
	if (sslState->client.len > 0) {
	    /* we didn't write the whole thing */
	    xmemmove(sslState->client.buf,
		sslState->client.buf + len,
		sslState->client.len);
	}
    }
    cbdataLock(sslState);
    if (len < 0) {
	debug(50, 1) ("sslWriteServer: FD %d: write failure: %s.\n",
	    fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    }
    if (cbdataValid(sslState))
	sslSetSelect(sslState);
    cbdataUnlock(sslState);
}

/* Writes data from the server buffer to the client side */
static void
sslWriteClient(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    assert(fd == sslState->client.fd);
    debug(26, 3) ("sslWriteClient: FD %d, %d bytes to write\n",
	fd, sslState->server.len);
    len = write(fd,
	sslState->server.buf,
	sslState->server.len);
    debug(26, 3) ("sslWriteClient: FD %d, %d bytes written\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_WRITE);
	kb_incr(&Counter.client_http.kbytes_out, len);
	assert(len <= sslState->server.len);
	sslState->server.len -= len;
	/* increment total object size */
	if (sslState->size_ptr)
	    *sslState->size_ptr += len;
	if (sslState->server.len > 0) {
	    /* we didn't write the whole thing */
	    xmemmove(sslState->server.buf,
		sslState->server.buf + len,
		sslState->server.len);
	}
    }
    cbdataLock(sslState);
    if (len < 0) {
	debug(50, 1) ("sslWriteClient: FD %d: write failure: %s.\n",
	    fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    }
    if (cbdataValid(sslState))
	sslSetSelect(sslState);
    cbdataUnlock(sslState);
}

static void
sslTimeout(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslTimeout: FD %d\n", fd);
    if (sslState->client.fd > -1)
	comm_close(sslState->client.fd);
    if (sslState->server.fd > -1)
	comm_close(sslState->server.fd);
}

static void
sslConnected(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslConnected: FD %d sslState=%p\n", fd, sslState);
    xstrncpy(sslState->server.buf, conn_established, SQUID_TCP_SO_RCVBUF);
    sslState->server.len = strlen(conn_established);
    sslSetSelect(sslState);
}

static void
sslErrorComplete(int fdnotused, void *data, size_t sizenotused)
{
    SslStateData *sslState = data;
    assert(sslState != NULL);
    if (sslState->client.fd > -1)
	comm_close(sslState->client.fd);
    if (sslState->server.fd > -1)
	comm_close(sslState->server.fd);
}


static void
sslConnectDone(int fdnotused, int status, void *data)
{
    SslStateData *sslState = data;
    request_t *request = sslState->request;
    ErrorState *err = NULL;
    if (status == COMM_ERR_DNS) {
	debug(26, 4) ("sslConnect: Unknown host: %s\n", sslState->host);
	err = errorCon(ERR_DNS_FAIL, HTTP_NOT_FOUND);
	err->request = requestLink(request);
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->callback = sslErrorComplete;
	err->callback_data = sslState;
	errorSend(sslState->client.fd, err);
    } else if (status != COMM_OK) {
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->host = xstrdup(sslState->host);
	err->port = sslState->port;
	err->request = requestLink(request);
	err->callback = sslErrorComplete;
	err->callback_data = sslState;
	errorSend(sslState->client.fd, err);
    } else {
	if (sslState->proxying)
	    sslProxyConnected(sslState->server.fd, sslState);
	else
	    sslConnected(sslState->server.fd, sslState);
	commSetTimeout(sslState->server.fd,
	    Config.Timeout.read,
	    sslTimeout,
	    sslState);
#if DELAY_POOLS
	commSetDefer(sslState->server.fd, sslDeferServerRead, sslState->request);
#endif
    }
}

void
sslStart(int fd, const char *url, request_t * request, size_t * size_ptr)
{
    /* Create state structure. */
    SslStateData *sslState = NULL;
    int sock;
    ErrorState *err = NULL;
    debug(26, 3) ("sslStart: '%s %s'\n",
	RequestMethodStr[request->method], url);
    Counter.server.all.requests++;
    Counter.server.other.requests++;
    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(26, 4) ("sslStart: Failed because we're out of sockets.\n");
	err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->request = requestLink(request);
	errorSend(fd, err);
	return;
    }
    sslState = xcalloc(1, sizeof(SslStateData));
    cbdataAdd(sslState, MEM_NONE);
    sslState->url = xstrdup(url);
    sslState->request = requestLink(request);
    sslState->size_ptr = size_ptr;
    sslState->client.fd = fd;
    sslState->server.fd = sock;
    sslState->server.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    sslState->client.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    comm_add_close_handler(sslState->server.fd,
	sslServerClosed,
	sslState);
    comm_add_close_handler(sslState->client.fd,
	sslClientClosed,
	sslState);
    commSetTimeout(sslState->client.fd,
	Config.Timeout.lifetime,
	sslTimeout,
	sslState);
    commSetTimeout(sslState->server.fd,
	Config.Timeout.connect,
	sslTimeout,
	sslState);
    peerSelect(request,
	NULL,
	sslPeerSelectComplete,
	sslPeerSelectFail,
	sslState);
    /*
     * Disable the client read handler until peer selection is complete
     * Take control away from client_side.c.
     */
    commSetSelect(sslState->client.fd, COMM_SELECT_READ, NULL, NULL, 0);
}

static void
sslProxyConnected(int fd, void *data)
{
    SslStateData *sslState = data;
    MemBuf mb;
    HttpHeader hdr_out;
    Packer p;
    debug(26, 3) ("sslProxyConnected: FD %d sslState=%p\n", fd, sslState);
    memBufDefInit(&mb);
    memBufPrintf(&mb, "CONNECT %s HTTP/1.0\r\n", sslState->url);
    httpBuildRequestHeader(sslState->request,
	sslState->request,
	NULL,			/* StoreEntry */
	&hdr_out,
	sslState->client.fd,
	0);			/* flags */
    packerToMemInit(&p, &mb);
    httpHeaderPackInto(&hdr_out, &p);
    httpHeaderClean(&hdr_out);
    packerClean(&p);
    memBufAppend(&mb, "\r\n", 2);
    xstrncpy(sslState->client.buf, mb.buf, SQUID_TCP_SO_RCVBUF);
    debug(26, 3) ("sslProxyConnected: Sending {%s}\n", sslState->client.buf);
    sslState->client.len = mb.size;
    memBufClean(&mb);
    commSetTimeout(sslState->server.fd,
	Config.Timeout.read,
	sslTimeout,
	sslState);
    sslSetSelect(sslState);
}

static void
sslPeerSelectComplete(peer * p, void *data)
{
    SslStateData *sslState = data;
    request_t *request = sslState->request;
    peer *g = NULL;
    sslState->proxying = p ? 1 : 0;
    sslState->host = p ? p->host : request->host;
    if (p == NULL) {
	sslState->port = request->port;
    } else if (p->http_port != 0) {
	sslState->port = p->http_port;
    } else if ((g = peerFindByName(p->host))) {
	sslState->port = g->http_port;
    } else {
	sslState->port = CACHE_HTTP_PORT;
    }
    commConnectStart(sslState->server.fd,
	sslState->host,
	sslState->port,
	sslConnectDone,
	sslState);
}

static void
sslPeerSelectFail(peer * peernotused, void *data)
{
    SslStateData *sslState = data;
    ErrorState *err;
    err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE);
    err->request = requestLink(sslState->request);
    err->callback = sslErrorComplete;
    err->callback_data = sslState;
    errorSend(sslState->client.fd, err);

}
