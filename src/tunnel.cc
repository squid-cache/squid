
/*
 * $Id: tunnel.cc,v 1.55 1997/06/18 01:43:45 wessels Exp $
 *
 * DEBUG: section 26    Secure Sockets Layer Proxy
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
	int offset;
	char *buf;
    } client, server;
    time_t timeout;
    int *size_ptr;		/* pointer to size in an ConnStateData for logging */
    int proxying;
} SslStateData;

static const char *const conn_established = "HTTP/1.0 200 Connection established\r\n\r\n";

static PF sslTimeout;
static void sslReadServer _PARAMS((int fd, void *));
static void sslReadClient _PARAMS((int fd, void *));
static void sslWriteServer _PARAMS((int fd, void *));
static void sslWriteClient _PARAMS((int fd, void *));
static void sslConnected _PARAMS((int fd, void *));
static void sslProxyConnected _PARAMS((int fd, void *));
static void sslErrorComplete _PARAMS((int, char *, int, int, void *));
static void sslClose _PARAMS((SslStateData * sslState));
static void sslClientClosed _PARAMS((int fd, void *));
static void sslConnectDone _PARAMS((int fd, int status, void *data));
static void sslStateFree _PARAMS((int fd, void *data));
static void sslPeerSelectComplete _PARAMS((peer * p, void *data));
static void sslPeerSelectFail _PARAMS((peer * p, void *data));

static void
sslClose(SslStateData * sslState)
{
    if (sslState->client.fd > -1) {
	/* remove the "unexpected" client close handler */
	comm_remove_close_handler(sslState->client.fd,
	    sslClientClosed,
	    sslState);
	comm_close(sslState->client.fd);
	sslState->client.fd = -1;
    }
    if (sslState->server.fd > -1) {
	comm_close(sslState->server.fd);
    }
}

/* This is called only if the client connect closes unexpectedly,
 * ie from icpDetectClientClose() */
static void
sslClientClosed(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslClientClosed: FD %d\n", fd);
    /* we have been called from comm_close for the client side, so
     * just need to clean up the server side */
    protoUnregister(NULL, sslState->request, no_addr);
    comm_close(sslState->server.fd);
}

static void
sslStateFree(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslStateFree: FD %d, sslState=%p\n", fd, sslState);
    if (sslState == NULL)
	return;
    if (fd != sslState->server.fd)
	fatal_dump("sslStateFree: FD mismatch!\n");
    if (sslState->client.fd > -1) {
	commSetSelect(sslState->client.fd,
	    COMM_SELECT_READ,
	    NULL,
	    NULL, 0);
    }
    safe_free(sslState->server.buf);
    safe_free(sslState->client.buf);
    xfree(sslState->url);
    requestUnlink(sslState->request);
    sslState->request = NULL;
    cbdataFree(sslState);
}

/* Read from server side and queue it for writing to the client */
static void
sslReadServer(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    len = read(sslState->server.fd, sslState->server.buf, SQUID_TCP_SO_RCVBUF);
    fd_bytes(sslState->server.fd, len, FD_READ);
    debug(26, 5) ("sslReadServer FD %d, read %d bytes\n", fd, len);
    if (len < 0) {
	debug(50, 1) ("sslReadServer: FD %d: read failure: %s\n",
	    sslState->server.fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(sslState->server.fd,
		COMM_SELECT_READ,
		sslReadServer,
		sslState, 0);
	} else {
	    sslClose(sslState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	sslClose(sslState);
    } else {
	sslState->server.offset = 0;
	sslState->server.len = len;
	/* extend server read timeout */
	commSetTimeout(sslState->server.fd, Config.Timeout.read, NULL, NULL);
	commSetSelect(sslState->client.fd,
	    COMM_SELECT_WRITE,
	    sslWriteClient,
	    sslState, 0);
    }
}

/* Read from client side and queue it for writing to the server */
static void
sslReadClient(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    len = read(sslState->client.fd, sslState->client.buf, SQUID_TCP_SO_RCVBUF);
    fd_bytes(sslState->client.fd, len, FD_READ);
    debug(26, 5) ("sslReadClient FD %d, read %d bytes\n",
	sslState->client.fd, len);
    if (len < 0) {
	debug(50, 1) ("sslReadClient: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(sslState->client.fd,
		COMM_SELECT_READ,
		sslReadClient,
		sslState, 0);
	} else {
	    sslClose(sslState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	sslClose(sslState);
    } else {
	sslState->client.offset = 0;
	sslState->client.len = len;
	commSetSelect(sslState->server.fd,
	    COMM_SELECT_WRITE,
	    sslWriteServer,
	    sslState, 0);
    }
}

/* Writes data from the client buffer to the server side */
static void
sslWriteServer(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    len = write(sslState->server.fd,
	sslState->client.buf + sslState->client.offset,
	sslState->client.len - sslState->client.offset);
    fd_bytes(fd, len, FD_WRITE);
    debug(26, 5) ("sslWriteServer FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
	    commSetSelect(sslState->server.fd,
		COMM_SELECT_WRITE,
		sslWriteServer,
		sslState, 0);
	    return;
	}
	debug(50, 2) ("sslWriteServer: FD %d: write failure: %s.\n",
	    sslState->server.fd, xstrerror());
	sslClose(sslState);
	return;
    }
    if ((sslState->client.offset += len) >= sslState->client.len) {
	/* Done writing, read more */
	commSetSelect(sslState->client.fd,
	    COMM_SELECT_READ,
	    sslReadClient,
	    sslState, 0);
    } else {
	/* still have more to write */
	commSetSelect(sslState->server.fd,
	    COMM_SELECT_WRITE,
	    sslWriteServer,
	    sslState, 0);
    }
}

/* Writes data from the server buffer to the client side */
static void
sslWriteClient(int fd, void *data)
{
    SslStateData *sslState = data;
    int len;
    debug(26, 5) ("sslWriteClient FD %d len=%d offset=%d\n",
	fd,
	sslState->server.len,
	sslState->server.offset);
    len = write(sslState->client.fd,
	sslState->server.buf + sslState->server.offset,
	sslState->server.len - sslState->server.offset);
    fd_bytes(fd, len, FD_WRITE);
    debug(26, 5) ("sslWriteClient FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
	    commSetSelect(sslState->client.fd,
		COMM_SELECT_WRITE,
		sslWriteClient,
		sslState, 0);
	    return;
	}
	debug(50, 2) ("sslWriteClient: FD %d: write failure: %s.\n",
	    sslState->client.fd, xstrerror());
	sslClose(sslState);
	return;
    }
    if (sslState->size_ptr)
	*sslState->size_ptr += len;	/* increment total object size */
    if ((sslState->server.offset += len) >= sslState->server.len) {
	/* Done writing, read more */
	commSetSelect(sslState->server.fd,
	    COMM_SELECT_READ,
	    sslReadServer,
	    sslState, 0);
    } else {
	/* still have more to write */
	commSetSelect(sslState->client.fd,
	    COMM_SELECT_WRITE,
	    sslWriteClient,
	    sslState, 0);
    }
}

static void
sslTimeout(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslTimeout: FD %d\n", fd);
    sslClose(sslState);
}

static void
sslConnected(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslConnected: FD %d sslState=%p\n", fd, sslState);
    strcpy(sslState->server.buf, conn_established);
    sslState->server.len = strlen(conn_established);
    sslState->server.offset = 0;
    commSetTimeout(sslState->server.fd, Config.Timeout.read, NULL, NULL);
    commSetSelect(sslState->client.fd,
	COMM_SELECT_WRITE,
	sslWriteClient,
	sslState, 0);
    commSetSelect(sslState->client.fd,
	COMM_SELECT_READ,
	sslReadClient,
	sslState, 0);
}

static void
sslErrorComplete(int fd, char *buf, int size, int errflag, void *sslState)
{
    safe_free(buf);
    if (sslState == NULL) {
	debug_trap("sslErrorComplete: NULL sslState\n");
	return;
    }
    sslClose(sslState);
}


static void
sslConnectDone(int fd, int status, void *data)
{
    SslStateData *sslState = data;
    request_t *request = sslState->request;
    char *buf = NULL;
    if (status == COMM_ERR_DNS) {
	debug(26, 4) ("sslConnect: Unknown host: %s\n", sslState->host);
	buf = squid_error_url(sslState->url,
	    request->method,
	    ERR_DNS_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    dns_error_message);
	comm_write(sslState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    sslErrorComplete,
	    sslState,
	    xfree);
	return;
    } else if (status != COMM_OK) {
	buf = squid_error_url(sslState->url,
	    sslState->request->method,
	    ERR_CONNECT_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	comm_write(sslState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    sslErrorComplete,
	    sslState,
	    xfree);
	return;
    }
    if (opt_no_ipcache)
	ipcacheInvalidate(sslState->host);
    if (sslState->proxying)
	sslProxyConnected(sslState->server.fd, sslState);
    else
	sslConnected(sslState->server.fd, sslState);
}

void
sslStart(int fd, const char *url, request_t * request, int *size_ptr)
{
    /* Create state structure. */
    SslStateData *sslState = NULL;
    int sock;
    char *buf = NULL;
    debug(26, 3) ("sslStart: '%s %s'\n",
	RequestMethodStr[request->method], url);
    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(26, 4) ("sslStart: Failed because we're out of sockets.\n");
	buf = squid_error_url(url,
	    request->method,
	    ERR_NO_FDS,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	comm_write(fd,
	    xstrdup(buf),
	    strlen(buf),
	    NULL,
	    NULL,
	    xfree);
	return;
    }
    sslState = xcalloc(1, sizeof(SslStateData));
    cbdataAdd(sslState);
    sslState->url = xstrdup(url);
    sslState->request = requestLink(request);
    sslState->timeout = Config.Timeout.read;
    sslState->size_ptr = size_ptr;
    sslState->client.fd = fd;
    sslState->server.fd = sock;
    sslState->server.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    sslState->client.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    comm_add_close_handler(sslState->server.fd,
	sslStateFree,
	sslState);
    comm_add_close_handler(sslState->client.fd,
	sslClientClosed,
	sslState);
    commSetTimeout(sslState->client.fd,
	Config.Timeout.lifetime,
	sslTimeout,
	sslState);
    peerSelect(request,
	NULL,
	sslPeerSelectComplete,
	sslPeerSelectFail,
	sslState);
}

static void
sslProxyConnected(int fd, void *data)
{
    SslStateData *sslState = data;
    debug(26, 3) ("sslProxyConnected: FD %d sslState=%p\n", fd, sslState);
    sprintf(sslState->client.buf, "CONNECT %s HTTP/1.0\r\n\r\n", sslState->url);
    debug(26, 3) ("sslProxyConnected: Sending 'CONNECT %s HTTP/1.0'\n", sslState->url);
    sslState->client.len = strlen(sslState->client.buf);
    sslState->client.offset = 0;
    commSetSelect(sslState->server.fd,
	COMM_SELECT_WRITE,
	sslWriteServer,
	sslState, 0);
    commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
    commSetSelect(sslState->server.fd,
	COMM_SELECT_READ,
	sslReadServer,
	sslState, 0);
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
    } else if ((g = neighborFindByName(p->host))) {
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
sslPeerSelectFail(peer * p, void *data)
{
    SslStateData *sslState = data;
    squid_error_request(sslState->url, ERR_CANNOT_FETCH, 400);
    sslClose(sslState);
}
