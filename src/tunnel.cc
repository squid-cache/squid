
/*
 * $Id: tunnel.cc,v 1.19 1996/10/09 22:49:42 wessels Exp $
 *
 * DEBUG: section 26    Secure Sockets Layer Proxy
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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
    char *mime_hdr;
    struct {
	int fd;
	int len;
	int offset;
	char *buf;
    } client, server;
    time_t timeout;
    int *size_ptr;		/* pointer to size in an icpStateData for logging */
    ConnectStateData connectState;
} SslStateData;

static char conn_established[] = "HTTP/1.0 200 Connection established\r\n\r\n";

static void sslLifetimeExpire _PARAMS((int fd, SslStateData * sslState));
static void sslReadTimeout _PARAMS((int fd, SslStateData * sslState));
static void sslReadServer _PARAMS((int fd, SslStateData * sslState));
static void sslReadClient _PARAMS((int fd, SslStateData * sslState));
static void sslWriteServer _PARAMS((int fd, SslStateData * sslState));
static void sslWriteClient _PARAMS((int fd, SslStateData * sslState));
static void sslConnected _PARAMS((int fd, SslStateData * sslState));
static void sslProxyConnected _PARAMS((int fd, SslStateData * sslState));
static void sslConnect _PARAMS((int fd, ipcache_addrs *, void *));
static void sslErrorComplete _PARAMS((int, char *, int, int, void *));
static void sslClose _PARAMS((SslStateData * sslState));
static int sslClientClosed _PARAMS((int fd, SslStateData * sslState));
static void sslConnectDone _PARAMS((int fd, int status, void *data));

static void
sslClose(SslStateData * sslState)
{
    if (sslState->client.fd > -1) {
	/* remove the "unexpected" client close handler */
	comm_remove_close_handler(sslState->client.fd,
	    (PF) sslClientClosed,
	    (void *) sslState);
	comm_close(sslState->client.fd);
	sslState->client.fd = -1;
    }
    if (sslState->server.fd > -1) {
	comm_close(sslState->server.fd);
    }
}

/* This is called only if the client connect closes unexpectedly,
 * ie from icpDetectClientClose() */
static int
sslClientClosed(int fd, SslStateData * sslState)
{
    debug(26, 3, "sslClientClosed: FD %d\n", fd);
    /* we have been called from comm_close for the client side, so
     * just need to clean up the server side */
    protoUnregister(sslState->server.fd,
	NULL,
	sslState->request,
	no_addr);
    comm_close(sslState->server.fd);
    return 0;
}

static int
sslStateFree(int fd, SslStateData * sslState)
{
    debug(26, 3, "sslStateFree: FD %d, sslState=%p\n", fd, sslState);
    if (sslState == NULL)
	return 1;
    if (fd != sslState->server.fd)
	fatal_dump("sslStateFree: FD mismatch!\n");
    comm_set_select_handler(sslState->client.fd,
	COMM_SELECT_READ,
	NULL,
	NULL);
    safe_free(sslState->server.buf);
    safe_free(sslState->client.buf);
    xfree(sslState->url);
    requestUnlink(sslState->request);
    memset(sslState, '\0', sizeof(SslStateData));
    safe_free(sslState);
    return 0;
}

/* This will be called when the server lifetime is expired. */
static void
sslLifetimeExpire(int fd, SslStateData * sslState)
{
    debug(26, 4, "sslLifeTimeExpire: FD %d: URL '%s'>\n",
	fd, sslState->url);
    sslClose(sslState);
}

/* Read from server side and queue it for writing to the client */
static void
sslReadServer(int fd, SslStateData * sslState)
{
    int len;
    len = read(sslState->server.fd, sslState->server.buf, SQUID_TCP_SO_RCVBUF);
    debug(26, 5, "sslReadServer FD %d, read %d bytes\n", fd, len);
    if (len < 0) {
	debug(26, 1, "sslReadServer: FD %d: read failure: %s\n",
	    sslState->server.fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(sslState->server.fd,
		COMM_SELECT_READ,
		(PF) sslReadServer,
		(void *) sslState);
	    comm_set_select_handler_plus_timeout(sslState->server.fd,
		COMM_SELECT_TIMEOUT,
		(PF) sslReadTimeout,
		(void *) sslState,
		sslState->timeout);
	} else {
	    sslClose(sslState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	sslClose(sslState);
    } else {
	sslState->server.offset = 0;
	sslState->server.len = len;
	comm_set_select_handler(sslState->client.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteClient,
	    (void *) sslState);
    }
}

/* Read from client side and queue it for writing to the server */
static void
sslReadClient(int fd, SslStateData * sslState)
{
    int len;
    len = read(sslState->client.fd, sslState->client.buf, SQUID_TCP_SO_RCVBUF);
    debug(26, 5, "sslReadClient FD %d, read %d bytes\n",
	sslState->client.fd, len);
    if (len < 0) {
	debug(26, 1, "sslReadClient: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(sslState->client.fd,
		COMM_SELECT_READ,
		(PF) sslReadClient,
		(void *) sslState);
	} else {
	    sslClose(sslState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	sslClose(sslState);
    } else {
	sslState->client.offset = 0;
	sslState->client.len = len;
	comm_set_select_handler(sslState->server.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteServer,
	    (void *) sslState);
    }
}

/* Writes data from the client buffer to the server side */
static void
sslWriteServer(int fd, SslStateData * sslState)
{
    int len;
    len = write(sslState->server.fd,
	sslState->client.buf + sslState->client.offset,
	sslState->client.len - sslState->client.offset);
    debug(26, 5, "sslWriteServer FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	debug(26, 2, "sslWriteServer: FD %d: write failure: %s.\n",
	    sslState->server.fd, xstrerror());
	sslClose(sslState);
	return;
    }
    if ((sslState->client.offset += len) >= sslState->client.len) {
	/* Done writing, read more */
	comm_set_select_handler(sslState->client.fd,
	    COMM_SELECT_READ,
	    (PF) sslReadClient,
	    (void *) sslState);
	comm_set_select_handler_plus_timeout(sslState->server.fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) sslReadTimeout,
	    (void *) sslState,
	    sslState->timeout);
    } else {
	/* still have more to write */
	comm_set_select_handler(sslState->server.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteServer,
	    (void *) sslState);
    }
}

/* Writes data from the server buffer to the client side */
static void
sslWriteClient(int fd, SslStateData * sslState)
{
    int len;
    debug(26, 5, "sslWriteClient FD %d len=%d offset=%d\n",
	fd,
	sslState->server.len,
	sslState->server.offset);
    len = write(sslState->client.fd,
	sslState->server.buf + sslState->server.offset,
	sslState->server.len - sslState->server.offset);
    debug(26, 5, "sslWriteClient FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	debug(26, 2, "sslWriteClient: FD %d: write failure: %s.\n",
	    sslState->client.fd, xstrerror());
	sslClose(sslState);
	return;
    }
    if (sslState->size_ptr)
	*sslState->size_ptr += len;	/* increment total object size */
    if ((sslState->server.offset += len) >= sslState->server.len) {
	/* Done writing, read more */
	comm_set_select_handler(sslState->server.fd,
	    COMM_SELECT_READ,
	    (PF) sslReadServer,
	    (void *) sslState);
    } else {
	/* still have more to write */
	comm_set_select_handler(sslState->client.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteClient,
	    (void *) sslState);
    }
}

static void
sslReadTimeout(int fd, SslStateData * sslState)
{
    debug(26, 3, "sslReadTimeout: FD %d\n", fd);
    sslClose(sslState);
}

static void
sslConnected(int fd, SslStateData * sslState)
{
    debug(26, 3, "sslConnected: FD %d sslState=%p\n", fd, sslState);
    strcpy(sslState->server.buf, conn_established);
    sslState->server.len = strlen(conn_established);
    sslState->server.offset = 0;
    comm_set_select_handler(sslState->client.fd,
	COMM_SELECT_WRITE,
	(PF) sslWriteClient,
	(void *) sslState);
    comm_set_fd_lifetime(fd, 86400);	/* extend lifetime */
    comm_set_select_handler(sslState->client.fd,
	COMM_SELECT_READ,
	(PF) sslReadClient,
	(void *) sslState);
}

static void
sslErrorComplete(int fd, char *buf, int size, int errflag, void *sslState)
{
    safe_free(buf);
    sslClose(sslState);
}


static void
sslConnect(int fd, ipcache_addrs * ia, void *data)
{
    SslStateData *sslState = data;
    request_t *request = sslState->request;
    char *buf = NULL;
    if (ia == NULL) {
	debug(26, 4, "sslConnect: Unknown host: %s\n", sslState->host);
	buf = squid_error_url(sslState->url,
	    request->method,
	    ERR_DNS_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    dns_error_message);
	comm_write(sslState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    30,
	    sslErrorComplete,
	    (void *) sslState,
	    xfree);
	return;
    }
    debug(26, 5, "sslConnect: client=%d server=%d\n",
	sslState->client.fd,
	sslState->server.fd);
    /* Install lifetime handler */
    comm_set_select_handler(sslState->server.fd,
	COMM_SELECT_LIFETIME,
	(PF) sslLifetimeExpire,
	(void *) sslState);
    /* NOTE this changes the lifetime handler for the client side.
     * It used to be asciiConnLifetimeHandle, but it does funny things
     * like looking for read handlers and assuming it was still reading
     * the HTTP request.  sigh... */
    comm_set_select_handler(sslState->client.fd,
	COMM_SELECT_LIFETIME,
	(PF) sslLifetimeExpire,
	(void *) sslState);
    sslState->connectState.fd = fd;
    sslState->connectState.host = sslState->host;
    sslState->connectState.port = sslState->port;
    sslState->connectState.handler = sslConnectDone;
    sslState->connectState.data = sslState;
    comm_nbconnect(fd, &sslState->connectState);
}

static void
sslConnectDone(int fd, int status, void *data)
{
    SslStateData *sslState = data;
    char *buf = NULL;
    if (status == COMM_ERROR) {
	buf = squid_error_url(sslState->url,
	    sslState->request->method,
	    ERR_CONNECT_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	comm_write(sslState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    30,
	    sslErrorComplete,
	    (void *) sslState,
	    xfree);
	return;
    }
    if (opt_no_ipcache)
	ipcacheInvalidate(sslState->host);
    if (Config.sslProxy.host)
	sslProxyConnected(sslState->server.fd, sslState);
    else
	sslConnected(sslState->server.fd, sslState);
}

int
sslStart(int fd, char *url, request_t * request, char *mime_hdr, int *size_ptr)
{
    /* Create state structure. */
    SslStateData *sslState = NULL;
    int sock;
    char *buf = NULL;
    edge *e = NULL;

    debug(26, 3, "sslStart: '%s %s'\n",
	RequestMethodStr[request->method], url);

    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(26, 4, "sslStart: Failed because we're out of sockets.\n");
	buf = squid_error_url(url,
	    request->method,
	    ERR_NO_FDS,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	comm_write(sslState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    30,
	    sslErrorComplete,
	    (void *) sslState,
	    xfree);
	return COMM_ERROR;
    }
    sslState = xcalloc(1, sizeof(SslStateData));
    sslState->url = xstrdup(url);
    sslState->request = requestLink(request);
    sslState->mime_hdr = mime_hdr;
    sslState->timeout = Config.readTimeout;
    sslState->size_ptr = size_ptr;
    sslState->client.fd = fd;
    sslState->server.fd = sock;
    sslState->server.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    sslState->client.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    if ((sslState->host = Config.sslProxy.host)) {
	if ((sslState->port = Config.sslProxy.port) == 0) {
	    if ((e = neighborFindByName(Config.sslProxy.host)))
		sslState->port = e->http_port;
	    else
		sslState->port = CACHE_HTTP_PORT;
	}
    } else {
	sslState->host = request->host;
	sslState->port = request->port;
    }
    comm_add_close_handler(sslState->server.fd,
	(PF) sslStateFree,
	(void *) sslState);
    comm_add_close_handler(sslState->client.fd,
	(PF) sslClientClosed,
	(void *) sslState);
    ipcache_nbgethostbyname(sslState->host,
	sslState->server.fd,
	sslConnect,
	sslState);
    return COMM_OK;
}

static void
sslProxyConnected(int fd, SslStateData * sslState)
{
    debug(26, 3, "sslProxyConnected: FD %d sslState=%p\n", fd, sslState);
    sprintf(sslState->client.buf, "CONNECT %s HTTP/1.0\r\n\r\n", sslState->url);
    debug(26, 3, "sslProxyConnected: Sending 'CONNECT %s HTTP/1.0'\n", sslState->url);
    sslState->client.len = strlen(sslState->client.buf);
    sslState->client.offset = 0;
    comm_set_select_handler(sslState->server.fd,
	COMM_SELECT_WRITE,
	(PF) sslWriteServer,
	(void *) sslState);
    comm_set_fd_lifetime(fd, 86400);	/* extend lifetime */
    comm_set_select_handler(sslState->server.fd,
	COMM_SELECT_READ,
	(PF) sslReadServer,
	(void *) sslState);
}
