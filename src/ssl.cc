
/*
 * $Id: ssl.cc,v 1.124 2002/10/13 20:35:03 robertc Exp $
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

typedef struct {
    char *url;
    char *host;			/* either request->host or proxy host */
    u_short port;
    request_t *request;
    FwdServer *servers;
    struct {
	int fd;
	int len;
	char *buf;
    } client, server;
    size_t *size_ptr;		/* pointer to size in an ConnStateData for logging */
    int *status_ptr;		/* pointer to status for logging */
#if DELAY_POOLS
    delay_id delay_id;
#endif
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
    SslStateData *sslState = (SslStateData *)data;
    debug(26, 3) ("sslServerClosed: FD %d\n", fd);
    assert(fd == sslState->server.fd);
    sslState->server.fd = -1;
    if (sslState->client.fd == -1)
	sslStateFree(sslState);
}

static void
sslClientClosed(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
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
    fwdServersFree(&sslState->servers);
    sslState->host = NULL;
    requestUnlink(sslState->request);
    sslState->request = NULL;
#if DELAY_POOLS
    delayUnregisterDelayIdPtr(&sslState->delay_id);
#endif
    cbdataFree(sslState);
}

#if DELAY_POOLS
static int
sslDeferServerRead(int fdnotused, void *data)
{
    SslStateData *s = (SslStateData *)data;
    int i = delayBytesWanted(s->delay_id, 0, INT_MAX);
    if (i == INT_MAX)
	return 0;
    if (i == 0)
	return 1;
    return -1;
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
	if ((size_t)sslState->client.len < read_sz) {
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
	/*
	 * If this was allowed to return 0, there would be a possibility
	 * of the socket becoming "hung" with data accumulating but no
	 * write handler (server.len==0) and no read handler (!(0<0)) and
	 * no data flowing in the other direction.  Hence the argument of
	 * 1 as min.
	 */
	read_sz = delayBytesWanted(sslState->delay_id, 1, read_sz);
#endif
	if ((size_t)sslState->server.len < read_sz) {
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
    SslStateData *sslState = (SslStateData *)data;
    int len;
    size_t read_sz = SQUID_TCP_SO_RCVBUF - sslState->server.len;
    assert(fd == sslState->server.fd);
    debug(26, 3) ("sslReadServer: FD %d, reading %d bytes at offset %d\n",
	fd, (int) read_sz, sslState->server.len);
    errno = 0;
#if DELAY_POOLS
    read_sz = delayBytesWanted(sslState->delay_id, 1, read_sz);
#endif
    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd, sslState->server.buf + sslState->server.len, read_sz);
    debug(26, 3) ("sslReadServer: FD %d, read   %d bytes\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
#if DELAY_POOLS
	delayBytesIn(sslState->delay_id, len);
#endif
	kb_incr(&statCounter.server.all.kbytes_in, len);
	kb_incr(&statCounter.server.other.kbytes_in, len);
	sslState->server.len += len;
    }
    cbdataInternalLock(sslState);	/* ??? should be locked by the caller... */
    if (len < 0) {
	debug(50, ignoreErrno(errno) ? 3 : 1)
	    ("sslReadServer: FD %d: read failure: %s\n", fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    } else if (len == 0) {
	comm_close(sslState->server.fd);
    }
    if (cbdataReferenceValid(sslState))
	sslSetSelect(sslState);
    cbdataInternalUnlock(sslState);	/* ??? */
}

/* Read from client side and queue it for writing to the server */
static void
sslReadClient(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    int len;
    assert(fd == sslState->client.fd);
    debug(26, 3) ("sslReadClient: FD %d, reading %d bytes at offset %d\n",
	fd, SQUID_TCP_SO_RCVBUF - sslState->client.len,
	sslState->client.len);
    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd,
	sslState->client.buf + sslState->client.len,
	SQUID_TCP_SO_RCVBUF - sslState->client.len);
    debug(26, 3) ("sslReadClient: FD %d, read   %d bytes\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
	kb_incr(&statCounter.client_http.kbytes_in, len);
	sslState->client.len += len;
    }
    cbdataInternalLock(sslState);	/* ??? should be locked by the caller... */
    if (len < 0) {
	int level = 1;
#ifdef ECONNRESET
	if (errno == ECONNRESET)
	    level = 2;
#endif
	if (ignoreErrno(errno))
	    level = 3;
	debug(50, level) ("sslReadClient: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    } else if (len == 0) {
	comm_close(fd);
    }
    if (cbdataReferenceValid(sslState))
	sslSetSelect(sslState);
    cbdataInternalUnlock(sslState);	/* ??? */
}

/* Writes data from the client buffer to the server side */
static void
sslWriteServer(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    int len;
    assert(fd == sslState->server.fd);
    debug(26, 3) ("sslWriteServer: FD %d, %d bytes to write\n",
	fd, sslState->client.len);
    statCounter.syscalls.sock.writes++;
    len = FD_WRITE_METHOD(fd,
	sslState->client.buf,
	sslState->client.len);
    debug(26, 3) ("sslWriteServer: FD %d, %d bytes written\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_WRITE);
	kb_incr(&statCounter.server.all.kbytes_out, len);
	kb_incr(&statCounter.server.other.kbytes_out, len);
	assert(len <= sslState->client.len);
	sslState->client.len -= len;
	if (sslState->client.len > 0) {
	    /* we didn't write the whole thing */
	    xmemmove(sslState->client.buf,
		sslState->client.buf + len,
		sslState->client.len);
	}
    }
    cbdataInternalLock(sslState);	/* ??? should be locked by the caller... */
    if (len < 0) {
	debug(50, ignoreErrno(errno) ? 3 : 1)
	    ("sslWriteServer: FD %d: write failure: %s.\n", fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    }
    if (cbdataReferenceValid(sslState))
	sslSetSelect(sslState);
    cbdataInternalUnlock(sslState);	/* ??? */
}

/* Writes data from the server buffer to the client side */
static void
sslWriteClient(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    int len;
    assert(fd == sslState->client.fd);
    debug(26, 3) ("sslWriteClient: FD %d, %d bytes to write\n",
	fd, sslState->server.len);
    statCounter.syscalls.sock.writes++;
    len = FD_WRITE_METHOD(fd,
	sslState->server.buf,
	sslState->server.len);
    debug(26, 3) ("sslWriteClient: FD %d, %d bytes written\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_WRITE);
	kb_incr(&statCounter.client_http.kbytes_out, len);
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
    cbdataInternalLock(sslState);	/* ??? should be locked by the caller... */
    if (len < 0) {
	debug(50, ignoreErrno(errno) ? 3 : 1)
	    ("sslWriteClient: FD %d: write failure: %s.\n", fd, xstrerror());
	if (!ignoreErrno(errno))
	    comm_close(fd);
    }
    if (cbdataReferenceValid(sslState))
	sslSetSelect(sslState);
    cbdataInternalUnlock(sslState);	/* ??? */
}

static void
sslTimeout(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    debug(26, 3) ("sslTimeout: FD %d\n", fd);
    if (sslState->client.fd > -1)
	comm_close(sslState->client.fd);
    if (sslState->server.fd > -1)
	comm_close(sslState->server.fd);
}

static void
sslConnected(int fd, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    debug(26, 3) ("sslConnected: FD %d sslState=%p\n", fd, sslState);
    *sslState->status_ptr = HTTP_OK;
    xstrncpy(sslState->server.buf, conn_established, SQUID_TCP_SO_RCVBUF);
    sslState->server.len = strlen(conn_established);
    sslSetSelect(sslState);
}

static void
sslErrorComplete(int fdnotused, void *data, size_t sizenotused)
{
    SslStateData *sslState = (SslStateData *)data;
    assert(sslState != NULL);
    if (sslState->client.fd > -1)
	comm_close(sslState->client.fd);
    if (sslState->server.fd > -1)
	comm_close(sslState->server.fd);
}


static void
sslConnectDone(int fdnotused, comm_err_t status, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    request_t *request = sslState->request;
    ErrorState *err = NULL;
    if (sslState->servers->_peer)
	hierarchyNote(&sslState->request->hier, sslState->servers->code,
	    sslState->servers->_peer->host);
    else if (Config.onoff.log_ip_on_direct)
	hierarchyNote(&sslState->request->hier, sslState->servers->code,
	    fd_table[sslState->server.fd].ipaddr);
    else
	hierarchyNote(&sslState->request->hier, sslState->servers->code,
	    sslState->host);
    if (status == COMM_ERR_DNS) {
	debug(26, 4) ("sslConnect: Unknown host: %s\n", sslState->host);
	err = errorCon(ERR_DNS_FAIL, HTTP_NOT_FOUND);
	*sslState->status_ptr = HTTP_NOT_FOUND;
	err->request = requestLink(request);
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->callback = sslErrorComplete;
	err->callback_data = sslState;
	errorSend(sslState->client.fd, err);
    } else if (status != COMM_OK) {
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	*sslState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
	err->xerrno = errno;
	err->host = xstrdup(sslState->host);
	err->port = sslState->port;
	err->request = requestLink(request);
	err->callback = sslErrorComplete;
	err->callback_data = sslState;
	errorSend(sslState->client.fd, err);
    } else {
	if (sslState->servers->_peer)
	    sslProxyConnected(sslState->server.fd, sslState);
	else
	    sslConnected(sslState->server.fd, sslState);
	commSetTimeout(sslState->server.fd,
	    Config.Timeout.read,
	    sslTimeout,
	    sslState);
#if DELAY_POOLS
	commSetDefer(sslState->server.fd, sslDeferServerRead, sslState);
#endif
    }
}

CBDATA_TYPE(SslStateData);
void
sslStart(clientHttpRequest * http, size_t * size_ptr, int *status_ptr)
{
    /* Create state structure. */
    SslStateData *sslState = NULL;
    int sock;
    ErrorState *err = NULL;
    aclCheck_t ch;
    int answer;
    int fd = http->conn->fd;
    request_t *request = http->request;
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
	memset(&ch, '\0', sizeof(aclCheck_t));
	ch.src_addr = request->client_addr;
	ch.my_addr = request->my_addr;
	ch.my_port = request->my_port;
	ch.request = request;
	answer = aclCheckFast(Config.accessList.miss, &ch);
	if (answer == 0) {
	    err = errorCon(ERR_FORWARDING_DENIED, HTTP_FORBIDDEN);
	    *status_ptr = HTTP_FORBIDDEN;
	    err->request = requestLink(request);
	    err->src_addr = request->client_addr;
	    errorSend(fd, err);
	    return;
	}
    }
    debug(26, 3) ("sslStart: '%s %s'\n",
	RequestMethodStr[request->method], url);
    statCounter.server.all.requests++;
    statCounter.server.other.requests++;
    /* Create socket. */
    sock = comm_openex(SOCK_STREAM,
	0,
	getOutgoingAddr(request),
	0,
	COMM_NONBLOCKING,
	getOutgoingTOS(request),
	url);
    if (sock == COMM_ERROR) {
	debug(26, 4) ("sslStart: Failed because we're out of sockets.\n");
	err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	*status_ptr = HTTP_INTERNAL_SERVER_ERROR;
	err->xerrno = errno;
	err->request = requestLink(request);
	errorSend(fd, err);
	return;
    }
    CBDATA_INIT_TYPE(SslStateData);
    sslState = cbdataAlloc(SslStateData);
#if DELAY_POOLS
    sslState->delay_id = delayClient(http);
    delayRegisterDelayIdPtr(&sslState->delay_id);
#endif
    sslState->url = xstrdup(url);
    sslState->request = requestLink(request);
    sslState->size_ptr = size_ptr;
    sslState->status_ptr = status_ptr;
    sslState->client.fd = fd;
    sslState->server.fd = sock;
    sslState->server.buf = (char *)xmalloc(SQUID_TCP_SO_RCVBUF);
    sslState->client.buf = (char *)xmalloc(SQUID_TCP_SO_RCVBUF);
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
    SslStateData *sslState = (SslStateData *)data;
    MemBuf mb;
    HttpHeader hdr_out;
    Packer p;
    http_state_flags flags;
    debug(26, 3) ("sslProxyConnected: FD %d sslState=%p\n", fd, sslState);
    memset(&flags, '\0', sizeof(flags));
    flags.proxying = sslState->request->flags.proxying;
    memBufDefInit(&mb);
    memBufPrintf(&mb, "CONNECT %s HTTP/1.0\r\n", sslState->url);
    httpBuildRequestHeader(sslState->request,
	sslState->request,
	NULL,			/* StoreEntry */
	&hdr_out,
	flags);			/* flags */
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
sslPeerSelectComplete(FwdServer * fs, void *data)
{
    SslStateData *sslState = (SslStateData *)data;
    request_t *request = sslState->request;
    peer *g = NULL;
    if (fs == NULL) {
	ErrorState *err;
	err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE);
	*sslState->status_ptr = HTTP_SERVICE_UNAVAILABLE;
	err->request = requestLink(sslState->request);
	err->callback = sslErrorComplete;
	err->callback_data = sslState;
	errorSend(sslState->client.fd, err);
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
    if (g && g->options.no_delay && sslState->delay_id) {
	delayUnregisterDelayIdPtr(&sslState->delay_id);
	sslState->delay_id = 0;
    }
#endif
    commConnectStart(sslState->server.fd,
	sslState->host,
	sslState->port,
	sslConnectDone,
	sslState);
}
