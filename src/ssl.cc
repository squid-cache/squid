/*
 *  $Id: ssl.cc,v 1.2 1996/05/03 22:56:31 wessels Exp $ 
 *
 * DEBUG: Section 26                    ssl
 */
#include "squid.h"

#define SSL_BUFSIZ (1<<14)

typedef struct {
    char *url;
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
} SslStateData;

static char conn_established[] = "HTTP/1.0 200 Connection established\r\n\r\n";

static void sslLifetimeExpire _PARAMS((int fd, SslStateData * sslState));
static void sslReadTimeout _PARAMS((int fd, SslStateData * sslState));
static void sslReadServer _PARAMS((int fd, SslStateData * sslState));
static void sslReadClient _PARAMS((int fd, SslStateData * sslState));
static void sslWriteServer _PARAMS((int fd, SslStateData * sslState));
static void sslWriteClient _PARAMS((int fd, SslStateData * sslState));
static void sslConnected _PARAMS((int fd, SslStateData * sslState));
static void sslConnInProgress _PARAMS((int fd, SslStateData * sslState));

static int sslStateFree(fd, sslState)
     int fd;
     SslStateData *sslState;
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
    memset(sslState, '\0', sizeof(SslStateData));
    safe_free(sslState);
    return 0;
}

/* This will be called when the server lifetime is expired. */
static void sslLifetimeExpire(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    debug(26, 4, "sslLifeTimeExpire: FD %d: URL '%s'>\n",
	fd, sslState->url);
    comm_close(sslState->client.fd);	/* close client first */
    comm_close(sslState->server.fd);
}

/* Read from server side and queue it for writing to the client */
static void sslReadServer(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    int len;
    len = read(sslState->server.fd, sslState->server.buf, 4096);
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
	    comm_close(sslState->client.fd);
	    comm_close(sslState->server.fd);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	comm_close(sslState->client.fd);
	comm_close(sslState->server.fd);
    } else {
	sslState->server.offset = 0;
	sslState->server.len = len;
	comm_set_select_handler(sslState->client.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteClient,
	    (void *) sslState);
	comm_set_select_handler_plus_timeout(sslState->server.fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) sslReadTimeout,
	    (void *) sslState,
	    sslState->timeout);
	comm_set_select_handler(sslState->server.fd,
	    COMM_SELECT_READ,
	    (PF) sslReadServer,
	    (void *) sslState);
    }
}

/* Read from client side and queue it for writing to the server */
static void sslReadClient(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    int len;
    len = read(sslState->client.fd, sslState->client.buf, 4096);
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
		(PF) sslReadServer,
		(void *) sslState);
	    comm_set_select_handler_plus_timeout(sslState->client.fd,
		COMM_SELECT_TIMEOUT,
		(PF) sslReadTimeout,
		(void *) sslState,
		sslState->timeout);
	} else {
	    comm_close(sslState->client.fd);
	    comm_close(sslState->server.fd);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	comm_close(sslState->client.fd);
	comm_close(sslState->server.fd);
    } else {
	sslState->client.offset = 0;
	sslState->client.len = len;
	comm_set_select_handler(sslState->server.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteServer,
	    (void *) sslState);
	comm_set_select_handler_plus_timeout(sslState->client.fd, COMM_SELECT_TIMEOUT,
	    (PF) sslReadTimeout,
	    (void *) sslState,
	    sslState->timeout);
	comm_set_select_handler(sslState->client.fd,
	    COMM_SELECT_READ,
	    (PF) sslReadServer,
	    (void *) sslState);
    }
}

/* Writes data from the client buffer to the server side */
static void sslWriteServer(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    int len;
    len = write(sslState->server.fd,
	sslState->client.buf + sslState->client.offset,
	sslState->client.len - sslState->client.offset);
    debug(26, 5, "sslWriteServer FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	debug(26, 2, "sslWriteServer: FD %d: write failure: %s.\n",
	    sslState->server.fd, xstrerror());
	comm_close(sslState->client.fd);
	comm_close(sslState->server.fd);
	return;
    }
    if ((sslState->client.offset += len) >= sslState->client.len) {
	/* Done writing, read more */
	comm_set_select_handler(sslState->client.fd,
	    COMM_SELECT_READ,
	    (PF) sslReadClient,
	    (void *) sslState);
    } else {
	/* still have more to write */
	comm_set_select_handler(sslState->server.fd,
	    COMM_SELECT_WRITE,
	    (PF) sslWriteServer,
	    (void *) sslState);
    }
}

/* Writes data from the server buffer to the client side */
static void sslWriteClient(fd, sslState)
     int fd;
     SslStateData *sslState;
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
	comm_close(sslState->client.fd);
	comm_close(sslState->server.fd);
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

static void sslReadTimeout(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    if (fd != sslState->server.fd)
	fatal_dump("sslReadTimeout: FD mismatch!\n");
    debug(26, 3, "sslReadTimeout: FD %d\n", fd);
    comm_close(sslState->client.fd);
    comm_close(sslState->server.fd);
}

static void sslConnected(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    debug(26, 3, "sslConnected: FD %d sslState=%p\n", fd, sslState);
    strcpy(sslState->server.buf, conn_established);
    sslState->server.len = strlen(conn_established);
    sslState->server.offset = 0;
    comm_set_select_handler(sslState->client.fd,
	COMM_SELECT_WRITE,
	(PF) sslWriteClient,
	(void *) sslState);
    comm_set_fd_lifetime(fd, -1);	/* disable lifetime */
    comm_set_select_handler_plus_timeout(sslState->server.fd,
	COMM_SELECT_TIMEOUT,
	(PF) sslReadTimeout,
	(void *) sslState,
	sslState->timeout);
    comm_set_select_handler(sslState->server.fd,
	COMM_SELECT_READ,
	(PF) sslReadServer,
	(void *) sslState);
    comm_set_select_handler(sslState->client.fd,
	COMM_SELECT_READ,
	(PF) sslReadClient,
	(void *) sslState);
}


static void sslConnInProgress(fd, sslState)
     int fd;
     SslStateData *sslState;
{
    request_t *req = sslState->request;
    debug(26, 5, "sslConnInProgress: FD %d sslState=%p\n", fd, sslState);

    if (comm_connect(fd, req->host, req->port) != COMM_OK) {
	debug(26, 5, "sslConnInProgress: FD %d: %s", fd, xstrerror());
	switch (errno) {
#if EINPROGRESS != EALREADY
	case EINPROGRESS:
#endif
	case EALREADY:
	    /* We are not connected yet. schedule this handler again */
	    comm_set_select_handler(fd, COMM_SELECT_WRITE,
		(PF) sslConnInProgress,
		(void *) sslState);
	    return;
	default:
	    comm_close(sslState->client.fd);
	    comm_close(sslState->server.fd);
	    return;
	}
    }
    /* We are now fully connected */
    sslConnected(fd, sslState);
    return;
}


int sslStart(fd, url, request, mime_hdr, size_ptr)
     int fd;
     char *url;
     request_t *request;
     char *mime_hdr;
     int *size_ptr;
{
    /* Create state structure. */
    int sock, status;
    SslStateData *sslState = NULL;

    debug(26, 3, "sslStart: '%s %s'\n",
	RequestMethodStr[request->method], url);

    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(26, 4, "sslStart: Failed because we're out of sockets.\n");
	squid_error_url(url,
	    request->method,
	    ERR_NO_FDS,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	return COMM_ERROR;
    }
    sslState = (SslStateData *) xcalloc(1, sizeof(SslStateData));
    sslState->url = xstrdup(url);
    sslState->request = request;
    sslState->mime_hdr = mime_hdr;
    sslState->timeout = getReadTimeout();
    sslState->size_ptr = size_ptr;
    sslState->client.fd = fd;
    sslState->server.fd = sock;
    sslState->server.buf = xmalloc(SSL_BUFSIZ);
    sslState->client.buf = xmalloc(SSL_BUFSIZ);
    comm_set_select_handler(sslState->server.fd,
	COMM_SELECT_CLOSE,
	(PF) sslStateFree,
	(void *) sslState);

    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for ssl. */
    if (!ipcache_gethostbyname(request->host)) {
	debug(26, 4, "sslstart: Called without IP entry in ipcache. OR lookup failed.\n");
	squid_error_url(url,
	    request->method,
	    ERR_DNS_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    dns_error_message);
	comm_close(sslState->client.fd);
	comm_close(sslState->server.fd);
	return COMM_ERROR;
    }
    debug(26, 5, "sslStart: client=%d server=%d\n",
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
    /* Open connection. */
    if ((status = comm_connect(sock, request->host, request->port))) {
	if (status != EINPROGRESS) {
	    squid_error_url(url,
		request->method,
		ERR_CONNECT_FAIL,
		fd_table[fd].ipaddr,
		500,
		xstrerror());
	    comm_close(sslState->client.fd);
	    comm_close(sslState->server.fd);
	    return COMM_ERROR;
	} else {
	    debug(26, 5, "sslStart: conn %d EINPROGRESS\n", sock);
	    /* The connection is in progress, install ssl handler */
	    comm_set_select_handler(sslState->server.fd,
		COMM_SELECT_WRITE,
		(PF) sslConnInProgress,
		(void *) sslState);
	    return COMM_OK;
	}
    }
    /* We got immediately connected. (can this happen?) */
    sslConnected(sslState->server.fd, sslState);
    return COMM_OK;
}
