/* $Id: http.cc,v 1.15 1996/03/29 21:19:21 wessels Exp $ */

/*
 * DEBUG: Section 11          http: HTTP
 */

#include "squid.h"

#define HTTP_PORT         80
#define HTTP_DELETE_GAP   (64*1024)
#define READBUFSIZ	4096

extern int errno;
extern char *dns_error_message;

typedef struct _httpdata {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    int port;
    char *type;
    char *req_hdr;
    char type_id;
    char request[MAX_URL + 1];
    char *icp_page_ptr;		/* Used to send proxy-http request: 
				 * put_free_8k_page(me) if the lifetime
				 * expires */
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
    char *reply_hdr;
    int reply_hdr_state;
    int content_length;
    int http_code;
    char content_type[128];
} HttpData;

char *HTTP_OPS[] =
{"GET", "POST", "HEAD", ""};

void httpCloseAndFree(fd, data)
     int fd;
     HttpData *data;
{
    if (fd > 0)
	comm_close(fd);
    if (data) {
	if (data->reply_hdr)
	    xfree(data->reply_hdr);
	xfree(data);
    }
}

int http_url_parser(url, host, port, request)
     char *url;
     char *host;
     int *port;
     char *request;
{
    static char hostbuf[MAX_URL];
    static char atypebuf[MAX_URL];
    int t;

    /* initialize everything */
    (*port) = 0;
    atypebuf[0] = hostbuf[0] = request[0] = host[0] = '\0';

    t = sscanf(url, "%[a-zA-Z]://%[^/]%s", atypebuf, hostbuf, request);
    if ((t < 2) || (strcasecmp(atypebuf, "http") != 0)) {
	return -1;
    } else if (t == 2) {
	strcpy(request, "/");
    }
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = HTTP_PORT;
    return 0;
}

int httpCachable(url, type, req_hdr)
     char *url;
     char *type;
     char *req_hdr;
{
    stoplist *p = NULL;

    /* GET and HEAD are cachable. Others are not. */
    if (((strncasecmp(type, "GET", 3) != 0)) &&
	(strncasecmp(type, "HEAD", 4) != 0))
	return 0;

    /* url's requiring authentication are uncachable */
    if (req_hdr && (strstr(req_hdr, "Authorization")))
	return 0;

    /* scan stop list */
    p = http_stoplist;
    while (p) {
	if (strstr(url, p->key))
	    return 0;
	p = p->next;
    }

    /* else cachable */
    return 1;
}

/* This will be called when timeout on read. */
void httpReadReplyTimeout(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(11, 4, "httpReadReplyTimeout: FD %d: <URL:%s>\n", fd, entry->url);
    cached_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    if (data->icp_rwd_ptr)
	safe_free(data->icp_rwd_ptr);
    if (data->icp_page_ptr) {
	put_free_8k_page(data->icp_page_ptr);
	data->icp_page_ptr = NULL;
    }
    comm_set_select_handler(fd, COMM_SELECT_READ, 0, 0);
    httpCloseAndFree(fd, data);
}

/* This will be called when socket lifetime is expired. */
void httpLifetimeExpire(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(11, 4, "httpLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);

    cached_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    if (data->icp_page_ptr) {
	put_free_8k_page(data->icp_page_ptr);
	data->icp_page_ptr = NULL;
    }
    if (data->icp_rwd_ptr)
	safe_free(data->icp_rwd_ptr);
    comm_set_select_handler(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, 0, 0);
    httpCloseAndFree(fd, data);
}


void httpProcessReplyHeader(data, buf)
     HttpData *data;
     char *buf;			/* chunk just read by httpReadReply() */
{
    char *t = NULL;
    StoreEntry *entry = data->entry;

    if (data->reply_hdr == NULL) {
	data->reply_hdr = get_free_8k_page();
	memset(data->reply_hdr, '\0', 8192);
    }
    if (data->reply_hdr_state == 0) {
	strncat(data->reply_hdr, buf, 8191 - strlen(data->reply_hdr));
	if ((t = strstr(data->reply_hdr, "\r\n\r\n"))) {
	    data->reply_hdr_state++;
	    t += 2;
	    *t = '\0';
	} else if ((t = strstr(data->reply_hdr, "\n\n"))) {
	    data->reply_hdr_state++;
	    t++;
	    *t = '\0';
	}
    }
    if (data->reply_hdr_state == 1) {
	data->reply_hdr_state++;
	debug(11, 9, "GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    data->reply_hdr);
	t = strtok(data->reply_hdr, "\r\n");
	while (t) {
	    if (!strncasecmp(t, "HTTP", 4)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    data->http_code = atoi(t);
		}
	    } else if (!strncasecmp(t, "Content-type:", 13)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    strncpy(data->content_type, t, 127);
		}
	    } else if (!strncasecmp(t, "Content-length:", 15)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    data->content_length = atoi(t);
		}
	    }
	    t = strtok(NULL, "\r\n");
	}
	if (data->http_code)
	    debug(11, 0, "httpReadReply: HTTP CODE: %d\n", data->http_code);
	if (data->content_length)
	    debug(11, 0, "httpReadReply: Content Length: %d\n", data->content_length);
	/* If we know this is cachable we can unchange the key */
	switch (data->http_code) {
	case 200:		/* OK */
	case 203:		/* ? */
	case 300:		/* ? */
	case 301:		/* Moved Permanently */
	case 302:		/* Moved Temporarily */
	case 410:		/* ? */
	    /* cachable, make the key public */
	    storeUnChangeKey(entry);
	    break;
	default:
	    BIT_RESET(entry->flag, CACHABLE);
	    BIT_SET(entry->flag, RELEASE_REQUEST);
	    break;
	}
    }
}


/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
/* XXX this function is too long! */
void httpReadReply(fd, data)
     int fd;
     HttpData *data;
{
    static char buf[READBUFSIZ];
    int len;
    int clen;
    int off;
    StoreEntry *entry = NULL;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    /* check if we want to defer reading */
	    clen = entry->mem_obj->e_current_len;
	    off = entry->mem_obj->e_lowest_offset;
	    if ((clen - off) > HTTP_DELETE_GAP) {
		debug(11, 3, "httpReadReply: Read deferred for Object: %s\n", entry->key);
		debug(11, 3, "                Current Gap: %d bytes\n", clen - off);
		/* reschedule, so it will be automatically reactivated
		 * when Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) httpReadReply,
		    (caddr_t) data);
/* don't install read timeout until we are below the GAP */
#ifdef INSTALL_READ_TIMEOUT_ABOVE_GAP
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) httpReadReplyTimeout,
		    (caddr_t) data,
		    getReadTimeout());
#else
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) NULL,
		    (caddr_t) NULL,
		    (time_t) 0);
#endif
		comm_set_stall(fd, getStallDelay());	/* dont try reading again for a while */
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    cached_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    httpCloseAndFree(fd, data);
	    return;
	}
    }
    errno = 0;
    len = read(fd, buf, READBUFSIZ);
    debug(11, 5, "httpReadReply: FD %d: len %d.\n", fd, len);

    if (len < 0 || ((len == 0) && (entry->mem_obj->e_current_len == 0))) {
	/* XXX we we should log when len==0 and current_len==0 */
	debug(11, 2, "httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (errno == ECONNRESET) {
	    /* Connection reset by peer */
	    /* consider it as a EOF */
	    if (!(entry->flag & DELETE_BEHIND))
		entry->expires = cached_curtime + ttlSet(entry);
	    sprintf(tmp_error_buf, "\n<p>Warning: The Remote Server sent RESET at the end of transmission.\n");
	    storeAppend(entry, tmp_error_buf, strlen(tmp_error_buf));
	    storeComplete(entry);
	    httpCloseAndFree(fd, data);
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) httpReadReply, (caddr_t) data);
	    comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
		(PF) httpReadReplyTimeout, (caddr_t) data, getReadTimeout());
	} else {
	    cached_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    httpCloseAndFree(fd, data);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	if (!(entry->flag & DELETE_BEHIND))
	    entry->expires = cached_curtime + ttlSet(entry);
	storeComplete(entry);
	httpCloseAndFree(fd, data);
    } else if (((entry->mem_obj->e_current_len + len) > getHttpMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);

	storeAppend(entry, buf, len);
	comm_set_select_handler(fd, COMM_SELECT_READ,
	    (PF) httpReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout, (caddr_t) data, getReadTimeout());

    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	cached_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	httpCloseAndFree(fd, data);
    } else {
	storeAppend(entry, buf, len);
	if (data->reply_hdr_state < 2)
	    httpProcessReplyHeader(data, buf);
	comm_set_select_handler(fd, COMM_SELECT_READ,
	    (PF) httpReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout, (caddr_t) data, getReadTimeout());
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
void httpSendComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(11, 5, "httpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);

    if (buf) {
	put_free_8k_page(buf);	/* Allocated by httpSendRequest. */
	buf = NULL;
    }
    data->icp_page_ptr = NULL;	/* So lifetime expire doesn't re-free */
    data->icp_rwd_ptr = NULL;	/* Don't double free in lifetimeexpire */

    if (errflag) {
	cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	httpCloseAndFree(fd, data);
	return;
    } else {
	/* Schedule read reply. */
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) httpReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout,
	    (caddr_t) data,
	    getReadTimeout());
	comm_set_fd_lifetime(fd, -1);	/* disable lifetime DPW */
    }
}

/* This will be called when connect completes. Write request. */
void httpSendRequest(fd, data)
     int fd;
     HttpData *data;
{
    char *xbuf = NULL;
    char *ybuf = NULL;
    char *buf = NULL;
    char *t = NULL;
    char *post_buf = NULL;
    static char *crlf = "\r\n";
    static char *HARVEST_PROXY_TEXT = "via Harvest Cache version";
    int len = 0;
    int buflen;

    debug(11, 5, "httpSendRequest: FD %d: data %p.\n", fd, data);
    buflen = strlen(data->type) + strlen(data->request);
    if (data->req_hdr)
	buflen += strlen(data->req_hdr);
    buflen += 512;		/* lots of extra */

    if (!strcasecmp(data->type, "POST") && data->req_hdr) {
	if ((t = strstr(data->req_hdr, "\r\n\r\n"))) {
	    post_buf = xstrdup(t + 4);
	    *(t + 4) = '\0';
	}
    }
    /* Since we limit the URL read to a 4K page, I doubt that the
     * mime header could be longer than an 8K page */
    buf = (char *) get_free_8k_page();
    data->icp_page_ptr = buf;
    if (buflen > DISK_PAGE_SIZE) {
	debug(11, 0, "Mime header length %d is breaking ICP code\n", buflen);
    }
    memset(buf, '\0', buflen);

    sprintf(buf, "%s %s ", data->type, data->request);
    len = strlen(buf);
    if (data->req_hdr) {	/* we have to parse the request header */
	xbuf = xstrdup(data->req_hdr);
	for (t = strtok(xbuf, crlf); t; t = strtok(NULL, crlf)) {
	    if (strncasecmp(t, "User-Agent:", 11) == 0) {
		ybuf = (char *) get_free_4k_page();
		memset(ybuf, '\0', SM_PAGE_SIZE);
		sprintf(ybuf, "%s %s %s", t, HARVEST_PROXY_TEXT, SQUID_VERSION);
		t = ybuf;
	    }
#ifdef 0
	    if (strncasecmp(t, "If-Modified-Since:", 18) == 0)
		continue;
#endif
	    if (len + (int) strlen(t) > buflen - 10)
		continue;
	    strcat(buf, t);
	    strcat(buf, crlf);
	    len += strlen(t) + 2;
	}
	xfree(xbuf);
	if (ybuf) {
	    put_free_4k_page(ybuf);
	    ybuf = NULL;
	}
    }
    strcat(buf, crlf);
    len += 2;
    if (post_buf) {
	strcat(buf, post_buf);
	len += strlen(post_buf);
	xfree(post_buf);
    }
    debug(11, 6, "httpSendRequest: FD %d: buf '%s'\n", fd, buf);
    data->icp_rwd_ptr = icpWrite(fd, buf, len, 30, httpSendComplete, (caddr_t) data);
}

void httpConnInProgress(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = data->entry;

    if (comm_connect(fd, data->host, data->port) != COMM_OK)
	switch (errno) {
	case EINPROGRESS:
	case EALREADY:
	    /* schedule this handler again */
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) httpConnInProgress,
		(caddr_t) data);
	    return;
	case EISCONN:
	    break;		/* cool, we're connected */
	default:
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    httpCloseAndFree(fd, data);
	    return;
	}
    /* Call the real write handler, now that we're fully connected */
    comm_set_select_handler(fd, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (caddr_t) data);
}

int proxyhttpStart(e, url, entry)
     edge *e;
     char *url;
     StoreEntry *entry;
{
    int sock;
    int status;
    HttpData *data = NULL;

    debug(11, 3, "proxyhttpStart: <URL:%s>\n", url);
    debug(11, 10, "proxyhttpStart: HTTP request header:\n%s\n",
	entry->mem_obj->mime_hdr);

    data = (HttpData *) xcalloc(1, sizeof(HttpData));
    data->entry = entry;

    strncpy(data->request, url, sizeof(data->request) - 1);
    data->type = HTTP_OPS[entry->type_id];
    data->port = e->ascii_port;
    data->req_hdr = entry->mem_obj->mime_hdr;
    strncpy(data->host, e->host, sizeof(data->host) - 1);

    if (e->proxy_only)
	storeStartDeleteBehind(entry);

    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(11, 4, "proxyhttpStart: Failed because we're out of sockets.\n");
	cached_error_entry(entry, ERR_NO_FDS, xstrerror());
	safe_free(data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(11, 4, "proxyhttpstart: Called without IP entry in ipcache. OR lookup failed.\n");
	cached_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	httpCloseAndFree(sock, data);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    httpCloseAndFree(sock, data);
	    e->last_fail_time = cached_curtime;
	    e->neighbor_up = 0;
	    return COMM_ERROR;
	} else {
	    debug(11, 5, "proxyhttpStart: FD %d: EINPROGRESS.\n", sock);
	    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
		(PF) httpLifetimeExpire, (caddr_t) data);
	    comm_set_select_handler(sock, COMM_SELECT_WRITE,
		(PF) httpConnInProgress, (caddr_t) data);
	    return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    fd_note(sock, entry->url);
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) httpLifetimeExpire, (caddr_t) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (caddr_t) data);
    return COMM_OK;

}

int httpStart(unusedfd, url, type, req_hdr, entry)
     int unusedfd;
     char *url;
     char *type;
     char *req_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    HttpData *data = NULL;

    debug(11, 3, "httpStart: %s <URL:%s>\n", type, url);
    debug(11, 10, "httpStart: req_hdr '%s'\n", req_hdr);

    data = (HttpData *) xcalloc(1, sizeof(HttpData));
    data->entry = entry;
    data->type = type;
    data->req_hdr = req_hdr;

    /* Parse url. */
    if (http_url_parser(url, data->host, &data->port, data->request)) {
	cached_error_entry(entry, ERR_INVALID_URL, NULL);
	safe_free(data);
	return COMM_ERROR;
    }
    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(11, 4, "httpStart: Failed because we're out of sockets.\n");
	cached_error_entry(entry, ERR_NO_FDS, xstrerror());
	safe_free(data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(11, 4, "httpstart: Called without IP entry in ipcache. OR lookup failed.\n");
	cached_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	httpCloseAndFree(sock, data);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    httpCloseAndFree(sock, data);
	    return COMM_ERROR;
	} else {
	    debug(11, 5, "httpStart: FD %d: EINPROGRESS.\n", sock);
	    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
		(PF) httpLifetimeExpire, (caddr_t) data);
	    comm_set_select_handler(sock, COMM_SELECT_WRITE,
		(PF) httpConnInProgress, (caddr_t) data);
	    return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    fd_note(sock, entry->url);
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) httpLifetimeExpire, (caddr_t) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (caddr_t) data);
    return COMM_OK;
}
