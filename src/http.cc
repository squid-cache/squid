/* $Id: http.cc,v 1.56 1996/04/17 21:03:14 wessels Exp $ */

/*
 * DEBUG: Section 11          http: HTTP
 */

#include "squid.h"

#define HTTP_DELETE_GAP   (64*1024)
#define READBUFSIZ	4096

typedef struct _httpdata {
    StoreEntry *entry;
    request_t *request;
    char *req_hdr;
    char *icp_page_ptr;		/* Used to send proxy-http request: 
				 * put_free_8k_page(me) if the lifetime
				 * expires */
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
    char *reply_hdr;
    int reply_hdr_state;
    int free_request;
} HttpData;

static int httpStateFree(fd, httpState)
     int fd;
     HttpData *httpState;
{
    if (httpState == NULL)
	return 1;
    if (httpState->reply_hdr) {
	put_free_8k_page(httpState->reply_hdr);
	httpState->reply_hdr = NULL;
    }
    if (httpState->icp_page_ptr) {
	put_free_8k_page(httpState->icp_page_ptr);
	httpState->icp_page_ptr = NULL;
    }
    if (httpState->icp_rwd_ptr)
	safe_free(httpState->icp_rwd_ptr);
    if (httpState->free_request)
	safe_free(httpState->request);
    xfree(httpState);
    return 0;
}

int httpCachable(url, method)
     char *url;
     int method;
{
    wordlist *p = NULL;

    /* GET and HEAD are cachable. Others are not. */
    if (method != METHOD_GET && method != METHOD_HEAD)
	return 0;

    /* scan stop list */
    for (p = getHttpStoplist(); p; p = p->next) {
	if (strstr(url, p->key))
	    return 0;
    }

    /* else cachable */
    return 1;
}

/* This will be called when timeout on read. */
static void httpReadReplyTimeout(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(11, 4, "httpReadReplyTimeout: FD %d: <URL:%s>\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    comm_set_select_handler(fd, COMM_SELECT_READ, 0, 0);
    comm_close(fd);
}

/* This will be called when socket lifetime is expired. */
static void httpLifetimeExpire(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(11, 4, "httpLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);

    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    comm_set_select_handler(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, 0, 0);
    comm_close(fd);
}


static void httpProcessReplyHeader(data, buf, size)
     HttpData *data;
     char *buf;			/* chunk just read by httpReadReply() */
     int size;
{
    char *s = NULL;
    char *t = NULL;
    char *t1 = NULL;
    char *t2 = NULL;
    StoreEntry *entry = data->entry;
    char *headers = NULL;
    int room;
    int hdr_len;
    struct _http_reply *reply = NULL;

    debug(11, 3, "httpProcessReplyHeader: key '%s'\n", entry->key);

    if (data->reply_hdr == NULL) {
	data->reply_hdr = get_free_8k_page();
	memset(data->reply_hdr, '\0', 8192);
    }
    if (data->reply_hdr_state == 0) {
	hdr_len = strlen(data->reply_hdr);
	room = 8191 - hdr_len;
	strncat(data->reply_hdr, buf, room < size ? room : size);
	hdr_len += room < size ? room : size;
	if (hdr_len > 4 && strncmp(data->reply_hdr, "HTTP/", 5)) {
	    debug(11, 3, "httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", entry->key);
	    data->reply_hdr_state += 2;
	    return;
	}
	/* need to take the lowest, non-zero pointer to the end of the headers.
	 * some objects have \n\n separating header and body, but \r\n\r\n in
	 * body text. */
	t1 = strstr(data->reply_hdr, "\r\n\r\n");
	t2 = strstr(data->reply_hdr, "\n\n");
	if (t1 && t2)
	    t = t2 < t1 ? t2 : t1;
	else
	    t = t2 ? t2 : t1;
	if (!t)
	    return;		/* headers not complete */
	t += (t == t1 ? 4 : 2);
	*t = '\0';
	reply = entry->mem_obj->reply;
	reply->hdr_sz = t - data->reply_hdr;
	debug(11, 7, "httpProcessReplyHeader: hdr_sz = %d\n", reply->hdr_sz);
	data->reply_hdr_state++;
    }
    if (data->reply_hdr_state == 1) {
	headers = xstrdup(data->reply_hdr);
	data->reply_hdr_state++;
	debug(11, 9, "GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    data->reply_hdr);
	t = strtok(headers, "\n");
	while (t) {
	    s = t + strlen(t);
	    while (*s == '\r')
		*s-- = '\0';
	    if (!strncasecmp(t, "HTTP", 4)) {
		sscanf(t + 1, "%lf", &reply->version);
		if ((t = strchr(t, ' '))) {
		    t++;
		    reply->code = atoi(t);
		}
	    } else if (!strncasecmp(t, "Content-type:", 13)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    strncpy(reply->content_type, t, HTTP_REPLY_FIELD_SZ - 1);
		}
	    } else if (!strncasecmp(t, "Content-length:", 15)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    reply->content_length = atoi(t);
		}
	    } else if (!strncasecmp(t, "Date:", 5)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    strncpy(reply->date, t, HTTP_REPLY_FIELD_SZ - 1);
		}
	    } else if (!strncasecmp(t, "Expires:", 8)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    strncpy(reply->expires, t, HTTP_REPLY_FIELD_SZ - 1);
		}
	    } else if (!strncasecmp(t, "Last-Modified:", 14)) {
		if ((t = strchr(t, ' '))) {
		    t++;
		    strncpy(reply->last_modified, t, HTTP_REPLY_FIELD_SZ - 1);
		}
	    }
	    t = strtok(NULL, "\n");
	}
	safe_free(headers);
	if (reply->code)
	    debug(11, 3, "httpProcessReplyHeader: HTTP CODE: %d\n", reply->code);
	switch (reply->code) {
	case 200:		/* OK */
	case 203:		/* Non-Authoritative Information */
	case 300:		/* Multiple Choices */
	case 301:		/* Moved Permanently */
	case 410:		/* Gone */
	    /* These can be cached for a long time, make the key public */
	    entry->expires = squid_curtime + ttlSet(entry);
	    if (!BIT_TEST(entry->flag, ENTRY_PRIVATE))
		storeSetPublicKey(entry);
	    break;
	case 401:		/* Unauthorized */
	case 407:		/* Proxy Authentication Required */
	    /* These should never be cached at all */
	    if (BIT_TEST(entry->flag, ENTRY_PRIVATE))
		storeSetPrivateKey(entry);
	    storeExpireNow(entry);
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	    break;
	default:
	    /* These can be negative cached, make key public */
	    entry->expires = squid_curtime + getNegativeTTL();
	    if (!BIT_TEST(entry->flag, ENTRY_PRIVATE))
		storeSetPublicKey(entry);
	    break;
	}
    }
}


/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
/* XXX this function is too long! */
static void httpReadReply(fd, data)
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
		debug(11, 3, "httpReadReply: Read deferred for Object: %s\n",
		    entry->url);
		debug(11, 3, "                Current Gap: %d bytes\n", clen - off);
		/* reschedule, so it will be automatically reactivated
		 * when Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) httpReadReply,
		    (void *) data);
		/* don't install read timeout until we are below the GAP */
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) NULL,
		    (void *) NULL,
		    (time_t) 0);
		/* dont try reading again for a while */
		comm_set_stall(fd, getStallDelay());
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    comm_close(fd);
	    return;
	}
    }
    errno = 0;
    len = read(fd, buf, READBUFSIZ);
    debug(11, 5, "httpReadReply: FD %d: len %d.\n", fd, len);

    if (len < 0) {
	debug(11, 2, "httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) httpReadReply, (void *) data);
	    comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
		(PF) httpReadReplyTimeout, (void *) data, getReadTimeout());
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	storeComplete(entry);
	comm_close(fd);
    } else if ((entry->mem_obj->e_current_len + len) > getHttpMax() &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) httpReadReply,
	    (void *) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout,
	    (void *) data,
	    getReadTimeout());
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	comm_close(fd);
    } else {
	storeAppend(entry, buf, len);
	if (data->reply_hdr_state < 2 && len > 0)
	    httpProcessReplyHeader(data, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) httpReadReply,
	    (void *) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout,
	    (void *) data,
	    getReadTimeout());
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void httpSendComplete(fd, buf, size, errflag, data)
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
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    } else {
	/* Schedule read reply. */
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) httpReadReply,
	    (void *) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout,
	    (void *) data,
	    getReadTimeout());
	comm_set_fd_lifetime(fd, -1);	/* disable lifetime DPW */
    }
}

/* This will be called when connect completes. Write request. */
static void httpSendRequest(fd, data)
     int fd;
     HttpData *data;
{
    char *xbuf = NULL;
    char *ybuf = NULL;
    char *buf = NULL;
    char *t = NULL;
    char *post_buf = NULL;
    static char *crlf = "\r\n";
    static char *VIA_PROXY_TEXT = "via Sqiud Cache version";
    int len = 0;
    int buflen;
    int cfd = -1;
    request_t *req = data->request;
    char *Method = RequestMethodStr[req->method];

    debug(11, 5, "httpSendRequest: FD %d: data %p.\n", fd, data);
    buflen = strlen(Method) + strlen(req->urlpath);
    if (data->req_hdr)
	buflen += strlen(data->req_hdr);
    buflen += 512;		/* lots of extra */

    if (req->method == METHOD_POST && data->req_hdr) {
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

    sprintf(buf, "%s %s HTTP/1.0\r\n", Method, req->urlpath);
    len = strlen(buf);
    if (data->req_hdr) {	/* we have to parse the request header */
	xbuf = xstrdup(data->req_hdr);
	for (t = strtok(xbuf, crlf); t; t = strtok(NULL, crlf)) {
	    if (strncasecmp(t, "User-Agent:", 11) == 0) {
		ybuf = (char *) get_free_4k_page();
		memset(ybuf, '\0', SM_PAGE_SIZE);
		sprintf(ybuf, "%s %s %s", t, VIA_PROXY_TEXT, version_string);
		t = ybuf;
	    }
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
    /* Add Forwarded: header */
    ybuf = get_free_4k_page();
    if (data->entry->mem_obj)
	cfd = data->entry->mem_obj->fd_of_first_client;
    if (cfd < 0) {
	sprintf(ybuf, "Forwarded: by http://%s:%d/\r\n",
	    getMyHostname(), getAsciiPortNum());
    } else {
	sprintf(ybuf, "Forwarded: by http://%s:%d/ for %s\r\n",
	    getMyHostname(), getAsciiPortNum(), fd_table[cfd].ipaddr);
    }
    strcat(buf, ybuf);
    len += strlen(ybuf);
    put_free_4k_page(ybuf);
    ybuf = NULL;

    strcat(buf, crlf);
    len += 2;
    if (post_buf) {
	strcat(buf, post_buf);
	len += strlen(post_buf);
	xfree(post_buf);
    }
    debug(11, 6, "httpSendRequest: FD %d: buf '%s'\n", fd, buf);
    data->icp_rwd_ptr = icpWrite(fd,
	buf,
	len,
	30,
	httpSendComplete,
	(void *) data);
}

static void httpConnInProgress(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = data->entry;
    request_t *req = data->request;

    debug(11, 5, "httpConnInProgress: FD %d data=%p\n", fd, data);

    if (comm_connect(fd, req->host, req->port) != COMM_OK) {
	debug(11, 5, "httpConnInProgress: FD %d errno=%d\n", fd, errno);
	switch (errno) {
	case EINPROGRESS:
	case EALREADY:
	    /* schedule this handler again */
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) httpConnInProgress,
		(void *) data);
	    return;
	case EISCONN:
	    break;		/* cool, we're connected */
	default:
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(fd);
	    return;
	}
    }
    /* Call the real write handler, now that we're fully connected */
    comm_set_select_handler(fd, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (void *) data);
}

int proxyhttpStart(e, url, entry)
     edge *e;
     char *url;
     StoreEntry *entry;
{
    int sock;
    int status;
    HttpData *data = NULL;
    request_t *request = NULL;

    debug(11, 3, "proxyhttpStart: \"%s %s\"\n",
	RequestMethodStr[entry->method], url);
    debug(11, 10, "proxyhttpStart: HTTP request header:\n%s\n",
	entry->mem_obj->mime_hdr);

    if (e->proxy_only)
	storeStartDeleteBehind(entry);

    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(11, 4, "proxyhttpStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    data = (HttpData *) xcalloc(1, sizeof(HttpData));
    data->entry = entry;
    data->req_hdr = entry->mem_obj->mime_hdr;
    request = (request_t *) xcalloc(1, sizeof(request_t));
    data->free_request = 1;
    data->request = request;
    /* register the handler to free HTTP state data when the FD closes */
    comm_set_select_handler(sock,
	COMM_SELECT_CLOSE,
	httpStateFree,
	(void *) data);

    request->method = entry->method;
    strncpy(request->host, e->host, SQUIDHOSTNAMELEN);
    request->port = e->ascii_port;
    strncpy(request->urlpath, url, MAX_URL);

    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(request->host)) {
	debug(11, 4, "proxyhttpstart: Called without IP entry in ipcache. OR lookup failed.\n");
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(sock);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, request->host, request->port))) {
	if (status != EINPROGRESS) {
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(sock);
	    e->last_fail_time = squid_curtime;
	    e->neighbor_up = 0;
	    return COMM_ERROR;
	} else {
	    debug(11, 5, "proxyhttpStart: FD %d: EINPROGRESS.\n", sock);
	    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
		(PF) httpLifetimeExpire, (void *) data);
	    comm_set_select_handler(sock, COMM_SELECT_WRITE,
		(PF) httpConnInProgress, (void *) data);
	    return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    fd_note(sock, entry->url);
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) httpLifetimeExpire, (void *) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (void *) data);
    return COMM_OK;
}

int httpStart(unusedfd, url, request, req_hdr, entry)
     int unusedfd;
     char *url;
     request_t *request;
     char *req_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    HttpData *data = NULL;

    debug(11, 3, "httpStart: \"%s %s\"\n",
	RequestMethodStr[request->method], url);
    debug(11, 10, "httpStart: req_hdr '%s'\n", req_hdr);

    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(11, 4, "httpStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    data = (HttpData *) xcalloc(1, sizeof(HttpData));
    data->entry = entry;
    data->req_hdr = req_hdr;
    data->request = request;
    comm_set_select_handler(sock,
	COMM_SELECT_CLOSE,
	httpStateFree,
	(void *) data);

    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(request->host)) {
	debug(11, 4, "httpstart: Called without IP entry in ipcache. OR lookup failed.\n");
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(sock);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, request->host, request->port))) {
	if (status != EINPROGRESS) {
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(sock);
	    return COMM_ERROR;
	} else {
	    debug(11, 5, "httpStart: FD %d: EINPROGRESS.\n", sock);
	    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
		(PF) httpLifetimeExpire, (void *) data);
	    comm_set_select_handler(sock, COMM_SELECT_WRITE,
		(PF) httpConnInProgress, (void *) data);
	    return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    fd_note(sock, entry->url);
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) httpLifetimeExpire, (void *) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (void *) data);
    return COMM_OK;
}
