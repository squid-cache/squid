/* $Id: ftp.cc,v 1.39 1996/05/03 22:56:25 wessels Exp $ */

/*
 * DEBUG: Section 9           ftp: FTP
 */

#include "squid.h"

#define FTP_DELETE_GAP  (64*1024)
#define READBUFSIZ	4096
#define MAGIC_MARKER    "\004\004\004"	/* No doubt this should be more configurable */
#define MAGIC_MARKER_SZ 3

static char ftpASCII[] = "A";
static char ftpBinary[] = "I";
static char localhost[] = "127.0.0.1";
static int ftpget_server_pipe = -1;

typedef struct _Ftpdata {
    StoreEntry *entry;
    request_t *request;
    char user[MAX_URL];
    char password[MAX_URL];
    char *reply_hdr;
    int ftp_fd;
    char *icp_page_ptr;		/* Used to send proxy-http request: 
				 * put_free_8k_page(me) if the lifetime
				 * expires */
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
    int got_marker;		/* denotes end of successful request */
    int reply_hdr_state;
} FtpData;


/* Local functions */
static int ftpStateFree _PARAMS((int fd, FtpData * ftpState));
static void ftpProcessReplyHeader _PARAMS((FtpData * data, char *buf, int size));
static void ftpServerClosed _PARAMS((int fd, void *nodata));
static void ftp_login_parser _PARAMS((char *login, FtpData * data));

/* Global functions not declared in ftp.h */
void ftpLifetimeExpire _PARAMS((int fd, FtpData * data));
int ftpReadReply _PARAMS((int fd, FtpData * data));
void ftpSendComplete _PARAMS((int fd, char *buf, int size, int errflag, FtpData * data));
void ftpSendRequest _PARAMS((int fd, FtpData * data));
void ftpConnInProgress _PARAMS((int fd, FtpData * data));
void ftpServerClose _PARAMS((void));

static int ftpStateFree(fd, ftpState)
     int fd;
     FtpData *ftpState;
{
    if (ftpState == NULL)
	return 1;
    if (ftpState->reply_hdr) {
	put_free_8k_page(ftpState->reply_hdr);
	ftpState->reply_hdr = NULL;
    }
    if (ftpState->icp_page_ptr) {
	put_free_8k_page(ftpState->icp_page_ptr);
	ftpState->icp_page_ptr = NULL;
    }
    if (ftpState->icp_rwd_ptr)
	safe_free(ftpState->icp_rwd_ptr);
    xfree(ftpState);
    return 0;
}

static void ftp_login_parser(login, data)
     char *login;
     FtpData *data;
{
    char *user = data->user;
    char *password = data->password;
    char *s = NULL;

    strcpy(user, login);
    s = strchr(user, ':');
    if (s) {
	*s = 0;
	strcpy(password, s + 1);
    } else {
	strcpy(password, "");
    }

    if (!*user && !*password) {
	strcpy(user, "anonymous");
	strcpy(password, getFtpUser());
    }
}

int ftpCachable(url)
     char *url;
{
    wordlist *p = NULL;

    /* scan stop list */
    for (p = getFtpStoplist(); p; p = p->next) {
	if (strstr(url, p->key))
	    return 0;
    }

    /* else cachable */
    return 1;
}

/* This will be called when socket lifetime is expired. */
void ftpLifetimeExpire(fd, data)
     int fd;
     FtpData *data;
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(9, 4, "ftpLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);
    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    comm_close(fd);
}


/* This is too much duplicated code from httpProcessReplyHeader.  Only
 * difference is FtpData vs HttpData. */
static void ftpProcessReplyHeader(data, buf, size)
     FtpData *data;
     char *buf;			/* chunk just read by ftpReadReply() */
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

    debug(11, 3, "ftpProcessReplyHeader: key '%s'\n", entry->key);

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
	    debug(11, 3, "ftpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", entry->key);
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
	debug(11, 7, "ftpProcessReplyHeader: hdr_sz = %d\n", reply->hdr_sz);
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
	    debug(11, 3, "ftpProcessReplyHeader: HTTP CODE: %d\n", reply->code);
	switch (reply->code) {
	case 200:		/* OK */
	case 203:		/* Non-Authoritative Information */
	case 300:		/* Multiple Choices */
	case 301:		/* Moved Permanently */
	case 410:		/* Gone */
	    /* These can be cached for a long time, make the key public */
	    entry->expires = squid_curtime + ttlSet(entry);
	    if (BIT_TEST(entry->flag, CACHABLE))
		storeSetPublicKey(entry);
	    break;
	case 304:		/* Not Modified */
	case 401:		/* Unauthorized */
	case 407:		/* Proxy Authentication Required */
	    /* These should never be cached at all */
	    storeSetPrivateKey(entry);
	    storeExpireNow(entry);
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	    break;
	default:
	    /* These can be negative cached, make key public */
	    entry->expires = squid_curtime + getNegativeTTL();
	    if (BIT_TEST(entry->flag, CACHABLE))
		storeSetPublicKey(entry);
	    break;
	}
    }
}


/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
int ftpReadReply(fd, data)
     int fd;
     FtpData *data;
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
	    if ((clen - off) > FTP_DELETE_GAP) {
		debug(9, 3, "ftpReadReply: Read deferred for Object: %s\n",
		    entry->url);
		debug(9, 3, "--> Current Gap: %d bytes\n", clen - off);
		/* reschedule, so it will automatically be reactivated when
		 * Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) ftpReadReply,
		    (void *) data);
		/* dont try reading again for a while */
		comm_set_stall(fd, getStallDelay());
		return 0;
	    }
	} else {
	    /* we can terminate connection right now */
	    squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    comm_close(fd);
	    return 0;
	}
    }
    errno = 0;
    len = read(fd, buf, READBUFSIZ);
    debug(9, 5, "ftpReadReply: FD %d, Read %d bytes\n", fd, len);

    if (len < 0) {
	debug(9, 1, "ftpReadReply: read error: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) ftpReadReply, (void *) data);
	    /* note there is no ftpReadReplyTimeout.  Timeouts are handled
	     * by `ftpget'. */
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
	if (!data->got_marker) {
	    /* If we didn't see the magic marker, assume the transfer
	     * failed and arrange so the object gets ejected and
	     * never gets to disk. */
	    debug(9, 1, "ftpReadReply: Didn't see magic marker, purging <URL:%s>.\n", entry->url);
	    entry->expires = squid_curtime + getNegativeTTL();
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	} else if (!(entry->flag & DELETE_BEHIND)) {
	    entry->expires = squid_curtime + ttlSet(entry);
	}
	/* update fdstat and fdtable */
	storeComplete(entry);
	comm_close(fd);
    } else if (((entry->mem_obj->e_current_len + len) > getFtpMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (void *) data);
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	comm_close(fd);
    } else {
	/* check for a magic marker at the end of the read */
	data->got_marker = 0;
	if (len >= MAGIC_MARKER_SZ) {
	    if (!memcmp(MAGIC_MARKER, buf + len - MAGIC_MARKER_SZ, MAGIC_MARKER_SZ)) {
		data->got_marker = 1;
		len -= MAGIC_MARKER_SZ;
	    }
	}
	storeAppend(entry, buf, len);
	if (data->reply_hdr_state < 2 && len > 0)
	    ftpProcessReplyHeader(data, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (void *) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) ftpLifetimeExpire,
	    (void *) data,
	    getReadTimeout());
    }
    return 0;
}

void ftpSendComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     FtpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(9, 5, "ftpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);

    if (buf) {
	put_free_8k_page(buf);	/* Allocated by ftpSendRequest. */
	buf = NULL;
    }
    data->icp_page_ptr = NULL;	/* So lifetime expire doesn't re-free */
    data->icp_rwd_ptr = NULL;	/* Don't double free in lifetimeexpire */

    if (errflag) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    } else {
	comm_set_select_handler(data->ftp_fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (void *) data);
	comm_set_select_handler_plus_timeout(data->ftp_fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) ftpLifetimeExpire,
	    (void *) data, getReadTimeout());
    }
}

void ftpSendRequest(fd, data)
     int fd;
     FtpData *data;
{
    char *ext = NULL;
    ext_table_entry *e = NULL;
    int l;
    char *path = NULL;
    char *mode = NULL;
    char *buf = NULL;
    static char tbuf[BUFSIZ];
    static char opts[BUFSIZ];
    static char *space = " ";
    char *s = NULL;
    int got_timeout = 0;
    int got_negttl = 0;
    int buflen;

    debug(9, 5, "ftpSendRequest: FD %d\n", fd);

    buflen = strlen(data->request->urlpath) + 256;
    buf = (char *) get_free_8k_page();
    data->icp_page_ptr = buf;
    memset(buf, '\0', buflen);

    path = data->request->urlpath;
    l = strlen(path);
    if (path[l - 1] == '/')
	mode = ftpASCII;
    else {
	if ((ext = strrchr(path, '.')) != NULL) {
	    ext++;
	    mode = ((e = mime_ext_to_type(ext)) &&
		strncmp(e->mime_type, "text", 4) == 0) ? ftpASCII :
		ftpBinary;
	} else
	    mode = ftpBinary;
    }

#ifdef NO_NEED_TO_DO_THIS
    /* Remove leading slash from FTP url-path so that we can
     *  handle ftp://user:pw@host/path objects where path and /path
     *  are quite different.         -DW */
    if (!strcmp(path, "/"))
	*path = '.';
    if (*path == '/')
	path++;
#endif

    /* Start building the buffer ... */

    strcat(buf, getFtpProgram());
    strcat(buf, space);

    strncpy(opts, getFtpOptions(), BUFSIZ);
    for (s = strtok(opts, w_space); s; s = strtok(NULL, w_space)) {
	strcat(buf, s);
	strcat(buf, space);
	if (!strncmp(s, "-t", 2))
	    got_timeout = 1;
	if (!strncmp(s, "-n", 2))
	    got_negttl = 1;
    }
    if (!got_timeout) {
	sprintf(tbuf, "-t %d ", getReadTimeout());
	strcat(buf, tbuf);
    }
    if (!got_negttl) {
	sprintf(tbuf, "-n %d ", getNegativeTTL());
	strcat(buf, tbuf);
    }
    if (data->request->port) {
	sprintf(tbuf, "-P %d ", data->request->port);
	strcat(buf, tbuf);
    }
    strcat(buf, "-h ");		/* httpify */
    strcat(buf, "- ");		/* stdout */
    strcat(buf, data->request->host);
    strcat(buf, space);
    strcat(buf, *path ? path : "\"\"");
    strcat(buf, space);
    strcat(buf, mode);		/* A or I */
    strcat(buf, space);
    strcat(buf, *data->user ? data->user : "\"\"");
    strcat(buf, space);
    strcat(buf, *data->password ? data->password : "\"\"");
    strcat(buf, "\n");
    debug(9, 5, "ftpSendRequest: FD %d: buf '%s'\n", fd, buf);
    data->icp_rwd_ptr = icpWrite(fd,
	buf,
	strlen(buf),
	30,
	ftpSendComplete,
	(void *) data);
}

void ftpConnInProgress(fd, data)
     int fd;
     FtpData *data;
{
    StoreEntry *entry = data->entry;

    debug(9, 5, "ftpConnInProgress: FD %d\n", fd);

    if (comm_connect(fd, localhost, CACHE_FTP_PORT) != COMM_OK) {
	switch (errno) {
	case EINPROGRESS:
	case EALREADY:
	    /* schedule this handler again */
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) ftpConnInProgress,
		(void *) data);
	    return;
	default:
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(fd);
	    return;
	}
    }
    /* Call the real write handler, now that we're fully connected */
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) ftpSendRequest,
	(void *) data);
}


int ftpStart(unusedfd, url, request, entry)
     int unusedfd;
     char *url;
     request_t *request;
     StoreEntry *entry;
{
    FtpData *data = NULL;
    int status;

    debug(9, 3, "FtpStart: FD %d <URL:%s>\n", unusedfd, url);

    data = (FtpData *) xcalloc(1, sizeof(FtpData));
    data->entry = entry;
    data->request = request;

    /* Parse login info. */
    ftp_login_parser(request->login, data);

    debug(9, 5, "FtpStart: FD %d, host=%s, path=%s, user=%s, passwd=%s\n",
	unusedfd, data->request->host, data->request->urlpath,
	data->user, data->password);

    data->ftp_fd = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (data->ftp_fd == COMM_ERROR) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	safe_free(data);
	return COMM_ERROR;
    }
    /* Pipe/socket created ok */

    /* register close handler */
    comm_set_select_handler(data->ftp_fd,
	COMM_SELECT_CLOSE,
	(PF) ftpStateFree,
	(void *) data);

    /* Now connect ... */
    if ((status = comm_connect(data->ftp_fd, localhost, CACHE_FTP_PORT))) {
	if (status != EINPROGRESS) {
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(data->ftp_fd);
	    return COMM_ERROR;
	} else {
	    debug(9, 5, "ftpStart: FD %d: EINPROGRESS.\n", data->ftp_fd);
	    comm_set_select_handler(data->ftp_fd, COMM_SELECT_LIFETIME,
		(PF) ftpLifetimeExpire, (void *) data);
	    comm_set_select_handler(data->ftp_fd, COMM_SELECT_WRITE,
		(PF) ftpConnInProgress, (void *) data);
	    return COMM_OK;
	}
    }
    fdstat_open(data->ftp_fd, Socket);
    commSetNonBlocking(data->ftp_fd);
    (void) fd_note(data->ftp_fd, entry->url);

    /* Install connection complete handler. */
    fd_note(data->ftp_fd, entry->url);
    comm_set_select_handler(data->ftp_fd,
	COMM_SELECT_WRITE,
	(PF) ftpSendRequest,
	(void *) data);
    comm_set_fd_lifetime(data->ftp_fd,
	getClientLifetime());
    comm_set_select_handler(data->ftp_fd,
	COMM_SELECT_LIFETIME,
	(PF) ftpLifetimeExpire,
	(void *) data);
    return COMM_OK;
}

static void ftpServerClosed(fd, nodata)
     int fd;
     void *nodata;
{
    static time_t last_restart = 0;
    comm_close(fd);
    if (squid_curtime - last_restart < 2) {
	debug(9, 0, "ftpget server failing too rapidly\n");
	debug(9, 0, "WARNING: FTP access is disabled!\n");
	return;
    }
    last_restart = squid_curtime;
    debug(9, 1, "Restarting ftpget server...\n");
    (void) ftpInitialize();
}

void ftpServerClose()
{
    if (ftpget_server_pipe < 0)
	return;

    comm_set_select_handler(ftpget_server_pipe,
	COMM_SELECT_EXCEPT,
	(PF) NULL,
	(void *) NULL);
    fdstat_close(ftpget_server_pipe);
    close(ftpget_server_pipe);
    ftpget_server_pipe = -1;
}


int ftpInitialize()
{
    int pid;
    int fd;
    int p[2];
    char pbuf[128];
    char *ftpget = getFtpProgram();

    if (pipe(p) < 0) {
	debug(9, 0, "ftpInitialize: pipe: %s\n", xstrerror());
	return -1;
    }
    if ((pid = fork()) < 0) {
	debug(9, 0, "ftpInitialize: fork: %s\n", xstrerror());
	return -1;
    }
    if (pid != 0) {		/* parent */
	close(p[0]);
	fdstat_open(p[1], Pipe);
	fd_note(p[1], "ftpget -S");
	fcntl(p[1], F_SETFD, 1);	/* set close-on-exec */
	/* if ftpget -S goes away, this handler should get called */
	comm_set_select_handler(p[1],
	    COMM_SELECT_EXCEPT,
	    (PF) ftpServerClosed,
	    (void *) NULL);
	ftpget_server_pipe = p[1];
	return 0;
    }
    /* child */
    /* give up all extra priviligies */
    no_suid();
    /* set up stdin,stdout */
    dup2(p[0], 0);
    dup2(fileno(debug_log), 2);
    close(p[0]);
    close(p[1]);
    /* inherit stdin,stdout,stderr */
    for (fd = 3; fd < fdstat_biggest_fd(); fd++)
	(void) close(fd);
    sprintf(pbuf, "%d", CACHE_FTP_PORT);
    execlp(ftpget, ftpget, "-S", pbuf, NULL);
    debug(9, 0, "ftpInitialize: %s: %s\n", ftpget, xstrerror());
    _exit(1);
    return (1);			/* eliminate compiler warning */
}
