/* $Id: ftp.cc,v 1.21 1996/04/04 18:41:24 wessels Exp $ */

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

typedef struct _Ftpdata {
    StoreEntry *entry;
    char type_id;
    char host[SQUIDHOSTNAMELEN + 1];
    char request[MAX_URL];
    char user[MAX_URL];
    char password[MAX_URL];
    char *type;
    char *mime_hdr;
    int ftp_fd;
    char *icp_page_ptr;		/* Used to send proxy-http request: 
				 * put_free_8k_page(me) if the lifetime
				 * expires */
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
    int got_marker;		/* denotes end of successful request */
} FtpData;

static void ftpCloseAndFree(fd, data)
     int fd;
     FtpData *data;
{
    if (fd > -1)
	comm_close(fd);
    xfree(data);
}

/* XXX: this does not support FTP on a different port! */
int ftp_url_parser(url, data)
     char *url;
     FtpData *data;
{
    static char atypebuf[MAX_URL];
    static char hostbuf[MAX_URL];
    char *tmp = NULL;
    int t;
    char *host = data->host;
    char *request = data->request;
    char *user = data->user;
    char *password = data->password;

    /* initialize everything */
    atypebuf[0] = hostbuf[0] = '\0';
    request[0] = host[0] = user[0] = password[0] = '\0';

    t = sscanf(url, "%[a-zA-Z]://%[^/]%s", atypebuf, hostbuf, request);
    if ((t < 2) ||
	!(!strcasecmp(atypebuf, "ftp") || !strcasecmp(atypebuf, "file"))) {
	return -1;
    } else if (t == 2) {	/* no request */
	strcpy(request, "/");
    } else {
	tmp = url_convert_hex(request);		/* convert %xx to char */
	strncpy(request, tmp, MAX_URL);
	safe_free(tmp);
    }

    /* url address format is something like this:
     * [ userid [ : password ] @ ] host 
     * or possibly even
     * [ [ userid ] [ : [ password ] ] @ ] host
     * 
     * So we must try to make sense of it.  */

    /* XXX: this only support [user:passwd@]host */
    t = sscanf(hostbuf, "%[^:]:%[^@]@%s", user, password, host);
    if (t < 3) {
	strcpy(host, user);	/* no login/passwd information */
	strcpy(user, "anonymous");
	strcpy(password, getFtpUser());
    }
    /* we need to convert user and password for URL encodings */
    tmp = url_convert_hex(user);
    strcpy(user, tmp);
    safe_free(tmp);

    tmp = url_convert_hex(password);
    strcpy(password, tmp);
    safe_free(tmp);

    return 0;
}

int ftpCachable(url)
     char *url;
{
    stoplist *p = NULL;

    /* scan stop list */
    p = ftp_stoplist;
    while (p) {
	if (strstr(url, p->key))
	    return 0;
	p = p->next;
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
    if (data->icp_page_ptr) {
	put_free_8k_page(data->icp_page_ptr, __FILE__, __LINE__);
	data->icp_page_ptr = NULL;
    }
    safe_free(data->icp_rwd_ptr);
    cached_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    ftpCloseAndFree(fd, data);
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
		    (caddr_t) data);
		comm_set_stall(fd, getStallDelay());	/* dont try reading again for a while */
		return 0;
	    }
	} else {
	    /* we can terminate connection right now */
	    cached_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    ftpCloseAndFree(fd, data);
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
		(PF) ftpReadReply, (caddr_t) data);
	    /* note there is no ftpReadReplyTimeout.  Timeouts are handled
	     * by `ftpget'. */
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    BIT_SET(entry->flag, RELEASE_REQUEST);
	    cached_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    ftpCloseAndFree(fd, data);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	cached_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	ftpCloseAndFree(fd, data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	if (!data->got_marker) {
	    /* If we didn't see the magic marker, assume the transfer
	     * failed and arrange so the object gets ejected and
	     * never gets to disk. */
	    debug(9, 1, "ftpReadReply: Didn't see magic marker, purging <URL:%s>.\n", entry->url);
	    entry->expires = cached_curtime + getNegativeTTL();
	    BIT_RESET(entry->flag, CACHABLE);
	    BIT_SET(entry->flag, RELEASE_REQUEST);
	} else if (!(entry->flag & DELETE_BEHIND)) {
	    entry->expires = cached_curtime + ttlSet(entry);
	}
	/* update fdstat and fdtable */
	storeComplete(entry);
	ftpCloseAndFree(fd, data);
    } else if (((entry->mem_obj->e_current_len + len) > getFtpMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (caddr_t) data);
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	cached_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	ftpCloseAndFree(fd, data);
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
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) ftpLifetimeExpire,
	    (caddr_t) data,
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
	put_free_8k_page(buf, __FILE__, __LINE__);	/* Allocated by ftpSendRequest. */
	buf = NULL;
    }
    data->icp_page_ptr = NULL;	/* So lifetime expire doesn't re-free */
    data->icp_rwd_ptr = NULL;	/* Don't double free in lifetimeexpire */

    if (errflag) {
	cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	ftpCloseAndFree(fd, data);
	return;
    } else {
	comm_set_select_handler(data->ftp_fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(data->ftp_fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) ftpLifetimeExpire,
	    (caddr_t) data, getReadTimeout());
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

    buflen = strlen(data->request) + 256;
    buf = (char *) get_free_8k_page(__FILE__, __LINE__);
    data->icp_page_ptr = buf;
    memset(buf, '\0', buflen);

    path = data->request;
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

    /* Remove leading slash from FTP url-path so that we can
     *  handle ftp://user:pw@host/path objects where path and /path
     *  are quite different.         -DW */
    if (!strcmp(path, "/"))
	*path = '.';
    if (*path == '/')
	path++;

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
    strcat(buf, "-h ");		/* httpify */
    strcat(buf, "- ");		/* stdout */
    strcat(buf, data->host);
    strcat(buf, space);
    strcat(buf, path);
    strcat(buf, space);
    strcat(buf, mode);		/* A or I */
    strcat(buf, space);
    strcat(buf, data->user);
    strcat(buf, space);
    strcat(buf, data->password);
    strcat(buf, space);
    debug(9, 5, "ftpSendRequest: FD %d: buf '%s'\n", fd, buf);
    data->icp_rwd_ptr = icpWrite(fd, buf, strlen(buf), 30, ftpSendComplete, (caddr_t) data);
}

void ftpConnInProgress(fd, data)
     int fd;
     FtpData *data;
{
    StoreEntry *entry = data->entry;

    debug(9, 5, "ftpConnInProgress: FD %d\n", fd);

    if (comm_connect(fd, "localhost", 3131) != COMM_OK)
	switch (errno) {
	case EINPROGRESS:
	case EALREADY:
	    /* schedule this handler again */
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) ftpConnInProgress,
		(caddr_t) data);
	    return;
	case EISCONN:
	    debug(9, 5, "ftpConnInProgress: FD %d is now connected.", fd);
	    break;		/* cool, we're connected */
	default:
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    ftpCloseAndFree(fd, data);
	    return;
	}
    /* Call the real write handler, now that we're fully connected */
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) ftpSendRequest,
	(caddr_t) data);
}


int ftpStart(unusedfd, url, entry)
     int unusedfd;
     char *url;
     StoreEntry *entry;
{
    FtpData *data = NULL;
    int status;

    debug(9, 3, "FtpStart: FD %d <URL:%s>\n", unusedfd, url);

    data = (FtpData *) xcalloc(1, sizeof(FtpData));
    data->entry = entry;

    /* Parse url. */
    if (ftp_url_parser(url, data)) {
	cached_error_entry(entry, ERR_INVALID_URL, NULL);
	safe_free(data);
	return COMM_ERROR;
    }
    debug(9, 5, "FtpStart: FD %d, host=%s, request=%s, user=%s, passwd=%s\n",
	unusedfd, data->host, data->request, data->user, data->password);

    data->ftp_fd = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (data->ftp_fd == COMM_ERROR) {
	cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	safe_free(data);
	return COMM_ERROR;
    }
    /* Pipe/socket created ok */

    /* Now connect ... */
    if ((status = comm_connect(data->ftp_fd, "localhost", 3131))) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    ftpCloseAndFree(data->ftp_fd, data);
	    return COMM_ERROR;
	} else {
	    debug(9, 5, "ftpStart: FD %d: EINPROGRESS.\n", data->ftp_fd);
	    comm_set_select_handler(data->ftp_fd, COMM_SELECT_LIFETIME,
		(PF) ftpLifetimeExpire, (caddr_t) data);
	    comm_set_select_handler(data->ftp_fd, COMM_SELECT_WRITE,
		(PF) ftpConnInProgress, (caddr_t) data);
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
	(caddr_t) data);
    comm_set_fd_lifetime(data->ftp_fd,
	getClientLifetime());
    comm_set_select_handler(data->ftp_fd,
	COMM_SELECT_LIFETIME,
	(PF) ftpLifetimeExpire,
	(caddr_t) data);
    if (!BIT_TEST(entry->flag, ENTRY_PRIVATE))
	storeSetPublicKey(entry);	/* Make it public */

    return COMM_OK;
}

int ftpInitialize()
{
    int pid;
    int fd;
    int p[2];
    static char pbuf[128];
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
	return 0;
    }
    /* child */
    dup2(p[0], 0);
    dup2(fileno(debug_log), 2);
    close(p[0]);
    close(p[1]);
    /* inherit stdin,stdout,stderr */
    for (fd = 3; fd < fdstat_biggest_fd(); fd++)
	(void) close(fd);
    sprintf(pbuf, "%d", 3131);
    execlp(ftpget, ftpget, "-D26,1", "-S", pbuf, NULL);
    debug(9, 0, "ftpInitialize: %s: %s\n", ftpget, xstrerror());
    _exit(1);
    return (1);			/* eliminate compiler warning */
}
