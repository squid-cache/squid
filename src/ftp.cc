
/*
 * $Id: ftp.cc,v 1.108 1997/05/22 15:51:53 wessels Exp $
 *
 * DEBUG: section 9     File Transfer Protocol (FTP)
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

#define FTP_DELETE_GAP  (1<<18)
#define MAGIC_MARKER    "\004\004\004"	/* No doubt this should be more configurable */
#define MAGIC_MARKER_SZ 3

static int ftpget_server_read = -1;
static int ftpget_server_write = -1;
static u_short ftpget_port = 0;

typedef struct _Ftpdata {
    StoreEntry *entry;
    request_t *request;
    char user[MAX_URL];
    char password[MAX_URL];
    char *reply_hdr;
    int ftp_fd;
    int got_marker;		/* denotes end of successful request */
    int reply_hdr_state;
    int authenticated;		/* This ftp request is authenticated */
} FtpStateData;

typedef struct ftp_ctrl_t {
    request_t *request;
    StoreEntry *entry;
} ftp_ctrl_t;

/* Local functions */
static CNCB ftpConnectDone;
static CWCB ftpSendComplete;
static PF ftpReadReply;
static PF ftpSendRequest;
static PF ftpServerClosed;
static PF ftpStateFree;
static PF ftpTimeout;
static char *ftpGetBasicAuth _PARAMS((const char *));
static void ftpProcessReplyHeader _PARAMS((FtpStateData *, const char *, int));
static void ftpLoginParser _PARAMS((const char *, FtpStateData *));

/* External functions */
extern char *base64_decode _PARAMS((const char *coded));

static void
ftpStateFree(int fd, void *data)
{
    FtpStateData *ftpState = data;
    if (ftpState == NULL)
	return;
    storeUnlockObject(ftpState->entry);
    if (ftpState->reply_hdr) {
	put_free_8k_page(ftpState->reply_hdr);
	ftpState->reply_hdr = NULL;
    }
    requestUnlink(ftpState->request);
    xfree(ftpState);
}

static void
ftpLoginParser(const char *login, FtpStateData * ftpState)
{
    char *s = NULL;
    xstrncpy(ftpState->user, login, MAX_URL);
    if ((s = strchr(ftpState->user, ':'))) {
	*s = 0;
	xstrncpy(ftpState->password, s + 1, MAX_URL);
    } else {
	xstrncpy(ftpState->password, null_string, MAX_URL);
    }
    if (ftpState->user[0] || ftpState->password[0])
	return;
    xstrncpy(ftpState->user, "anonymous", MAX_URL);
    xstrncpy(ftpState->password, Config.ftpUser, MAX_URL);
}

static void
ftpTimeout(int fd, void *data)
{
    FtpStateData *ftpState = data;
    StoreEntry *entry = ftpState->entry;
    debug(9, 4, "ftpLifeTimeExpire: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    comm_close(fd);
}

/* This is too much duplicated code from httpProcessReplyHeader.  Only
 * difference is FtpStateData vs HttpData. */
static void
ftpProcessReplyHeader(FtpStateData * ftpState, const char *buf, int size)
{
    char *t = NULL;
    StoreEntry *entry = ftpState->entry;
    int room;
    int hdr_len;
    struct _http_reply *reply = entry->mem_obj->reply;

    debug(11, 3, "ftpProcessReplyHeader: key '%s'\n", entry->key);

    if (ftpState->reply_hdr == NULL)
	ftpState->reply_hdr = get_free_8k_page();
    if (ftpState->reply_hdr_state == 0) {
	hdr_len = strlen(ftpState->reply_hdr);
	room = 8191 - hdr_len;
	strncat(ftpState->reply_hdr, buf, room < size ? room : size);
	hdr_len += room < size ? room : size;
	if (hdr_len > 4 && strncmp(ftpState->reply_hdr, "HTTP/", 5)) {
	    debug(11, 3, "ftpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", entry->key);
	    ftpState->reply_hdr_state += 2;
	    return;
	}
	/* Find the end of the headers */
	if ((t = mime_headers_end(ftpState->reply_hdr)) == NULL)
	    return;		/* headers not complete */
	/* Cut after end of headers */
	*t = '\0';
	ftpState->reply_hdr_state++;
    }
    if (ftpState->reply_hdr_state == 1) {
	ftpState->reply_hdr_state++;
	debug(11, 9, "GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    ftpState->reply_hdr);
	/* Parse headers into reply structure */
	httpParseReplyHeaders(ftpState->reply_hdr, reply);
	storeTimestampsSet(entry);
	/* Check if object is cacheable or not based on reply code */
	if (reply->code)
	    debug(11, 3, "ftpProcessReplyHeader: HTTP CODE: %d\n", reply->code);
	switch (reply->code) {
	case 200:		/* OK */
	case 203:		/* Non-Authoritative Information */
	case 300:		/* Multiple Choices */
	case 301:		/* Moved Permanently */
	case 410:		/* Gone */
	    /* These can be cached for a long time, make the key public */
	    if (BIT_TEST(entry->flag, ENTRY_CACHABLE))
		storeSetPublicKey(entry);
	    break;
	case 302:		/* Moved Temporarily */
	case 304:		/* Not Modified */
	case 401:		/* Unauthorized */
	case 407:		/* Proxy Authentication Required */
	    /* These should never be cached at all */
	    storeExpireNow(entry);
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    break;
	default:
	    /* These can be negative cached, make key public */
	    storeNegativeCache(entry);
	    if (BIT_TEST(entry->flag, ENTRY_CACHABLE))
		storeSetPublicKey(entry);
	    break;
	}
    }
}


/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void
ftpReadReply(int fd, void *data)
{
    FtpStateData *ftpState = data;
    LOCAL_ARRAY(char, buf, SQUID_TCP_SO_RCVBUF);
    int len;
    int clen;
    int off;
    int bin;
    StoreEntry *entry = NULL;

    entry = ftpState->entry;
    if (protoAbortFetch(entry)) { 
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->e_current_len;
    off = storeGetLowestReaderOffset(entry);
    if ((clen - off) > FTP_DELETE_GAP) {
	if (entry->flag & CLIENT_ABORT_REQUEST) {
	    squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	    comm_close(fd);
	}
	IOStats.Ftp.reads_deferred++;
	debug(11, 3, "ftpReadReply: Read deferred for Object: %s\n",
	    entry->url);
	debug(11, 3, "                Current Gap: %d bytes\n", clen - off);
	/* reschedule, so it will be automatically reactivated
	 * when Gap is big enough. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    ftpReadReply,
	    data, 0);
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    commSetTimeout(fd, Config.Timeout.defer, NULL, NULL);
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, Config.stallDelay);
	return;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    errno = 0;
    len = read(fd, buf, SQUID_TCP_SO_RCVBUF);
    fd_bytes(fd, len, FD_READ);
    debug(9, 5, "ftpReadReply: FD %d, Read %d bytes\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Ftp.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Ftp.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1, "ftpReadReply: read error: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(fd, COMM_SELECT_READ,
		ftpReadReply, data, 0);
	    /* note there is no ftpReadReplyTimeout.  Timeouts are handled
	     * by `ftpget'. */
	} else {
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
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
	if (!ftpState->got_marker) {
	    /* If we didn't see the magic marker, assume the transfer
	     * failed and arrange so the object gets ejected and
	     * never gets to disk. */
	    debug(9, 1, "ftpReadReply: Purging '%s'\n", entry->url);
	    storeNegativeCache(entry);
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	} else {
	    storeTimestampsSet(entry);
	}
	storeComplete(entry);
	comm_close(fd);
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	comm_close(fd);
    } else {
	if (ftpState->got_marker) {
	    /* oh, this is so gross -- we found the marker at the
	     * end of the previous read, but theres more data!
	     * So put the marker back in. */
	    storeAppend(entry, MAGIC_MARKER, MAGIC_MARKER_SZ);
	}
	/* check for a magic marker at the end of the read */
	ftpState->got_marker = 0;
	if (len >= MAGIC_MARKER_SZ) {
	    if (!memcmp(MAGIC_MARKER, buf + len - MAGIC_MARKER_SZ, MAGIC_MARKER_SZ)) {
		ftpState->got_marker = 1;
		len -= MAGIC_MARKER_SZ;
	    }
	}
	storeAppend(entry, buf, len);
	if (ftpState->reply_hdr_state < 2 && len > 0)
	    ftpProcessReplyHeader(data, buf, len);
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    ftpReadReply,
	    data, 0);
    }
}

static void
ftpSendComplete(int fd, char *buf, int size, int errflag, void *data)
{
    FtpStateData *ftpState = (FtpStateData *) data;
    StoreEntry *entry = NULL;

    entry = ftpState->entry;
    debug(9, 5, "ftpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);

    if (buf) {
	put_free_8k_page(buf);	/* Allocated by ftpSendRequest. */
	buf = NULL;
    }
    if (errflag) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    commSetSelect(ftpState->ftp_fd,
	COMM_SELECT_READ,
	ftpReadReply,
	ftpState, 0);
}

static void
ftpSendRequest(int fd, void *data)
{
    FtpStateData *ftpState = data;
    char *path = NULL;
    const char *mode = NULL;
    char *buf = NULL;
    LOCAL_ARRAY(char, tbuf, BUFSIZ);
    LOCAL_ARRAY(char, opts, BUFSIZ);
    const char *const space = " ";
    char *s = NULL;
    int got_timeout = 0;
    int got_negttl = 0;

    debug(9, 5, "ftpSendRequest: FD %d\n", fd);

    buf = get_free_8k_page();

    path = ftpState->request->urlpath;
    mode = "-";			/* let ftpget figure it out */

    /* Start building the buffer ... */
    strcat(buf, Config.Program.ftpget);
    strcat(buf, space);

    xstrncpy(opts, Config.Program.ftpget_opts, BUFSIZ);
    for (s = strtok(opts, w_space); s; s = strtok(NULL, w_space)) {
	strcat(buf, s);
	strcat(buf, space);
	if (!strncmp(s, "-t", 2))
	    got_timeout = 1;
	if (!strncmp(s, "-n", 2))
	    got_negttl = 1;
    }
    if (!got_timeout) {
	sprintf(tbuf, "-t %d ", Config.Timeout.read);
	strcat(buf, tbuf);
    }
    if (!got_negttl) {
	sprintf(tbuf, "-n %d ", Config.negativeTtl);
	strcat(buf, tbuf);
    }
    if (ftpState->request->port) {
	sprintf(tbuf, "-P %d ", ftpState->request->port);
	strcat(buf, tbuf);
    }
    if ((s = Config.visibleHostname)) {
	sprintf(tbuf, "-H %s ", s);
	strcat(buf, tbuf);
    }
    if (ftpState->authenticated) {
	strcat(buf, "-a ");
    }
    if (Config.Addrs.tcp_outgoing.s_addr != no_addr.s_addr) {
	sprintf(tbuf, "-o %s ", inet_ntoa(Config.Addrs.tcp_outgoing));
	strcat(buf, tbuf);
    }
    strcat(buf, "-h ");		/* httpify */
    strcat(buf, "- ");		/* stdout */
    strcat(buf, ftpState->request->host);
    strcat(buf, space);
    strcat(buf, *path ? path : "\"\"");
    strcat(buf, space);
    strcat(buf, mode);		/* A or I */
    strcat(buf, space);
    strcat(buf, *ftpState->user ? ftpState->user : "\"\"");
    strcat(buf, space);
    strcat(buf, *ftpState->password ? ftpState->password : "\"\"");
    strcat(buf, "\n");
    debug(9, 5, "ftpSendRequest: FD %d: buf '%s'\n", fd, buf);
    comm_write(fd,
	buf,
	strlen(buf),
	ftpSendComplete,
	ftpState,
	put_free_8k_page);
}

static char *
ftpGetBasicAuth(const char *req_hdr)
{
    char *auth_hdr;
    char *t;
    if (req_hdr == NULL)
	return NULL;
    if ((auth_hdr = mime_get_header(req_hdr, "Authorization")) == NULL)
	return NULL;
    if ((t = strtok(auth_hdr, " \t")) == NULL)
	return NULL;
    if (strcasecmp(t, "Basic") != 0)
	return NULL;
    if ((t = strtok(NULL, " \t")) == NULL)
	return NULL;
    return base64_decode(t);
}

/*
 * ftpCheckAuth
 *
 * Return 1 if we have everything needed to complete this request.
 * Return 0 if something is missing.
 */
static int
ftpCheckAuth(FtpStateData * ftpState, char *req_hdr)
{
    char *orig_user;
    char *auth;
    ftpLoginParser(ftpState->request->login, ftpState);
    if (ftpState->user[0] && ftpState->password[0])
	return 1;		/* name and passwd both in URL */
    if (!ftpState->user[0] && !ftpState->password[0])
	return 1;		/* no name or passwd */
    if (ftpState->password[0])
	return 1;		/* passwd with no name? */
    /* URL has name, but no passwd */
    if ((auth = ftpGetBasicAuth(req_hdr)) == NULL)
	return 0;		/* need auth header */
    orig_user = xstrdup(ftpState->user);
    ftpLoginParser(auth, ftpState);
    if (!strcmp(orig_user, ftpState->user)) {
	xfree(orig_user);
	return 1;		/* same username */
    }
    strcpy(ftpState->user, orig_user);
    xfree(orig_user);
    return 0;			/* different username */
}

void
ftpStart(request_t * request, StoreEntry * entry)
{
    LOCAL_ARRAY(char, realm, 8192);
    char *url = entry->url;
    FtpStateData *ftpState = xcalloc(1, sizeof(FtpStateData));
    char *req_hdr;
    char *response;
    debug(9, 3, "FtpStart: '%s'\n", entry->url);
    if (ftpget_server_write < 0) {
	squid_error_entry(entry, ERR_FTP_DISABLED, NULL);
	return;
    }
    storeLockObject(entry);
    ftpState->entry = entry;
    req_hdr = entry->mem_obj->mime_hdr;
    ftpState->request = requestLink(request);
    if (!ftpCheckAuth(ftpState, req_hdr)) {
	/* This request is not fully authenticated */
	if (request->port == 21) {
	    sprintf(realm, "ftp %s", ftpState->user);
	} else {
	    sprintf(realm, "ftp %s port %d",
		ftpState->user, request->port);
	}
	response = authorization_needed_msg(request, realm);
	storeAppend(entry, response, strlen(response));
	httpParseReplyHeaders(response, entry->mem_obj->reply);
	storeComplete(entry);
	ftpStateFree(-1, ftpState);
	return;
    }
    debug(9, 5, "FtpStart: host=%s, path=%s, user=%s, passwd=%s\n",
	ftpState->request->host, ftpState->request->urlpath,
	ftpState->user, ftpState->password);
    ftpState->ftp_fd = comm_open(SOCK_STREAM,
	0,
	local_addr,
	0,
	COMM_NONBLOCKING,
	url);
    if (ftpState->ftp_fd == COMM_ERROR) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	ftpStateFree(-1, ftpState);
	return;
    }
    /* Pipe/socket created ok */
    /* register close handler */
    comm_add_close_handler(ftpState->ftp_fd,
	ftpStateFree,
	ftpState);
    commSetTimeout(ftpState->ftp_fd,
	Config.Timeout.connect,
	ftpTimeout,
	ftpState);
    commConnectStart(ftpState->ftp_fd,
	localhost,
	ftpget_port,
	ftpConnectDone,
	ftpState);
}

static void
ftpConnectDone(int fd, int status, void *data)
{
    FtpStateData *ftpState = data;
    if (status == COMM_ERROR) {
	squid_error_entry(ftpState->entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    commSetNonBlocking(fd);
    (void) fd_note(fd, ftpState->entry->url);
    /* Install connection complete handler. */
    fd_note(fd, ftpState->entry->url);
    commSetSelect(fd,
	COMM_SELECT_WRITE,
	ftpSendRequest,
	data, 0);
    if (opt_no_ipcache)
	ipcacheInvalidate(ftpState->request->host);
}

static void
ftpServerClosed(int fd, void *nodata)
{
    static time_t last_restart = 0;
    comm_close(fd);
    if (squid_curtime - last_restart < 2) {
	debug(9, 0, "ftpget server failing too rapidly\n");
	debug(9, 0, "WARNING: FTP access is disabled!\n");
	ftpget_server_write = -1;
	ftpget_server_read = -1;
	return;
    }
    last_restart = squid_curtime;
    debug(9, 1, "Restarting ftpget server...\n");
    (void) ftpInitialize();
}

void
ftpServerClose(void)
{
    /* NOTE: this function will be called repeatedly while shutdown is
     * pending */
    if (ftpget_server_read < 0)
	return;
    commSetSelect(ftpget_server_read,
	COMM_SELECT_READ,
	NULL,
	NULL, 0);
    fd_close(ftpget_server_read);
    close(ftpget_server_read);
    ftpget_server_read = -1;
    fd_close(ftpget_server_write);
    close(ftpget_server_write);
    ftpget_server_write = -1;
}


int
ftpInitialize(void)
{
    pid_t pid;
    int cfd;
    int squid_to_ftpget[2];
    int ftpget_to_squid[2];
    LOCAL_ARRAY(char, pbuf, 128);
    char *ftpget = Config.Program.ftpget;
    struct sockaddr_in S;
    int len;
    struct timeval slp;

    if (!strcmp(ftpget, "none")) {
	debug(9, 1, "ftpInitialize: ftpget is disabled.\n");
	return -1;
    }
    debug(9, 5, "ftpInitialize: Initializing...\n");
    if (pipe(squid_to_ftpget) < 0) {
	debug(50, 0, "ftpInitialize: pipe: %s\n", xstrerror());
	return -1;
    }
    if (pipe(ftpget_to_squid) < 0) {
	debug(50, 0, "ftpInitialize: pipe: %s\n", xstrerror());
	return -1;
    }
    cfd = comm_open(SOCK_STREAM,
	0,
	local_addr,
	0,
	COMM_NOCLOEXEC,
	"ftpget -S socket");
    debug(9, 5, "ftpget -S socket on FD %d\n", cfd);
    if (cfd == COMM_ERROR) {
	debug(9, 0, "ftpInitialize: Failed to create socket\n");
	return -1;
    }
    len = sizeof(S);
    memset(&S, '\0', len);
    if (getsockname(cfd, (struct sockaddr *) &S, &len) < 0) {
	debug(50, 0, "ftpInitialize: getsockname: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    ftpget_port = ntohs(S.sin_port);
    listen(cfd, Squid_MaxFD >> 2);
    if ((pid = fork()) < 0) {
	debug(50, 0, "ftpInitialize: fork: %s\n", xstrerror());
	comm_close(cfd);
	fatal("Failed to fork() for ftpget.");
    }
    if (pid != 0) {		/* parent */
	comm_close(cfd);
	close(squid_to_ftpget[0]);
	close(ftpget_to_squid[1]);
	fd_open(squid_to_ftpget[1], FD_PIPE, "squid -> ftpget");
	fd_open(ftpget_to_squid[0], FD_PIPE, "squid <- ftpget");
	commSetCloseOnExec(squid_to_ftpget[1]);
	commSetCloseOnExec(ftpget_to_squid[0]);
	/* if ftpget -S goes away, this handler should get called */
	commSetSelect(ftpget_to_squid[0],
	    COMM_SELECT_READ,
	    ftpServerClosed,
	    NULL, 0);
	ftpget_server_write = squid_to_ftpget[1];
	ftpget_server_read = ftpget_to_squid[0];
	slp.tv_sec = 0;
	slp.tv_usec = 250000;
	select(0, NULL, NULL, NULL, &slp);
	return 0;
    }
    /* child */
    /* give up all extra priviligies */
    no_suid();
    /* set up stdin,stdout */
    dup2(squid_to_ftpget[0], 0);
    dup2(ftpget_to_squid[1], 1);
    dup2(fileno(debug_log), 2);
    close(squid_to_ftpget[0]);
    close(squid_to_ftpget[1]);
    close(ftpget_to_squid[0]);
    close(ftpget_to_squid[1]);
    dup2(cfd, 3);		/* pass listening socket to ftpget */
    /* inherit stdin,stdout,stderr */
    for (cfd = 4; cfd <= Biggest_FD; cfd++)
	(void) close(cfd);
    sprintf(pbuf, "%d", ftpget_port);
    execlp(ftpget, ftpget, "-S", pbuf, NULL);
    debug(50, 0, "ftpInitialize: %s: %s\n", ftpget, xstrerror());
    _exit(1);
    return (1);			/* eliminate compiler warning */
}
