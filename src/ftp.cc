
/*
 * $Id: ftp.cc,v 1.85 1996/11/22 05:07:13 wessels Exp $
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
static const char *const w_space = " \t\n\r";

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
    ConnectStateData connectState;
} FtpStateData;

/* Local functions */
static const char *ftpTransferMode _PARAMS((const char *));
static char *ftpGetBasicAuth _PARAMS((const char *));
static int ftpReadReply _PARAMS((int, FtpStateData *));
static int ftpStateFree _PARAMS((int, FtpStateData *));
static void ftpConnectDone _PARAMS((int fd, int status, void *data));
static void ftpLifetimeExpire _PARAMS((int, FtpStateData *));
static void ftpProcessReplyHeader _PARAMS((FtpStateData *, const char *, int));
static void ftpSendComplete _PARAMS((int, char *, int, int, void *));
static void ftpSendRequest _PARAMS((int, FtpStateData *));
static void ftpServerClosed _PARAMS((int, void *));
static void ftp_login_parser _PARAMS((const char *, FtpStateData *));

/* External functions */
extern char *base64_decode _PARAMS((const char *coded));

static int
ftpStateFree(int fd, FtpStateData * ftpState)
{
    if (ftpState == NULL)
	return 1;
    storeUnlockObject(ftpState->entry);
    if (ftpState->reply_hdr) {
	put_free_8k_page(ftpState->reply_hdr);
	ftpState->reply_hdr = NULL;
    }
    requestUnlink(ftpState->request);
    xfree(ftpState);
    return 0;
}

static void
ftp_login_parser(const char *login, FtpStateData * data)
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
	strcpy(password, null_string);
    }

    if (!*user && !*password) {
	strcpy(user, "anonymous");
	strcpy(password, Config.ftpUser);
    }
}

/* This will be called when socket lifetime is expired. */
static void
ftpLifetimeExpire(int fd, FtpStateData * data)
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(9, 4, "ftpLifeTimeExpire: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    comm_close(fd);
}


/* This is too much duplicated code from httpProcessReplyHeader.  Only
 * difference is FtpStateData vs HttpData. */
static void
ftpProcessReplyHeader(FtpStateData * data, const char *buf, int size)
{
    char *t = NULL;
    StoreEntry *entry = data->entry;
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
	/* Find the end of the headers */
	t = mime_headers_end(data->reply_hdr);
	if (!t)
	    return;		/* headers not complete */
	/* Cut after end of headers */
	*t = '\0';
	reply = entry->mem_obj->reply;
	reply->hdr_sz = t - data->reply_hdr;
	debug(11, 7, "ftpProcessReplyHeader: hdr_sz = %d\n", reply->hdr_sz);
	data->reply_hdr_state++;
    }
    if (data->reply_hdr_state == 1) {
	data->reply_hdr_state++;
	debug(11, 9, "GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    data->reply_hdr);
	/* Parse headers into reply structure */
	httpParseReplyHeaders(data->reply_hdr, reply);
	timestampsSet(entry);
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
static int
ftpReadReply(int fd, FtpStateData * data)
{
    LOCAL_ARRAY(char, buf, SQUID_TCP_SO_RCVBUF);
    int len;
    int clen;
    int off;
    int bin;
    StoreEntry *entry = NULL;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND && !storeClientWaiting(entry)) {
	/* we can terminate connection right now */
	squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	comm_close(fd);
	return 0;
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
	    (PF) ftpReadReply,
	    (void *) data, 0);
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    /* NOTE there is no read timeout handler to disable */
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, Config.stallDelay);
	return 0;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    errno = 0;
    len = read(fd, buf, SQUID_TCP_SO_RCVBUF);
    debug(9, 5, "ftpReadReply: FD %d, Read %d bytes\n", fd, len);
    if (len > 0) {
	IOStats.Ftp.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Ftp.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1, "ftpReadReply: read error: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(fd, COMM_SELECT_READ,
		(PF) ftpReadReply, (void *) data, 0);
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
	if (!data->got_marker) {
	    /* If we didn't see the magic marker, assume the transfer
	     * failed and arrange so the object gets ejected and
	     * never gets to disk. */
	    debug(9, 1, "ftpReadReply: Purging '%s'\n", entry->url);
	    storeNegativeCache(entry);
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	} else if (!(entry->flag & DELETE_BEHIND)) {
	    timestampsSet(entry);
	}
	/* update fdstat and fdtable */
	storeComplete(entry);
	comm_close(fd);
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
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (void *) data, 0);
	commSetSelect(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) ftpLifetimeExpire,
	    (void *) data,
	    Config.readTimeout);
    }
    return 0;
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
	(PF) ftpReadReply,
	(void *) ftpState, 0);
    commSetSelect(ftpState->ftp_fd,
	COMM_SELECT_TIMEOUT,
	(PF) ftpLifetimeExpire,
	(void *) ftpState, Config.readTimeout);
}

static const char *
ftpTransferMode(const char *urlpath)
{
    const char *const ftpASCII = "A";
    const char *const ftpBinary = "I";
    char *ext = NULL;
    const ext_table_entry *mime = NULL;
    int len;
    len = strlen(urlpath);
    if (*(urlpath + len - 1) == '/')
	return ftpASCII;
    if ((ext = strrchr(urlpath, '.')) == NULL)
	return ftpBinary;
    if ((mime = mime_ext_to_type(++ext)) == NULL)
	return ftpBinary;
    if (!strcmp(mime->mime_encoding, "7bit"))
	return ftpASCII;
    return ftpBinary;
}

static void
ftpSendRequest(int fd, FtpStateData * data)
{
    char *path = NULL;
    const char *mode = NULL;
    char *buf = NULL;
    LOCAL_ARRAY(char, tbuf, BUFSIZ);
    LOCAL_ARRAY(char, opts, BUFSIZ);
    const char *const space = " ";
    char *s = NULL;
    int got_timeout = 0;
    int got_negttl = 0;
    int buflen;

    debug(9, 5, "ftpSendRequest: FD %d\n", fd);

    buflen = strlen(data->request->urlpath) + 256;
    buf = (char *) get_free_8k_page();
    memset(buf, '\0', buflen);

    path = data->request->urlpath;
    mode = ftpTransferMode(path);

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
	sprintf(tbuf, "-t %d ", Config.readTimeout);
	strcat(buf, tbuf);
    }
    if (!got_negttl) {
	sprintf(tbuf, "-n %d ", Config.negativeTtl);
	strcat(buf, tbuf);
    }
    if (data->request->port) {
	sprintf(tbuf, "-P %d ", data->request->port);
	strcat(buf, tbuf);
    }
    if ((s = Config.visibleHostname)) {
	sprintf(tbuf, "-H %s ", s);
	strcat(buf, tbuf);
    }
    if (data->authenticated) {
	strcat(buf, "-a ");
    }
    if (Config.Addrs.tcp_outgoing.s_addr != INADDR_NONE) {
	sprintf(tbuf, "-o %s ", inet_ntoa(Config.Addrs.tcp_outgoing));
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
    comm_write(fd,
	buf,
	strlen(buf),
	30,
	ftpSendComplete,
	(void *) data,
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


int
ftpStart(int unusedfd, const char *url, request_t * request, StoreEntry * entry)
{
    LOCAL_ARRAY(char, realm, 8192);
    FtpStateData *ftpData = NULL;
    char *req_hdr = entry->mem_obj->mime_hdr;
    char *response;
    char *auth;

    debug(9, 3, "FtpStart: FD %d '%s'\n", unusedfd, url);

    if (ftpget_server_write < 0) {
	squid_error_entry(entry, ERR_FTP_DISABLED, NULL);
	return COMM_ERROR;
    }
    ftpData = xcalloc(1, sizeof(FtpStateData));
    storeLockObject(ftpData->entry = entry, NULL, NULL);
    ftpData->request = requestLink(request);

    /* Parse login info. */
    if ((auth = ftpGetBasicAuth(req_hdr))) {
	ftp_login_parser(auth, ftpData);
	ftpData->authenticated = 1;
    } else {
	ftp_login_parser(request->login, ftpData);
	if (*ftpData->user && !*ftpData->password) {
	    /* This request is not fully authenticated */
	    if (request->port == 21) {
		sprintf(realm, "ftp %s", ftpData->user);
	    } else {
		sprintf(realm, "ftp %s port %d",
		    ftpData->user, request->port);
	    }
	    response = authorization_needed_msg(request, realm);
	    storeAppend(entry, response, strlen(response));
	    httpParseReplyHeaders(response, entry->mem_obj->reply);
	    storeComplete(entry);
	    ftpStateFree(-1, ftpData);
	    return COMM_OK;
	}
    }

    debug(9, 5, "FtpStart: FD %d, host=%s, path=%s, user=%s, passwd=%s\n",
	unusedfd, ftpData->request->host, ftpData->request->urlpath,
	ftpData->user, ftpData->password);

    ftpData->ftp_fd = comm_open(SOCK_STREAM,
	0,
	local_addr,
	0,
	COMM_NONBLOCKING,
	url);
    if (ftpData->ftp_fd == COMM_ERROR) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	ftpStateFree(-1, ftpData);
	return COMM_ERROR;
    }
    /* Pipe/socket created ok */

    /* register close handler */
    comm_add_close_handler(ftpData->ftp_fd,
	(PF) ftpStateFree,
	(void *) ftpData);

    /* Now connect ... */
    ftpData->connectState.fd = ftpData->ftp_fd;
    ftpData->connectState.host = localhost;
    ftpData->connectState.port = ftpget_port;
    ftpData->connectState.handler = ftpConnectDone;
    ftpData->connectState.data = ftpData;
    comm_nbconnect(ftpData->ftp_fd, &ftpData->connectState);
    return COMM_OK;
}

static void
ftpConnectDone(int fd, int status, void *data)
{
    FtpStateData *ftpData = data;
    if (status == COMM_ERROR) {
	squid_error_entry(ftpData->entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    fdstat_open(fd, FD_SOCKET);
    commSetNonBlocking(fd);
    (void) fd_note(fd, ftpData->entry->url);
    /* Install connection complete handler. */
    fd_note(fd, ftpData->entry->url);
    commSetSelect(fd,
	COMM_SELECT_WRITE,
	(PF) ftpSendRequest,
	(void *) data, 0);
    comm_set_fd_lifetime(fd,
	Config.lifetimeDefault);
    commSetSelect(fd,
	COMM_SELECT_LIFETIME,
	(PF) ftpLifetimeExpire,
	(void *) ftpData, 0);
    if (opt_no_ipcache)
	ipcacheInvalidate(ftpData->request->host);
    if (Config.vizHackAddr.sin_port)
	vizHackSendPkt(&ftpData->connectState.S, 2);
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
	(PF) NULL,
	(void *) NULL, 0);
    fdstat_close(ftpget_server_read);
    close(ftpget_server_read);
    fdstat_close(ftpget_server_write);
    close(ftpget_server_write);
    ftpget_server_read = -1;
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
    listen(cfd, SQUID_MAXFD >> 2);
    if ((pid = fork()) < 0) {
	debug(50, 0, "ftpInitialize: fork: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    if (pid != 0) {		/* parent */
	comm_close(cfd);
	close(squid_to_ftpget[0]);
	close(ftpget_to_squid[1]);
	fdstat_open(squid_to_ftpget[1], FD_PIPE);
	fdstat_open(ftpget_to_squid[0], FD_PIPE);
	fd_note(squid_to_ftpget[1], "ftpget -S");
	fd_note(ftpget_to_squid[0], "ftpget -S");
	commSetCloseOnExec(squid_to_ftpget[1]);
	commSetCloseOnExec(ftpget_to_squid[0]);
	/* if ftpget -S goes away, this handler should get called */
	commSetSelect(ftpget_to_squid[0],
	    COMM_SELECT_READ,
	    (PF) ftpServerClosed,
	    (void *) NULL, 0);
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
    for (cfd = 4; cfd <= fdstat_biggest_fd(); cfd++)
	(void) close(cfd);
    sprintf(pbuf, "%d", ftpget_port);
    execlp(ftpget, ftpget, "-S", pbuf, NULL);
    debug(50, 0, "ftpInitialize: %s: %s\n", ftpget, xstrerror());
    _exit(1);
    return (1);			/* eliminate compiler warning */
}
