
/*
 * DEBUG: section 50    URN Parsing
 * AUTHOR: Kostas Anagnostakis
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
    void *data;
    char *orig_url;
    struct in_addr client_addr;
    const char *client_ident;
    const char *method_s;
    RH *handler;
} urnStateData;

struct urnQueueData {
    struct urnQueueData *next;
    urnStateData *urnState;
};

static struct urnQueueData *urnQueueHead = NULL;
static struct urnQueueData **urnQueueTailP = &urnQueueHead;

static char **urn_parsebuffer(const char *,urnserver_t *);

static int urnOpenServer(const char *command);
static void urnHandleRead(int, void *);
static void urnStateFree(urnStateData * );

static PF urnShutdownRead;
static urnserver_t **urn_child_table = NULL;
static void Enqueue (urnStateData *);
static urnStateData *Dequeue();


static void
urnDispatch(urnserver_t * urn, urnStateData * r)
{
    char *buf = NULL;
	clientHttpRequest *http=r->data;

    int len;
    if (r->handler == NULL) {
        debug(50, 1) ("urnDispatch: skipping '%s' because no handler\n",
		http->urn);
        urnStateFree(r);
        return;
    }
    EBIT_SET(urn->flags, HELPER_BUSY);
    urn->urnState = r;
    urn->dispatch_time = current_time;
    buf = get_free_8k_page();
	snprintf(buf, 8192, "%s\n", http->urn);
	debug(50,1)("urnDispatch: urn=%s\n",buf);
    len = strlen(buf);
    comm_write(urn->outpipe,
        buf,
        len,
        NULL,                   /* Handler */
        NULL,                   /* Handler-data */
        put_free_8k_page);
    debug(50, 5) ("urnDispatch: Request sent to Redirector #%d, %d bytes\n",
        urn->id, len);
    commSetSelect(urn->outpipe,
        COMM_SELECT_READ,
        urnHandleRead,
        urn, 0);

}

static void
urnHandleRead(int fd, void *data)
{
    urnserver_t *urnData = data;
	char **x  = NULL;
	urnStateData *sd=urnData->urnState;
	RH *handler=sd->handler;
    clientHttpRequest *f = sd->data;
    int len;
    debug(50,5)("urnHandleRead for %s\n",f->urn);
    len = read(fd,
        urnData->urn_buf + urnData->offset,
        urnData->size - urnData->offset);
    fd_bytes(fd, len, FD_READ);
    debug(50, 5) ("urnHandleRead: Result from URN ID %d (%d bytes)\n",
        urnData->id, len);
    if (len <= 0) {
        if (len < 0 && ignoreErrno(errno)) {
            commSetSelect(fd,
                COMM_SELECT_READ,
                urnHandleRead,
                urnData,
                0);
            return;
        }
        debug(50, EBIT_TEST(urnData->flags, HELPER_CLOSING) ? 5 : 1)
            ("FD %d: Connection from URNSERVER #%d is closed, disabling\n",
            fd, urnData->id);
        urnData->flags = 0;
        commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
        comm_close(fd);
        return;
    }
    urnData->offset += len;
    urnData->urn_buf[urnData->offset] = '\0';
    if (strstr(urnData->urn_buf, "$end\n")) {
        /* end of record found */
        x = urn_parsebuffer(urnData->urn_buf, urnData);
            urnData->offset = 0;
            urnData->urn_buf[0] = '\0';
	    f->urls=x;
	    if (f->urls)
	    	handler(f, f->urls[0]);
	    else 
		handler(f, NULL);
#ifdef HAVE_URNLOCKS
        urnUnlockEntry(f);        /* unlock from URN_DISPATCHED */
#endif
    }
    if (urnData->offset == 0) {
        urnData->data = NULL;
        EBIT_CLR(urnData->flags, HELPER_BUSY);
    }
    /* reschedule */
    commSetSelect(urnData->inpipe,
        COMM_SELECT_READ,
        urnHandleRead,
        urnData, 0);
}

void
urnFindClosestStart(clientHttpRequest *http,RH *handler, void *data)
{
	int i=0;
	int avail=0;
	double min_rtt=-1.0;
	int min_nr=0;
	static request_t *tmpr[MAX_URNTOURL];
	netdbEntry *net=NULL;

	assert(http->urls);
	for (i=0;http->urls[i]!=NULL;i++)
	{
		tmpr[i]=urlParse(http->request->method,http->urls[i]);
		debug(50,5)("Parsed %s\n",http->urls[i]);
		net=netdbLookupHost(tmpr[i]->host);
		if (net==NULL)
		{
			debug(50,5)("Pinging up %s\n",tmpr[i]->host);
			netdbPingSite(tmpr[i]->host);
		}
		else debug(50,5)("Already here with %s and rtt=%f\n",
			tmpr[i]->host,net->rtt);
	}
	net=NULL;
	for (i=0, avail=0;http->urls[i]!=NULL;i++)
		if ((net=netdbLookupHost(tmpr[i]->host))!=NULL)
		{
			avail++;
			if (min_rtt==-1.0 || net->rtt<min_rtt)
			{
				min_rtt=net->rtt;
				min_nr=i;
			}
		}
	if (avail>1)	/* we got one */
	{
		http->url=http->urls[min_nr];
		urnFindClosestDone(0,http);
		return;
	}

	/* none received yet, must set timeout and wait */
	commSetTimeout(http->conn->fd, Config.Timeout.siteSelect, 
		(void *)urnFindClosestDone, http);
}

static void
urnNudgeQueue(void)
{
    urnserver_t *urnData;
    urnStateData *i = NULL;
    while ((urnData = urnGetFirstAvailable()) && (i = Dequeue()))
        urnDispatch(urnData, i);
}

void
urnTranslateStart(clientHttpRequest * http, RH * handler, void *data)
{
    ConnStateData *conn = http->conn;
    urnStateData *r = NULL;
    urnserver_t *urns = NULL;
    if (!http)
        fatal_dump("urnTranslateStart: NULL clientHttpRequest");
    if (!handler)
        fatal_dump("urnTranslateStart: NULL handler");
    debug(50, 5) ("urnStart: '%s'\n", http->urn);
    if (Config.Program.urnserver == NULL) {
        handler(data, NULL);
        return;
    }
    r = xcalloc(1, sizeof(urnStateData));
    r->client_addr = conn->log_addr;
    if (conn->ident.ident == NULL || *conn->ident.ident == '\0') {
        r->client_ident = dash_str;
    } else {
        r->client_ident = conn->ident.ident;
    }
    r->method_s = RequestMethodStr[http->request->method];
    r->handler = handler;
    r->data = http;

    /*
     * Build a URL of the form http://host/uri-res?path
     *
     * Create a key
     * storeGet(key);
     * if NULL {
     *     call protoStart()  or httpStart()
     *  }
     *  register to receive the data
     *  storeClientCopy(..., urnHandleSomething, r);
     * 
     */
     
	
    if ((urns = urnGetFirstAvailable()))
	{
	debug(50,5)("urnTranslateStart: dispatching with %s\n",http->urn);
        urnDispatch(urns, r);
	}
    else
        Enqueue(r);
}

static void
urnStateFree(urnStateData * r)
{
    safe_free(r->orig_url);
    safe_free(r);
}

static void
Enqueue(urnStateData * r)
{
    struct urnQueueData *new = xcalloc(1, sizeof(struct urnQueueData));
    new->urnState = r;
    *urnQueueTailP = new;
    urnQueueTailP = &new->next;
}

static urnStateData *
Dequeue(void)
{
    struct urnQueueData *old = NULL;
    urnStateData *r = NULL;
    if (urnQueueHead) {
        r = urnQueueHead->urnState;
        old = urnQueueHead;
        urnQueueHead = urnQueueHead->next;
        if (urnQueueHead == NULL)
            urnQueueTailP = &urnQueueHead;
        safe_free(old);
    }
    return r;
}


#ifdef URN_URL_TOGETHER
request_t *
urlParse(method_t method, char *url)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, login, MAX_URL);
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, urlpath, MAX_URL);
    request_t *request = NULL;
    char *t = NULL;
    int port;
    protocol_t protocol = PROTO_NONE;
    int l;
    proto[0] = host[0] = urlpath[0] = login[0] = '\0';

    if ((l = strlen(url)) + Config.appendDomainLen > (MAX_URL - 1)) {
	/* terminate so it doesn't overflow other buffers */
	*(url + (MAX_URL >> 1)) = '\0';
	debug(50, 0) ("urlParse: URL too large (%d bytes)\n", l);
	return NULL;
    }
    if (method == METHOD_CONNECT) {
	port = CONNECT_PORT;
	if (sscanf(url, "%[^:]:%d", host, &port) < 1)
	    return NULL;
    } else {
	if (sscanf(url, "%[^:]://%[^/]%s", proto, host, urlpath) < 2)
	    return NULL;
	protocol = urlParseProtocol(proto);
	port = urlDefaultPort(protocol);
	/* Is there any login informaiton? */
	if ((t = strrchr(host, '@'))) {
	    strcpy(login, host);
	    t = strrchr(login, '@');
	    *t = 0;
	    strcpy(host, t + 1);
	}
	if ((t = strrchr(host, ':'))) {
	    *t++ = '\0';
	    if (*t != '\0')
		port = atoi(t);
	}
    }
    for (t = host; *t; t++)
	*t = tolower(*t);
    /* remove trailing dots from hostnames */
    while ((l = strlen(host)) > 0 && host[--l] == '.')
	host[l] = '\0';
    if (Config.appendDomain && !strchr(host, '.'))
	strncat(host, Config.appendDomain, SQUIDHOSTNAMELEN);
    if (port == 0) {
	debug(50, 0) ("urlParse: Invalid port == 0\n");
	return NULL;
    }
#ifdef HARDCODE_DENY_PORTS
    /* These ports are filtered in the default squid.conf, but
     * maybe someone wants them hardcoded... */
    if (port == 7 || port == 9 || port = 19) {
	debug(50, 0) ("urlParse: Deny access to port %d\n", port);
	return NULL;
    }
#endif
#ifdef REMOVE_FTP_TRAILING_SLASHES
    /* remove trailing slashes from FTP URLs */
    if (protocol == PROTO_FTP) {
	t = urlpath + strlen(urlpath);
	while (t > urlpath && *(--t) == '/')
	    *t = '\0';
    }
#endif
    request = get_free_request_t();
    request->method = method;
    request->protocol = protocol;
    xstrncpy(request->host, host, SQUIDHOSTNAMELEN);
    xstrncpy(request->login, login, MAX_LOGIN_SZ);
    request->port = (u_short) port;
    xstrncpy(request->urlpath, urlpath, MAX_URL);
    request->max_age = -1;
    request->max_forwards = -1;
    return request;
}

char *
urlCanonical(const request_t * request, char *buf)
{
    LOCAL_ARRAY(char, urlbuf, MAX_URL);
    LOCAL_ARRAY(char, portbuf, 32);
    if (buf == NULL)
	buf = urlbuf;
    switch (request->method) {
    case METHOD_CONNECT:
	snprintf(buf, MAX_URL, "%s:%d", request->host, request->port);
	break;
    default:
	portbuf[0] = '\0';
	if (request->port != urlDefaultPort(request->protocol))
	    snprintf(portbuf, 32, ":%d", request->port);
	snprintf(buf, MAX_URL, "%s://%s%s%s%s%s",
	    ProtocolStr[request->protocol],
	    request->login,
	    *request->login ? "@" : null_string,
	    request->host,
	    portbuf,
	    request->urlpath);
	break;
    }
    return buf;
}

char *
urlCanonicalClean(const request_t * request)
{
    LOCAL_ARRAY(char, buf, MAX_URL);
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, loginbuf, MAX_LOGIN_SZ + 1);
    char *t;
    switch (request->method) {
    case METHOD_CONNECT:
	snprintf(buf, MAX_URL, "%s:%d", request->host, request->port);
	break;
    default:
	portbuf[0] = '\0';
	if (request->port != urlDefaultPort(request->protocol))
	    snprintf(portbuf, 32, ":%d", request->port);
	loginbuf[0] = '\0';
	if (strlen(request->login) > 0) {
	    strcpy(loginbuf, request->login);
	    if ((t = strchr(loginbuf, ':')))
		*t = '\0';
	    strcat(loginbuf, "@");
	}
	snprintf(buf, MAX_URL, "%s://%s%s%s%s",
	    ProtocolStr[request->protocol],
	    loginbuf,
	    request->host,
	    portbuf,
	    request->urlpath);
	if ((t = strchr(buf, '?')))
	    *t = '\0';
	break;
    }
    return buf;
}

char *
urlClean(char *dirty)
{
    char *clean;
    request_t *r = urlParse(METHOD_GET, dirty);
    if (r == NULL)
	return dirty;
    clean = urlCanonicalClean(r);
    put_free_request_t(r);
    return clean;
}


request_t *
requestLink(request_t * request)
{
    request->link_count++;
    return request;
}

void
requestUnlink(request_t * request)
{
    if (request == NULL)
	return;
    request->link_count--;
    if (request->link_count)
	return;
    safe_free(request->headers);
    put_free_request_t(request);
}

int
matchDomainName(const char *domain, const char *host)
{
    int offset;
    if ((offset = strlen(host) - strlen(domain)) < 0)
	return 0;		/* host too short */
    if (strcasecmp(domain, host + offset) != 0)
	return 0;		/* no match at all */
    if (*domain == '.')
	return 1;
    if (*(host + offset - 1) == '.')
	return 1;
    if (offset == 0)
	return 1;
    return 0;
}

int
urlCheckRequest(const request_t * r)
{
    int rc = 0;
    if (r->method == METHOD_CONNECT)
	return 1;
    if (r->method == METHOD_TRACE)
	return 1;
    if (r->method == METHOD_PURGE)
	return 1;
    switch (r->protocol) {
    case PROTO_HTTP:
    case PROTO_CACHEOBJ:
	rc = 1;
	break;
    case PROTO_FTP:
	if (r->method == METHOD_PUT)
	    rc = 1;
    case PROTO_GOPHER:
    case PROTO_WAIS:
	if (r->method == METHOD_GET)
	    rc = 1;
	else if (r->method == METHOD_HEAD)
	    rc = 1;
	break;
    default:
	break;
    }
    return rc;
}
#endif



void
urnShutdownServers(void)
{
    urnserver_t *urn = NULL;
    int k;

    debug(50, 3) ("urnShutdownServers:\n");

    for (k = 0; k < NUrnServersAlloc; k++) {
        urn = *(urn_child_table + k);
        if (!EBIT_TEST(urn->flags, HELPER_ALIVE)) {
            debug(50, 3) ("urnShutdownServers: #%d is NOT ALIVE.\n", urn->id);
            continue;
        }
        if (EBIT_TEST(urn->flags, HELPER_BUSY)) {
            debug(50, 3) ("urnShutdownServers: #%d is BUSY.\n", urn->id);
            EBIT_SET(urn->flags, HELPER_SHUTDOWN);
            continue;
        }
        if (EBIT_TEST(urn->flags, HELPER_CLOSING)) {
            debug(50, 3) ("urnShutdownServers: #%d is CLOSING.\n", urn->id);
            continue;
        }
        urnShutdownServer(urn);
    }
}

void
urnShutdownServer(urnserver_t * urn)
{
    static char *shutdown_cmd = "$shutdown\n";
    debug(50, 3) ("urnShutdownServer: sending '$shutdown' to urnserver #%d\n",
        urn->id);
    debug(50, 3) ("urnShutdownServer: --> FD %d\n", urn->outpipe);
    cbdataLock(urn);
    comm_write(urn->outpipe,
        xstrdup(shutdown_cmd),
        strlen(shutdown_cmd),
        NULL,                   /* Handler */
        NULL,                   /* Handler-data */
        xfree);
    commSetSelect(urn->inpipe,
        COMM_SELECT_READ,
        urnShutdownRead,
        urn,
        0);
    EBIT_SET(urn->flags, HELPER_CLOSING);
}

static void
urnShutdownRead(int fd, void *data)
{
    urnserver_t *urn = data;
    debug(50, EBIT_TEST(urn->flags, HELPER_CLOSING) ? 5 : 1)
        ("FD %d: Connection from URNSERVER #%d is closed, disabling\n",
        fd,
        urn->id);
    urn->flags = 0;
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    cbdataUnlock(urn);
    comm_close(fd);
}

void
urnOpenServers(void)
{
    int N = Config.urnChildren;
    char *prg = Config.Program.urnserver;
    int k;
    int urnsocket;
    LOCAL_ARRAY(char, fd_note_buf, FD_DESC_SZ);
    char *s;
	
    urnFreeMemory();
    urn_child_table = xcalloc(N, sizeof(urnserver_t *));
    NUrnServersAlloc = 0;
    for (k = 0; k < N; k++) {
        urn_child_table[k] = xcalloc(1, sizeof(urnserver_t));
        cbdataAdd(urn_child_table[k]);
        if ((urnsocket = urnOpenServer(prg)) < 0) {
            debug(50, 1) ("urnOpenServers: WARNING: Failed to start 'urnserver' #%d. %s \n", k + 1, prg);
            EBIT_CLR(urn_child_table[k]->flags, HELPER_ALIVE);
            urn_child_table[k]->id = k + 1;
            urn_child_table[k]->inpipe = -1;
            urn_child_table[k]->outpipe = -1;
        } else {
            debug(50, 4) ("urnOpenServers: FD %d connected to %s #%d.\n",
                urnsocket, prg, k + 1);
            EBIT_SET(urn_child_table[k]->flags, HELPER_ALIVE);
            urn_child_table[k]->id = k + 1;
            urn_child_table[k]->inpipe = urnsocket;
            urn_child_table[k]->outpipe = urnsocket;
            urn_child_table[k]->answer = squid_curtime;
            urn_child_table[k]->dispatch_time = current_time;
            urn_child_table[k]->size = URN_INBUF_SZ - 1;
            urn_child_table[k]->offset = 0;
            if ((s = strrchr(prg, '/')))
                s++;
            else
                s = prg;
            snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", s, urn_child_table[k]->id);
            fd_note(urn_child_table[k]->inpipe, fd_note_buf);
            commSetNonBlocking(urn_child_table[k]->inpipe);
            debug(50, 3) ("urnOpenServers: 'urn_server' %d started\n", k);
            NUrnServersAlloc++;
        }
    }
    if (NUrnServersAlloc == 0 && Config.urnChildren > 0)
        fatal("Failed to start any urnservers");
    debug(50, 1) ("Started %d 'urnserver' processes\n", NUrnServersAlloc);
}

void
urnFreeMemory(void)
{
    int k;
    /* free old structures if present */
    if (urn_child_table) {
        for (k = 0; k < NUrnServersAlloc; k++)
            cbdataFree(urn_child_table[k]);
        safe_free(urn_child_table);
    }
}
urnserver_t *
urnGetFirstAvailable(void)
{
    int k;
    urnserver_t *urn = NULL;
    for (k = 0; k < NUrnServersAlloc; k++) {
        urn = *(urn_child_table + k);
        if (EBIT_TEST(urn->flags, HELPER_BUSY))
            continue;
        if (EBIT_TEST(urn->flags, HELPER_CLOSING))
            continue;
        if (!EBIT_TEST(urn->flags, HELPER_ALIVE))
            continue;
        return urn;
    }
    return NULL;
}

static int
urnOpenServer(const char *command)
{
    pid_t pid;
    struct sockaddr_in S;
    int cfd;
    int sfd;
    int fd;
    int len;
    LOCAL_ARRAY(char, buf, 128);

    cfd = comm_open(SOCK_STREAM,
        0,
        local_addr,
        0,
        COMM_NOCLOEXEC,
        "urnserver listen socket");
    if (cfd < 0) {
        debug(50, 0) ("urnOpenServer: Failed to create urnserver\n");
        return -1;
    }
    len = sizeof(S);
    memset(&S, '\0', len);
    if (getsockname(cfd, (struct sockaddr *) &S, &len) < 0) {
        debug(50, 5) ("urnOpenServer: getsockname: %s\n", xstrerror());
        comm_close(cfd);
        return -1;
    }
    listen(cfd, 1);

    /* flush or else we get dup data if unbuffered_logs is set */
    logsFlush();
    if ((pid = fork()) < 0) {
        debug(50, 5) ("urnOpenServer: fork: %s\n", xstrerror());
        comm_close(cfd);
		fprintf(stderr,"ERR 1\n");
        return -1;
    }
    if (pid > 0) {              /* parent */
        comm_close(cfd);        /* close shared socket with child */
        /* open new socket for parent process */
        sfd = comm_open(SOCK_STREAM,
            0,                  /* protocol */
            local_addr,
            0,                  /* port */
            0,                  /* flags */
            "squid <-> urnserver");
        if (sfd == COMM_ERROR) {
            comm_close(sfd);
            return -1;
	}
        if (comm_connect_addr(sfd, &S) == COMM_ERROR) {
            comm_close(sfd);
            return -1;
        }
        if (write(sfd, "$hello\n", 7) < 0) {
            debug(50, 0) ("urnOpenServer: $hello write test failed \n");
		perror("squid");
            comm_close(sfd);
            return -1;
        }
        memset(buf, '\0', 128);
        if (read(sfd, buf, 127) < 0) {
            debug(50, 0) ("urnOpenServer: $hello read test failed\n");
            debug(50, 0) ("--> read: %s\n", xstrerror());
            comm_close(sfd);
            return -1;
        } else if (strcmp(buf, "$alive\n$end\n")) {
            debug(50, 0) ("urnOpenServer: $hello read test failed\n");
            debug(50, 0) ("--> got '%s'\n", rfc1738_escape(buf));
            comm_close(sfd);
            return -1;
        }
        commSetTimeout(sfd, -1, NULL, NULL);
        return sfd;
    }
    /* child */
    if ((fd = accept(cfd, NULL, NULL)) < 0) {
        debug(50, 0) ("urnOpenServer: FD %d accept: %s\n", cfd, xstrerror());
        exit(1);
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fileno(debug_log), 2);
    fclose(debug_log);
    close(fd);
    close(cfd);

    execlp(command, "(urnserver)", NULL);
    debug(50, 0) ("urnOpenServer: %s: %s\n", command, xstrerror());
    _exit(1);
    return 0;
}

static char **
urn_parsebuffer(const char *inbuf, urnserver_t * urnData)
{
    char *buf = xstrdup(inbuf);
    char *token;
    char **urls=NULL;
    int k;
    int urlcount;

    debug(50, 5) ("urn_parsebuffer: parsing:\n%s", inbuf);
    for (token = strtok(buf, w_space); token; token = strtok(NULL, w_space)) {
        if (!strcmp(token, "$end")) {
            break;
	} else if (!strcmp(token, "$none")) {
		return NULL;
        } else if (!strcmp(token, "$alive")) {
            urnData->answer = squid_curtime;
        } else if (!strcmp(token, "$fail")) {
            if ((token = strtok(NULL, "\n")) == NULL)
                fatal_dump("Invalid $fail");
        } else if (!strcmp(token, "$message")) {
            if ((token = strtok(NULL, "\n")) == NULL)
                fatal_dump("Invalid $message");
        } else if (!strcmp(token, "$urlcount")) {
            if ((token = strtok(NULL, w_space)) == NULL)
                fatal_dump("Invalid $urlcount");
            urlcount = atoi(token);
		if (urlcount== 0 ) 
			return NULL;
		if (urls==NULL) 
			urls=xmalloc((urlcount+1)*sizeof(char *));
            for (k = 0; k < urlcount; k++) {
                if ((token = strtok(NULL, w_space)) == NULL)
                    fatal_dump("Invalid URL");
		urls[k]=xstrdup(token);
            }
	    urls[k]=NULL;
        } else {
            debug(50, 0) ("--> %s <--\n", inbuf);
            debug_trap("Invalid urnserver output");
        }
    }
    xfree(buf);

	return (urls);
}

