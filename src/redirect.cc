
/*
 * $Id: redirect.cc,v 1.57 1998/03/03 00:31:12 rousskov Exp $
 *
 * DEBUG: section 29    Redirector
 * AUTHOR: Duane Wessels
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
} redirectStateData;

typedef struct _redirector {
    int index;
    int flags;
    int fd;
    char *inbuf;
    unsigned int size;
    unsigned int offset;
    struct timeval dispatch_time;
    redirectStateData *redirectState;
} redirector_t;

static struct {
    int requests;
    int replies;
    int errors;
    int avg_svc_time;
    int queue_size;
    int use_hist[DefaultRedirectChildrenMax];
    int rewrites[DefaultRedirectChildrenMax];
} RedirectStats;


struct redirectQueueData {
    struct redirectQueueData *next;
    redirectStateData *redirectState;
};

static redirector_t *GetFirstAvailable(void);
static PF redirectHandleRead;
static redirectStateData *Dequeue(void);
static void Enqueue(redirectStateData *);
static void redirectDispatch(redirector_t *, redirectStateData *);
static void redirectStateFree(redirectStateData * r);

static redirector_t **redirect_child_table = NULL;
static int NRedirectors = 0;
static int NRedirectorsOpen = 0;
static struct redirectQueueData *redirectQueueHead = NULL;
static struct redirectQueueData **redirectQueueTailP = &redirectQueueHead;

static void
redirectHandleRead(int fd, void *data)
{
    redirector_t *redirector = data;
    int len;
    redirectStateData *r = redirector->redirectState;
    char *t = NULL;
    int n;

    len = read(fd,
	redirector->inbuf + redirector->offset,
	redirector->size - redirector->offset);
    fd_bytes(fd, len, FD_READ);
    debug(29, 5) ("redirectHandleRead: %d bytes from Redirector #%d.\n",
	len, redirector->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(50, 1) ("redirectHandleRead: FD %d read: %s\n", fd, xstrerror());
	debug(29, EBIT_TEST(redirector->flags, HELPER_CLOSING) ? 5 : 1)
	    ("FD %d: Connection from Redirector #%d is closed, disabling\n",
	    fd, redirector->index + 1);
	redirector->flags = 0;
	memFree(MEM_8K_BUF, redirector->inbuf);
	redirector->inbuf = NULL;
	comm_close(fd);
	if (--NRedirectorsOpen == 0 && !shutdown_pending && !reconfigure_pending)
	    fatal_dump("All redirectors have exited!");
	return;
    }
    if (len != 1)
	RedirectStats.rewrites[redirector->index]++;
    redirector->offset += len;
    redirector->inbuf[redirector->offset] = '\0';
    /* reschedule */
    commSetSelect(redirector->fd,
	COMM_SELECT_READ,
	redirectHandleRead,
	redirector, 0);
    if ((t = strchr(redirector->inbuf, '\n'))) {
	/* end of record found */
	*t = '\0';
	if ((t = strchr(redirector->inbuf, ' ')))
	    *t = '\0';		/* terminate at space */
	if (r == NULL) {
	    /* A naughty redirector has spoken without being spoken to */
	    /* B.R.Foster@massey.ac.nz, SQUID/1.1.3 */
	    debug(29, 0) ("redirectHandleRead: unexpected reply: '%s'\n",
		redirector->inbuf);
	    redirector->offset = 0;
	} else {
	    debug(29, 5) ("redirectHandleRead: reply: '%s'\n",
		redirector->inbuf);
	    /* careful here.  r->data might point to something which
	     * has recently been freed.  If so, we require that r->handler
	     * be NULL */
	    if (r->handler) {
		r->handler(r->data,
		    t == redirector->inbuf ? NULL : redirector->inbuf);
	    }
	    redirectStateFree(r);
	    redirector->redirectState = NULL;
	    EBIT_CLR(redirector->flags, HELPER_BUSY);
	    redirector->offset = 0;
	    n = ++RedirectStats.replies;
	    RedirectStats.avg_svc_time =
		intAverage(RedirectStats.avg_svc_time,
		tvSubMsec(redirector->dispatch_time, current_time),
		n, REDIRECT_AV_FACTOR);
	}
    }
    while ((redirector = GetFirstAvailable()) && (r = Dequeue()))
	redirectDispatch(redirector, r);
}

static void
Enqueue(redirectStateData * r)
{
    struct redirectQueueData *new = xcalloc(1, sizeof(struct redirectQueueData));
    new->redirectState = r;
    *redirectQueueTailP = new;
    redirectQueueTailP = &new->next;
    RedirectStats.queue_size++;
}

static redirectStateData *
Dequeue(void)
{
    struct redirectQueueData *old = NULL;
    redirectStateData *r = NULL;
    if (redirectQueueHead) {
	r = redirectQueueHead->redirectState;
	old = redirectQueueHead;
	redirectQueueHead = redirectQueueHead->next;
	if (redirectQueueHead == NULL)
	    redirectQueueTailP = &redirectQueueHead;
	safe_free(old);
	RedirectStats.queue_size--;
    }
    return r;
}

static redirector_t *
GetFirstAvailable(void)
{
    int k;
    redirector_t *redirect = NULL;
    for (k = 0; k < NRedirectors; k++) {
	redirect = *(redirect_child_table + k);
	if (EBIT_TEST(redirect->flags, HELPER_BUSY))
	    continue;
	if (!EBIT_TEST(redirect->flags, HELPER_ALIVE))
	    continue;
	return redirect;
    }
    return NULL;
}

static void
redirectStateFree(redirectStateData * r)
{
    safe_free(r->orig_url);
    safe_free(r);
}


static void
redirectDispatch(redirector_t * redirect, redirectStateData * r)
{
    char *buf = NULL;
    const char *fqdn = NULL;
    int len;
    if (r->handler == NULL) {
	debug(29, 1) ("redirectDispatch: skipping '%s' because no handler\n",
	    r->orig_url);
	redirectStateFree(r);
	return;
    }
    EBIT_SET(redirect->flags, HELPER_BUSY);
    redirect->redirectState = r;
    redirect->dispatch_time = current_time;
    if ((fqdn = fqdncache_gethostbyaddr(r->client_addr, 0)) == NULL)
	fqdn = dash_str;
    buf = memAllocate(MEM_8K_BUF);
    snprintf(buf, 8192, "%s %s/%s %s %s\n",
	r->orig_url,
	inet_ntoa(r->client_addr),
	fqdn,
	r->client_ident,
	r->method_s);
    len = strlen(buf);
    comm_write(redirect->fd,
	buf,
	len,
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	memFree8K);
    debug(29, 5) ("redirectDispatch: Request sent to Redirector #%d, %d bytes\n",
	redirect->index + 1, len);
    RedirectStats.use_hist[redirect->index]++;
    RedirectStats.requests++;
}


/**** PUBLIC FUNCTIONS ****/


void
redirectStart(clientHttpRequest * http, RH * handler, void *data)
{
    ConnStateData *conn = http->conn;
    redirectStateData *r = NULL;
    redirector_t *redirector = NULL;
    if (!http)
	fatal_dump("redirectStart: NULL clientHttpRequest");
    if (!handler)
	fatal_dump("redirectStart: NULL handler");
    debug(29, 5) ("redirectStart: '%s'\n", http->uri);
    if (Config.Program.redirect == NULL) {
	handler(data, NULL);
	return;
    }
    r = xcalloc(1, sizeof(redirectStateData));
    r->orig_url = xstrdup(http->uri);
    r->client_addr = conn->log_addr;
    if (conn->ident.ident == NULL || *conn->ident.ident == '\0') {
	r->client_ident = dash_str;
    } else {
	r->client_ident = conn->ident.ident;
    }
    r->method_s = RequestMethodStr[http->request->method];
    r->handler = handler;
    r->data = data;
    if ((redirector = GetFirstAvailable()))
	redirectDispatch(redirector, r);
    else
	Enqueue(r);
}

void
redirectFreeMemory(void)
{
    int k;
    /* free old structures if present */
    if (redirect_child_table) {
	for (k = 0; k < NRedirectors; k++) {
	    if (redirect_child_table[k]->inbuf)
		memFree(MEM_8K_BUF, redirect_child_table[k]->inbuf);
	    safe_free(redirect_child_table[k]);
	}
	safe_free(redirect_child_table);
    }
}

void
redirectOpenServers(void)
{
    char *prg = Config.Program.redirect;
    int k;
    int redirectsocket;
    LOCAL_ARRAY(char, fd_note_buf, FD_DESC_SZ);
    static int first_time = 0;
    char *s;
    char *args[2];
    int x;

    redirectFreeMemory();
    if (Config.Program.redirect == NULL)
	return;
    NRedirectors = NRedirectorsOpen = Config.redirectChildren;
    redirect_child_table = xcalloc(NRedirectors, sizeof(redirector_t *));
    debug(29, 1) ("redirectOpenServers: Starting %d '%s' processes\n",
	NRedirectors, prg);
    for (k = 0; k < NRedirectors; k++) {
	redirect_child_table[k] = xcalloc(1, sizeof(redirector_t));
	args[0] = "(redirector)";
	args[1] = NULL;
	x = ipcCreate(IPC_TCP_SOCKET,
	    prg,
	    args,
	    "redirector",
	    &redirectsocket,
	    &redirectsocket);
	if (x < 0) {
	    debug(29, 1) ("WARNING: Cannot run '%s' process.\n", prg);
	    EBIT_CLR(redirect_child_table[k]->flags, HELPER_ALIVE);
	} else {
	    EBIT_SET(redirect_child_table[k]->flags, HELPER_ALIVE);
	    redirect_child_table[k]->index = k;
	    redirect_child_table[k]->fd = redirectsocket;
	    redirect_child_table[k]->inbuf = memAllocate(MEM_8K_BUF);
	    redirect_child_table[k]->size = 8192;
	    redirect_child_table[k]->offset = 0;
	    if ((s = strrchr(prg, '/')))
		s++;
	    else
		s = prg;
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d",
		s,
		redirect_child_table[k]->index + 1);
	    fd_note(redirect_child_table[k]->fd, fd_note_buf);
	    commSetNonBlocking(redirect_child_table[k]->fd);
	    /* set handler for incoming result */
	    commSetSelect(redirect_child_table[k]->fd,
		COMM_SELECT_READ,
		redirectHandleRead,
		redirect_child_table[k], 0);
	    debug(29, 3) ("redirectOpenServers: 'redirect_server' %d started\n",
		k);
	}
    }
    if (first_time == 0) {
	first_time++;
	memset(&RedirectStats, '\0', sizeof(RedirectStats));
	cachemgrRegister("redirector",
	    "URL Redirector Stats",
	    redirectStats, 0);
    }
}

void
redirectShutdownServers(void)
{
    redirector_t *redirect = NULL;
    redirectStateData *r = NULL;
    int k;
    if (Config.Program.redirect == NULL)
	return;
    if (redirectQueueHead) {
	while ((redirect = GetFirstAvailable()) && (r = Dequeue()))
	    redirectDispatch(redirect, r);
	return;
    }
    for (k = 0; k < NRedirectors; k++) {
	redirect = *(redirect_child_table + k);
	if (!EBIT_TEST(redirect->flags, HELPER_ALIVE))
	    continue;
	if (EBIT_TEST(redirect->flags, HELPER_BUSY))
	    continue;
	if (EBIT_TEST(redirect->flags, HELPER_CLOSING))
	    continue;
	debug(29, 3) ("redirectShutdownServers: closing redirector #%d, FD %d\n",
	    redirect->index + 1, redirect->fd);
	comm_close(redirect->fd);
	EBIT_SET(redirect->flags, HELPER_CLOSING);
	EBIT_SET(redirect->flags, HELPER_BUSY);
    }
}


int
redirectUnregister(const char *url, void *data)
{
    redirector_t *redirect = NULL;
    redirectStateData *r = NULL;
    struct redirectQueueData *rq = NULL;
    int k;
    int n = 0;
    if (Config.Program.redirect == NULL)
	return 0;
    debug(29, 3) ("redirectUnregister: '%s'\n", url);
    for (k = 0; k < NRedirectors; k++) {
	redirect = *(redirect_child_table + k);
	if ((r = redirect->redirectState) == NULL)
	    continue;
	if (r->data != data)
	    continue;
	if (strcmp(r->orig_url, url))
	    continue;
	debug(29, 3) ("redirectUnregister: Found match\n");
	r->handler = NULL;
	n++;
    }
    for (rq = redirectQueueHead; rq; rq = rq->next) {
	if ((r = rq->redirectState) == NULL)
	    continue;
	if (r->data != data)
	    continue;
	if (strcmp(r->orig_url, url))
	    continue;
	debug(29, 3) ("redirectUnregister: Found match.\n");
	r->handler = NULL;
	n++;
    }
    debug(29, 3) ("redirectUnregister: Unregistered %d handlers\n", n);
    return n;
}

void
redirectStats(StoreEntry * sentry)
{
    int k;
    storeAppendPrintf(sentry, "Redirector Statistics:\n");
    storeAppendPrintf(sentry, "requests: %d\n",
	RedirectStats.requests);
    storeAppendPrintf(sentry, "replies: %d\n",
	RedirectStats.replies);
    storeAppendPrintf(sentry, "queue length: %d\n",
	RedirectStats.queue_size);
    storeAppendPrintf(sentry, "avg service time: %d msec\n",
	RedirectStats.avg_svc_time);
    storeAppendPrintf(sentry, "number of redirectors: %d\n",
	NRedirectors);
    storeAppendPrintf(sentry, "use histogram:\n");
    for (k = 0; k < NRedirectors; k++) {
	storeAppendPrintf(sentry, "    redirector #%d: %d (%d rewrites)\n",
	    k + 1,
	    RedirectStats.use_hist[k],
	    RedirectStats.rewrites[k]);
    }
}
