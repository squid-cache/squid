
/*
 * $Id: redirect.cc,v 1.70 1998/09/15 06:49:58 wessels Exp $
 *
 * DEBUG: section 29    Redirector
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
    void *data;
    char *orig_url;
    struct in_addr client_addr;
    const char *client_ident;
    const char *method_s;
    RH *handler;
} redirectStateData;

typedef struct _redirector {
    int index;
    helper_flags flags;
    int fd;
    char *inbuf;
    unsigned int size;
    unsigned int offset;
    struct timeval dispatch_time;
    redirectStateData *redirectState;
    dlink_node link;
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
static PF redirectorStateFree;

static dlink_list redirectors;
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
    int valid;
    assert(cbdataValid(data));
    Counter.syscalls.sock.reads++;
    len = read(fd,
	redirector->inbuf + redirector->offset,
	redirector->size - redirector->offset);
    fd_bytes(fd, len, FD_READ);
    debug(29, 5) ("redirectHandleRead: %d bytes from Redirector #%d.\n",
	len, redirector->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(50, 1) ("redirectHandleRead: FD %d read: %s\n", fd, xstrerror());
	debug(29, redirector->flags.closing ? 5 : 1)
	    ("FD %d: Connection from Redirector #%d is closed, disabling\n",
	    fd, redirector->index + 1);
	redirector->flags.alive = 0;
	redirector->flags.busy = 0;
	redirector->flags.closing = 0;
	redirector->flags.shutdown = 0;
	memFree(MEM_8K_BUF, redirector->inbuf);
	redirector->inbuf = NULL;
	comm_close(fd);
	return;
    }
    if (len != 1)
	RedirectStats.rewrites[redirector->index]++;
    redirector->offset += len;
    redirector->inbuf[redirector->offset] = '\0';
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
	    valid = cbdataValid(r->data);
	    cbdataUnlock(r->data);
	    if (valid)
		r->handler(r->data,
		    t == redirector->inbuf ? NULL : redirector->inbuf);
	    redirectStateFree(r);
	    redirector->redirectState = NULL;
	    redirector->flags.busy = 0;
	    redirector->offset = 0;
	    n = ++RedirectStats.replies;
	    RedirectStats.avg_svc_time =
		intAverage(RedirectStats.avg_svc_time,
		tvSubMsec(redirector->dispatch_time, current_time),
		n, REDIRECT_AV_FACTOR);
	    if (redirector->flags.shutdown)
		comm_close(redirector->fd);
	}
    } else {
	commSetSelect(redirector->fd,
	    COMM_SELECT_READ,
	    redirectHandleRead,
	    redirector, 0);
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
    dlink_node *n;
    redirector_t *r = NULL;
    for (n = redirectors.head; n != NULL; n = n->next) {
	r = n->data;
	if (r->flags.busy)
	    continue;
	if (!r->flags.alive)
	    continue;
	return r;
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
    redirect->flags.busy = 1;
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
    commSetSelect(redirect->fd,
	COMM_SELECT_READ,
	redirectHandleRead,
	redirect, 0);
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
    cbdataLock(r->data);
    if ((redirector = GetFirstAvailable()))
	redirectDispatch(redirector, r);
    else
	Enqueue(r);
}

static void
redirectorStateFree(int fd, void *data)
{
    redirector_t *r = data;
    assert(r->fd == fd);
    if (r->inbuf) {
	memFree(MEM_8K_BUF, r->inbuf);
	r->inbuf = NULL;
    }
    dlinkDelete(&r->link, &redirectors);
    cbdataFree(r);
    NRedirectorsOpen--;
    if (NRedirectorsOpen == 0 && !shutting_down)
	fatal_dump("All redirectors have exited!");
}

void
redirectOpenServers(void)
{
    char *prg = Config.Program.redirect;
    char *short_prg;
    char *short_prg2;
    redirector_t *redirector;
    int k;
    int redirectsocket;
    LOCAL_ARRAY(char, fd_note_buf, FD_DESC_SZ);
    static int first_time = 0;
    char *s;
    char *args[2];
    int x;

    if (first_time == 0) {
	memset(&redirectors, '\0', sizeof(redirectors));
    }
    assert(redirectors.head == NULL);
    assert(redirectors.tail == NULL);
    if (Config.Program.redirect == NULL)
	return;
    NRedirectors = Config.redirectChildren;
    debug(29, 1) ("redirectOpenServers: Starting %d '%s' processes\n",
	NRedirectors, prg);
    if ((s = strrchr(prg, '/')))
	short_prg = xstrdup(s + 1);
    else
	short_prg = xstrdup(prg);
    short_prg2 = xmalloc(strlen(s) + 3);
    snprintf(short_prg2, strlen(s) + 3, "(%s)", short_prg);
    for (k = 0; k < NRedirectors; k++) {
	args[0] = short_prg2;
	args[1] = NULL;
	x = ipcCreate(IPC_TCP_SOCKET,
	    prg,
	    args,
	    "redirector",
	    &redirectsocket,
	    &redirectsocket);
	if (x < 0) {
	    debug(29, 1) ("WARNING: Cannot run '%s' process.\n", prg);
	    continue;
	}
	NRedirectorsOpen++;
	redirector = xcalloc(1, sizeof(redirector_t));
	cbdataAdd(redirector, MEM_NONE);
	redirector->flags.alive = 1;
	redirector->index = k;
	redirector->fd = redirectsocket;
	redirector->inbuf = memAllocate(MEM_8K_BUF);
	redirector->size = 8192;
	redirector->offset = 0;
	snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d",
	    short_prg,
	    redirector->index + 1);
	fd_note(redirector->fd, fd_note_buf);
	commSetNonBlocking(redirector->fd);
	comm_add_close_handler(redirector->fd, redirectorStateFree, redirector);
	debug(29, 3) ("redirectOpenServers: 'redirect_server' %d started\n",
	    k);
	dlinkAddTail(redirector, &redirector->link, &redirectors);
    }
    if (first_time == 0) {
	first_time++;
	memset(&RedirectStats, '\0', sizeof(RedirectStats));
	cachemgrRegister("redirector",
	    "URL Redirector Stats",
	    redirectStats, 0, 1);
    }
    safe_free(short_prg);
    safe_free(short_prg2);
}

static void
redirectShutdown(redirector_t * r)
{
    if (!r->flags.alive)
	return;
    if (r->flags.closing)
	return;
    debug(29, 3) ("redirectShutdown: closing redirector #%d, FD %d\n",
	r->index + 1, r->fd);
    r->flags.shutdown = 1;
    r->flags.busy = 1;
    /*
     * orphan the redirector, it will have to be freed when its done with
     * the current request
     */
    dlinkDelete(&r->link, &redirectors);
}

void
redirectShutdownServers(void *unused)
{
    dlink_node *n;
    redirector_t *redirect = NULL;
    if (Config.Program.redirect == NULL)
	return;
    for (n = redirectors.head; n != NULL; n = n->next) {
	redirect = n->data;
	redirectShutdown(redirect);
    }
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
