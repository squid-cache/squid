
/*
 * $Id: helper.cc,v 1.34 2001/11/28 08:01:46 robertc Exp $
 *
 * DEBUG: section 29    Helper process maintenance
 * AUTHOR: Harvest Derived?
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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

#define HELPER_MAX_ARGS 64

static PF helperHandleRead;
static PF helperStatefulHandleRead;
static PF helperServerFree;
static PF helperStatefulServerFree;
static void Enqueue(helper * hlp, helper_request *);
static helper_request *Dequeue(helper * hlp);
static helper_stateful_request *StatefulDequeue(statefulhelper * hlp);
static helper_server *GetFirstAvailable(helper * hlp);
static helper_stateful_server *StatefulGetFirstAvailable(statefulhelper * hlp);
static void helperDispatch(helper_server * srv, helper_request * r);
static void helperStatefulDispatch(helper_stateful_server * srv, helper_stateful_request * r);
static void helperKickQueue(helper * hlp);
static void helperStatefulKickQueue(statefulhelper * hlp);
static void helperRequestFree(helper_request * r);
static void helperStatefulRequestFree(helper_stateful_request * r);
static void StatefulEnqueue(statefulhelper * hlp, helper_stateful_request * r);
static helper_stateful_request *StatefulServerDequeue(helper_stateful_server * srv);
static void StatefulServerEnqueue(helper_stateful_server * srv, helper_stateful_request * r);
static void helperStatefulServerKickQueue(helper_stateful_server * srv);

void
helperOpenServers(helper * hlp)
{
    char *s;
    char *progname;
    char *shortname;
    char *procname;
    const char *args[HELPER_MAX_ARGS];
    char fd_note_buf[FD_DESC_SZ];
    helper_server *srv;
    int nargs = 0;
    int k;
    int x;
    int rfd;
    int wfd;
    wordlist *w;
    if (hlp->cmdline == NULL)
	return;
    progname = hlp->cmdline->key;
    if ((s = strrchr(progname, '/')))
	shortname = xstrdup(s + 1);
    else
	shortname = xstrdup(progname);
    debug(29, 1) ("helperOpenServers: Starting %d '%s' processes\n",
	hlp->n_to_start, shortname);
    procname = xmalloc(strlen(shortname) + 3);
    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);
    args[nargs++] = procname;
    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
	args[nargs++] = w->key;
    args[nargs++] = NULL;
    assert(nargs <= HELPER_MAX_ARGS);
    for (k = 0; k < hlp->n_to_start; k++) {
	getCurrentTime();
	rfd = wfd = -1;
	x = ipcCreate(hlp->ipc_type,
	    progname,
	    args,
	    shortname,
	    &rfd,
	    &wfd);
	if (x < 0) {
	    debug(29, 1) ("WARNING: Cannot run '%s' process.\n", progname);
	    continue;
	}
	hlp->n_running++;
	srv = cbdataAlloc(helper_server);
	srv->flags.alive = 1;
	srv->index = k;
	srv->rfd = rfd;
	srv->wfd = wfd;
	srv->buf = memAllocate(MEM_8K_BUF);
	srv->buf_sz = 8192;
	srv->offset = 0;
	srv->parent = hlp;
	cbdataLock(hlp);	/* lock because of the parent backlink */
	dlinkAddTail(srv, &srv->link, &hlp->servers);
	if (rfd == wfd) {
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	} else {
	    snprintf(fd_note_buf, FD_DESC_SZ, "reading %s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	    snprintf(fd_note_buf, FD_DESC_SZ, "writing %s #%d", shortname, k + 1);
	    fd_note(wfd, fd_note_buf);
	}
	commSetNonBlocking(rfd);
	if (wfd != rfd)
	    commSetNonBlocking(wfd);
	comm_add_close_handler(rfd, helperServerFree, srv);
    }
    safe_free(shortname);
    safe_free(procname);
    helperKickQueue(hlp);
}

void
helperStatefulOpenServers(statefulhelper * hlp)
{
    char *s;
    char *progname;
    char *shortname;
    char *procname;
    const char *args[HELPER_MAX_ARGS];
    char fd_note_buf[FD_DESC_SZ];
    helper_stateful_server *srv;
    int nargs = 0;
    int k;
    int x;
    int rfd;
    int wfd;
    wordlist *w;
    if (hlp->cmdline == NULL)
	return;
    progname = hlp->cmdline->key;
    if ((s = strrchr(progname, '/')))
	shortname = xstrdup(s + 1);
    else
	shortname = xstrdup(progname);
    debug(29, 1) ("helperStatefulOpenServers: Starting %d '%s' processes\n",
	hlp->n_to_start, shortname);
    procname = xmalloc(strlen(shortname) + 3);
    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);
    args[nargs++] = procname;
    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
	args[nargs++] = w->key;
    args[nargs++] = NULL;
    assert(nargs <= HELPER_MAX_ARGS);
    for (k = 0; k < hlp->n_to_start; k++) {
	getCurrentTime();
	rfd = wfd = -1;
	x = ipcCreate(hlp->ipc_type,
	    progname,
	    args,
	    shortname,
	    &rfd,
	    &wfd);
	if (x < 0) {
	    debug(29, 1) ("WARNING: Cannot run '%s' process.\n", progname);
	    continue;
	}
	hlp->n_running++;
	srv = cbdataAlloc(helper_stateful_server);
	srv->pid = x;
	srv->flags.alive = 1;
	srv->flags.reserved = S_HELPER_FREE;
	srv->deferred_requests = 0;
	srv->stats.deferbyfunc = 0;
	srv->stats.deferbycb = 0;
	srv->stats.submits = 0;
	srv->stats.releases = 0;
	srv->index = k;
	srv->rfd = rfd;
	srv->wfd = wfd;
	srv->buf = memAllocate(MEM_8K_BUF);
	srv->buf_sz = 8192;
	srv->offset = 0;
	srv->parent = hlp;
	if (hlp->datapool != NULL)
	    srv->data = memPoolAlloc(hlp->datapool);
	cbdataLock(hlp);	/* lock because of the parent backlink */
	dlinkAddTail(srv, &srv->link, &hlp->servers);
	if (rfd == wfd) {
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	} else {
	    snprintf(fd_note_buf, FD_DESC_SZ, "reading %s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	    snprintf(fd_note_buf, FD_DESC_SZ, "writing %s #%d", shortname, k + 1);
	    fd_note(wfd, fd_note_buf);
	}
	commSetNonBlocking(rfd);
	if (wfd != rfd)
	    commSetNonBlocking(wfd);
	comm_add_close_handler(rfd, helperStatefulServerFree, srv);
    }
    safe_free(shortname);
    safe_free(procname);
    helperStatefulKickQueue(hlp);
}


void
helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data)
{
    helper_request *r = memAllocate(MEM_HELPER_REQUEST);
    helper_server *srv;
    if (hlp == NULL) {
	debug(29, 3) ("helperSubmit: hlp == NULL\n");
	callback(data, NULL);
	return;
    }
    r->callback = callback;
    r->data = data;
    r->buf = xstrdup(buf);
    cbdataLock(r->data);
    if ((srv = GetFirstAvailable(hlp)))
	helperDispatch(srv, r);
    else
	Enqueue(hlp, r);
    debug(29, 9) ("helperSubmit: %s\n", buf);
}

/* lastserver = "server last used as part of a deferred or reserved
 * request sequence"
 */
void
helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver)
{
    helper_stateful_request *r = memAllocate(MEM_HELPER_STATEFUL_REQUEST);
    helper_stateful_server *srv;
    if (hlp == NULL) {
	debug(29, 3) ("helperStatefulSubmit: hlp == NULL\n");
	callback(data, 0, NULL);
	return;
    }
    r->callback = callback;
    r->data = data;
    if (buf != NULL) {
	r->buf = xstrdup(buf);
	r->placeholder = 0;
    } else {
	r->buf = NULL;
	r->placeholder = 1;
    }
    cbdataLock(r->data);
    if ((buf != NULL) && lastserver) {
	debug(29, 5) ("StatefulSubmit with lastserver %p\n", lastserver);
	/* the queue doesn't count for this assert because queued requests
	 * have already gone through here and been tested.
	 * It's legal to have deferred_requests == 0 and queue entries 
	 * and status of S_HELPEER_DEFERRED.
	 * BUT:  It's not legal to submit a new request w/lastserver in
	 * that state.
	 */
	assert(!(lastserver->deferred_requests == 0 &&
		lastserver->flags.reserved == S_HELPER_DEFERRED));
	if (lastserver->flags.reserved != S_HELPER_RESERVED) {
	    lastserver->stats.submits++;
	    lastserver->deferred_requests--;
	}
	if (!(lastserver->request)) {
	    debug(29, 5) ("StatefulSubmit dispatching\n");
	    helperStatefulDispatch(lastserver, r);
	} else {
	    debug(29, 5) ("StatefulSubmit queuing\n");
	    StatefulServerEnqueue(lastserver, r);
	}
    } else {
	if ((srv = StatefulGetFirstAvailable(hlp))) {
	    helperStatefulDispatch(srv, r);
	} else
	    StatefulEnqueue(hlp, r);
    }
    debug(29, 9) ("helperStatefulSubmit: placeholder: '%d', buf '%s'.\n", r->placeholder, buf);
}

helper_stateful_server *
helperStatefulDefer(statefulhelper * hlp)
/* find and add a deferred request to a server */
{
    dlink_node *n;
    helper_stateful_server *srv = NULL, *rv = NULL;
    if (hlp == NULL) {
	debug(29, 3) ("helperStatefulReserve: hlp == NULL\n");
	return NULL;
    }
    debug(29, 5) ("helperStatefulDefer: Running servers %d.\n", hlp->n_running);
    if (hlp->n_running == 0) {
	debug(29, 1) ("helperStatefulDefer: No running servers!. \n");
	return NULL;
    }
    srv = StatefulGetFirstAvailable(hlp);
    /* all currently busy:loop through servers and find server with the shortest queue */
    rv = srv;
    if (rv == NULL)
	for (n = hlp->servers.head; n != NULL; n = n->next) {
	    srv = n->data;
	    if (srv->flags.reserved == S_HELPER_RESERVED)
		continue;
	    if (!srv->flags.alive)
		continue;
	    if ((hlp->IsAvailable != NULL) && (srv->data != NULL) &&
		!(hlp->IsAvailable(srv->data)))
		continue;
	    if ((rv != NULL) && (rv->deferred_requests < srv->deferred_requests))
		continue;
	    rv = srv;
	}
    if (rv == NULL) {
	debug(29, 1) ("helperStatefulDefer: None available.\n");
	return NULL;
    }
    /* consistency check:
     * when the deferred count is 0,
     *   submits + releases == deferbyfunc + deferbycb
     * Or in english, when there are no deferred requests, the amount
     * we have submitted to the queue or cancelled must equal the amount
     * we have said we wanted to be able to submit or cancel
     */
    if (rv->deferred_requests == 0)
	assert(rv->stats.submits + rv->stats.releases ==
	    rv->stats.deferbyfunc + rv->stats.deferbycb);

    rv->flags.reserved = S_HELPER_DEFERRED;
    rv->deferred_requests++;
    rv->stats.deferbyfunc++;
    return rv;
}

void
helperStatefulReset(helper_stateful_server * srv)
/* puts this helper back in the queue. the calling app is required to 
 * manage the state in the helper.
 */
{
    statefulhelper *hlp = srv->parent;
    helper_stateful_request *r;
    r = srv->request;
    if (r != NULL) {
	/* reset attempt DURING an outstaning request */
	debug(29, 1) ("helperStatefulReset: RESET During request %s \n",
	    hlp->id_name);
	srv->flags.busy = 0;
	srv->offset = 0;
	helperStatefulRequestFree(r);
	srv->request = NULL;
    }
    srv->flags.busy = 0;
    if (srv->queue.head) {
	srv->flags.reserved = S_HELPER_DEFERRED;
	helperStatefulServerKickQueue(srv);
    } else {
	srv->flags.reserved = S_HELPER_FREE;
	if ((srv->parent->OnEmptyQueue != NULL) && (srv->data))
	    srv->parent->OnEmptyQueue(srv->data);
	helperStatefulKickQueue(hlp);
    }
}

void
helperStatefulReleaseServer(helper_stateful_server * srv)
/*decrease the number of 'waiting' clients that set the helper to be DEFERRED */
{
    srv->stats.releases++;
    if (srv->flags.reserved == S_HELPER_DEFERRED) {
	assert(srv->deferred_requests);
	srv->deferred_requests--;
    }
    if (!(srv->deferred_requests) && (srv->flags.reserved == S_HELPER_DEFERRED) && !(srv->queue.head)) {
	srv->flags.reserved = S_HELPER_FREE;
	if ((srv->parent->OnEmptyQueue != NULL) && (srv->data))
	    srv->parent->OnEmptyQueue(srv->data);
    }
}

void *
helperStatefulServerGetData(helper_stateful_server * srv)
/* return a pointer to the stateful routines data area */
{
    return srv->data;
}

void
helperStats(StoreEntry * sentry, helper * hlp)
{
    helper_server *srv;
    dlink_node *link;
    double tt;
    storeAppendPrintf(sentry, "number running: %d of %d\n",
	hlp->n_running, hlp->n_to_start);
    storeAppendPrintf(sentry, "requests sent: %d\n",
	hlp->stats.requests);
    storeAppendPrintf(sentry, "replies received: %d\n",
	hlp->stats.replies);
    storeAppendPrintf(sentry, "queue length: %d\n",
	hlp->stats.queue_size);
    storeAppendPrintf(sentry, "avg service time: %d msec\n",
	hlp->stats.avg_svc_time);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "%7s\t%7s\t%11s\t%s\t%7s\t%7s\t%7s\n",
	"#",
	"FD",
	"# Requests",
	"Flags",
	"Time",
	"Offset",
	"Request");
    for (link = hlp->servers.head; link; link = link->next) {
	srv = link->data;
	tt = 0.001 * tvSubMsec(srv->dispatch_time, current_time);
	storeAppendPrintf(sentry, "%7d\t%7d\t%11d\t%c%c%c%c\t%7.3f\t%7d\t%s\n",
	    srv->index + 1,
	    srv->rfd,
	    srv->stats.uses,
	    srv->flags.alive ? 'A' : ' ',
	    srv->flags.busy ? 'B' : ' ',
	    srv->flags.closing ? 'C' : ' ',
	    srv->flags.shutdown ? 'S' : ' ',
	    tt < 0.0 ? 0.0 : tt,
	    (int) srv->offset,
	    srv->request ? log_quote(srv->request->buf) : "(none)");
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
    storeAppendPrintf(sentry, "   S = SHUTDOWN\n");
}

void
helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp)
{
    helper_stateful_server *srv;
    dlink_node *link;
    double tt;
    storeAppendPrintf(sentry, "number running: %d of %d\n",
	hlp->n_running, hlp->n_to_start);
    storeAppendPrintf(sentry, "requests sent: %d\n",
	hlp->stats.requests);
    storeAppendPrintf(sentry, "replies received: %d\n",
	hlp->stats.replies);
    storeAppendPrintf(sentry, "queue length: %d\n",
	hlp->stats.queue_size);
    storeAppendPrintf(sentry, "avg service time: %d msec\n",
	hlp->stats.avg_svc_time);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "%7s\t%7s\t%7s\t%11s\t%s\t%7s\t%7s\t%7s\t%7s\n",
	"#",
	"FD",
	"PID",
	"# Requests",
	"# Deferred Requests",
	"Flags",
	"Time",
	"Offset",
	"Request");
    for (link = hlp->servers.head; link; link = link->next) {
	srv = link->data;
	tt = 0.001 * tvSubMsec(srv->dispatch_time, current_time);
	storeAppendPrintf(sentry, "%7d\t%7d\t%7d\t%11d\t%11d\t%c%c%c%c%c%c\t%7.3f\t%7d\t%s\n",
	    srv->index + 1,
	    srv->rfd,
	    srv->pid,
	    srv->stats.uses,
	    (int) srv->deferred_requests,
	    srv->flags.alive ? 'A' : ' ',
	    srv->flags.busy ? 'B' : ' ',
	    srv->flags.closing ? 'C' : ' ',
	    srv->flags.reserved != S_HELPER_FREE ? 'R' : ' ',
	    srv->flags.shutdown ? 'S' : ' ',
	    srv->request ? (srv->request->placeholder ? 'P' : ' ') : ' ',
	    tt < 0.0 ? 0.0 : tt,
	    (int) srv->offset,
	    srv->request ? log_quote(srv->request->buf) : "(none)");
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
    storeAppendPrintf(sentry, "   R = RESERVED or DEFERRED\n");
    storeAppendPrintf(sentry, "   S = SHUTDOWN\n");
    storeAppendPrintf(sentry, "   P = PLACEHOLDER\n");
}

void
helperShutdown(helper * hlp)
{
    dlink_node *link = hlp->servers.head;
    helper_server *srv;
    while (link) {
	srv = link->data;
	link = link->next;
	if (!srv->flags.alive) {
	    debug(34, 3) ("helperShutdown: %s #%d is NOT ALIVE.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.shutdown = 1;	/* request it to shut itself down */
	if (srv->flags.busy) {
	    debug(34, 3) ("helperShutdown: %s #%d is BUSY.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.closing) {
	    debug(34, 3) ("helperShutdown: %s #%d is CLOSING.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.closing = 1;
	comm_close(srv->wfd);
	srv->wfd = -1;
    }
}

void
helperStatefulShutdown(statefulhelper * hlp)
{
    dlink_node *link = hlp->servers.head;
    helper_stateful_server *srv;
    while (link) {
	srv = link->data;
	link = link->next;
	if (!srv->flags.alive) {
	    debug(34, 3) ("helperStatefulShutdown: %s #%d is NOT ALIVE.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.shutdown = 1;	/* request it to shut itself down */
	if (srv->flags.busy) {
	    debug(34, 3) ("helperStatefulShutdown: %s #%d is BUSY.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.closing) {
	    debug(34, 3) ("helperStatefulShutdown: %s #%d is CLOSING.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.reserved != S_HELPER_FREE) {
	    debug(34, 3) ("helperStatefulShutdown: %s #%d is RESERVED.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->deferred_requests) {
	    debug(34, 3) ("helperStatefulShutdown: %s #%d has DEFERRED requests.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.closing = 1;
	comm_close(srv->wfd);
	srv->wfd = -1;
    }
}


helper *
helperCreate(const char *name)
{
    helper *hlp;
    hlp = cbdataAlloc(helper);
    hlp->id_name = name;
    return hlp;
}

statefulhelper *
helperStatefulCreate(const char *name)
{
    statefulhelper *hlp;
    hlp = cbdataAlloc(statefulhelper);
    hlp->id_name = name;
    return hlp;
}


void
helperFree(helper * hlp)
{
    if (!hlp)
	return;
    /* note, don't free hlp->name, it probably points to static memory */
    if (hlp->queue.head)
	debug(29, 0) ("WARNING: freeing %s helper with %d requests queued\n",
	    hlp->id_name, hlp->stats.queue_size);
    cbdataFree(hlp);
}

void
helperStatefulFree(statefulhelper * hlp)
{
    if (!hlp)
	return;
    /* note, don't free hlp->name, it probably points to static memory */
    if (hlp->queue.head)
	debug(29, 0) ("WARNING: freeing %s helper with %d requests queued\n",
	    hlp->id_name, hlp->stats.queue_size);
    cbdataFree(hlp);
}


/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

static void
helperServerFree(int fd, void *data)
{
    helper_server *srv = data;
    helper *hlp = srv->parent;
    helper_request *r;
    assert(srv->rfd == fd);
    if (srv->buf) {
	memFree(srv->buf, MEM_8K_BUF);
	srv->buf = NULL;
    }
    if ((r = srv->request)) {
	if (cbdataValid(r->data))
	    r->callback(r->data, srv->buf);
	helperRequestFree(r);
	srv->request = NULL;
    }
    if (srv->wfd != srv->rfd && srv->wfd != -1)
	comm_close(srv->wfd);
    dlinkDelete(&srv->link, &hlp->servers);
    hlp->n_running--;
    assert(hlp->n_running >= 0);
    if (!srv->flags.shutdown) {
	debug(34, 0) ("WARNING: %s #%d (FD %d) exited\n",
	    hlp->id_name, srv->index + 1, fd);
	if (hlp->n_running < hlp->n_to_start / 2)
	    fatalf("Too few %s processes are running", hlp->id_name);
    }
    cbdataUnlock(srv->parent);
    cbdataFree(srv);
}

static void
helperStatefulServerFree(int fd, void *data)
{
    helper_stateful_server *srv = data;
    statefulhelper *hlp = srv->parent;
    helper_stateful_request *r;
    assert(srv->rfd == fd);
    if (srv->buf) {
	memFree(srv->buf, MEM_8K_BUF);
	srv->buf = NULL;
    }
    if ((r = srv->request)) {
	if (cbdataValid(r->data))
	    r->callback(r->data, srv, srv->buf);
	helperStatefulRequestFree(r);
	srv->request = NULL;
    }
    /* TODO: walk the local queue of requests and carry them all out */
    if (srv->wfd != srv->rfd && srv->wfd != -1)
	comm_close(srv->wfd);
    dlinkDelete(&srv->link, &hlp->servers);
    hlp->n_running--;
    assert(hlp->n_running >= 0);
    if (!srv->flags.shutdown) {
	debug(34, 0) ("WARNING: %s #%d (FD %d) exited\n",
	    hlp->id_name, srv->index + 1, fd);
	if (hlp->n_running < hlp->n_to_start / 2)
	    fatalf("Too few %s processes are running", hlp->id_name);
    }
    if (srv->data != NULL)
	memPoolFree(hlp->datapool, srv->data);
    cbdataUnlock(srv->parent);
    cbdataFree(srv);
}


static void
helperHandleRead(int fd, void *data)
{
    int len;
    char *t = NULL;
    helper_server *srv = data;
    helper_request *r;
    helper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataValid(data));
    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd, srv->buf + srv->offset, srv->buf_sz - srv->offset);
    fd_bytes(fd, len, FD_READ);
    debug(29, 5) ("helperHandleRead: %d bytes from %s #%d.\n",
	len, hlp->id_name, srv->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(50, 1) ("helperHandleRead: FD %d read: %s\n", fd, xstrerror());
	comm_close(fd);
	return;
    }
    srv->offset += len;
    srv->buf[srv->offset] = '\0';
    r = srv->request;
    if (r == NULL) {
	/* someone spoke without being spoken to */
	debug(29, 1) ("helperHandleRead: unexpected read from %s #%d, %d bytes\n",
	    hlp->id_name, srv->index + 1, len);
	srv->offset = 0;
    } else if ((t = strchr(srv->buf, '\n'))) {
	/* end of reply found */
	debug(29, 3) ("helperHandleRead: end of reply found\n");
	*t = '\0';
	if (cbdataValid(r->data))
	    r->callback(r->data, srv->buf);
	srv->flags.busy = 0;
	srv->offset = 0;
	helperRequestFree(r);
	srv->request = NULL;
	hlp->stats.replies++;
	hlp->stats.avg_svc_time =
	    intAverage(hlp->stats.avg_svc_time,
	    tvSubMsec(srv->dispatch_time, current_time),
	    hlp->stats.replies, REDIRECT_AV_FACTOR);
	if (srv->flags.shutdown) {
	    comm_close(srv->wfd);
	    srv->wfd = -1;
	} else
	    helperKickQueue(hlp);
    } else {
	commSetSelect(srv->rfd, COMM_SELECT_READ, helperHandleRead, srv, 0);
    }
}

static void
helperStatefulHandleRead(int fd, void *data)
{
    int len;
    char *t = NULL;
    helper_stateful_server *srv = data;
    helper_stateful_request *r;
    statefulhelper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataValid(data));
    statCounter.syscalls.sock.reads++;
    len = read(fd, srv->buf + srv->offset, srv->buf_sz - srv->offset);
    fd_bytes(fd, len, FD_READ);
    debug(29, 5) ("helperStatefulHandleRead: %d bytes from %s #%d.\n",
	len, hlp->id_name, srv->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(50, 1) ("helperStatefulHandleRead: FD %d read: %s\n", fd, xstrerror());
	comm_close(fd);
	return;
    }
    srv->offset += len;
    srv->buf[srv->offset] = '\0';
    r = srv->request;
    if (r == NULL) {
	/* someone spoke without being spoken to */
	debug(29, 1) ("helperStatefulHandleRead: unexpected read from %s #%d, %d bytes\n",
	    hlp->id_name, srv->index + 1, len);
	srv->offset = 0;
    } else if ((t = strchr(srv->buf, '\n'))) {
	/* end of reply found */
	debug(29, 3) ("helperStatefulHandleRead: end of reply found\n");
	*t = '\0';
	if (cbdataValid(r->data)) {
	    switch ((r->callback(r->data, srv, srv->buf))) {	/*if non-zero reserve helper */
	    case S_HELPER_UNKNOWN:
		fatal("helperStatefulHandleRead: either a non-state aware callback was give to the stateful helper routines, or an uninitialised callback response was recieved.\n");
		break;
	    case S_HELPER_RELEASE:	/* helper finished with */
		if (!srv->deferred_requests && !srv->queue.head) {
		    srv->flags.reserved = S_HELPER_FREE;
		    if ((srv->parent->OnEmptyQueue != NULL) && (srv->data))
			srv->parent->OnEmptyQueue(srv->data);
		    debug(29, 5) ("StatefulHandleRead: releasing %s #%d\n", hlp->id_name, srv->index + 1);
		} else {
		    srv->flags.reserved = S_HELPER_DEFERRED;
		    debug(29, 5) ("StatefulHandleRead: outstanding deferred requests on %s #%d. reserving for deferred requests.\n", hlp->id_name, srv->index + 1);
		}
		break;
	    case S_HELPER_RESERVE:	/* 'pin' this helper for the caller */
		if (!srv->queue.head) {
		    assert(srv->deferred_requests == 0);
		    srv->flags.reserved = S_HELPER_RESERVED;
		    debug(29, 5) ("StatefulHandleRead: reserving %s #%d\n", hlp->id_name, srv->index + 1);
		} else {
		    fatal("StatefulHandleRead: Callback routine attempted to reserve a stateful helper with deferred requests. This can lead to deadlock.\n");
		}
		break;
	    case S_HELPER_DEFER:
		/* the helper is still needed, but can
		 * be used for other requests in the meantime.
		 */
		srv->flags.reserved = S_HELPER_DEFERRED;
		srv->deferred_requests++;
		srv->stats.deferbycb++;
		debug(29, 5) ("StatefulHandleRead: reserving %s #%d for deferred requests.\n", hlp->id_name, srv->index + 1);
		break;
	    default:
		fatal("helperStatefulHandleRead: unknown stateful helper callback result.\n");
	    }

	} else {
	    debug(29, 1) ("StatefulHandleRead: no callback data registered\n");
	}
	srv->flags.busy = 0;
	srv->offset = 0;
	helperStatefulRequestFree(r);
	srv->request = NULL;
	hlp->stats.replies++;
	hlp->stats.avg_svc_time =
	    intAverage(hlp->stats.avg_svc_time,
	    tvSubMsec(srv->dispatch_time, current_time),
	    hlp->stats.replies, REDIRECT_AV_FACTOR);
	if (srv->flags.shutdown
	    && srv->flags.reserved == S_HELPER_FREE
	    && !srv->deferred_requests) {
	    comm_close(srv->wfd);
	    srv->wfd = -1;
	} else {
	    if (srv->queue.head)
		helperStatefulServerKickQueue(srv);
	    else
		helperStatefulKickQueue(hlp);
	}
    } else {
	commSetSelect(srv->rfd, COMM_SELECT_READ, helperStatefulHandleRead, srv, 0);
    }
}

static void
Enqueue(helper * hlp, helper_request * r)
{
    dlink_node *link = memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;
    if (hlp->stats.queue_size < hlp->n_running)
	return;
    if (squid_curtime - hlp->last_queue_warn < 600)
	return;
    if (shutting_down || reconfiguring)
	return;
    hlp->last_queue_warn = squid_curtime;
    debug(14, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);
    debug(14, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);
    if (hlp->stats.queue_size > hlp->n_running * 2)
	fatalf("Too many queued %s requests", hlp->id_name);
    debug(14, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);
}

static void
StatefulEnqueue(statefulhelper * hlp, helper_stateful_request * r)
{
    dlink_node *link = memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;
    if (hlp->stats.queue_size < hlp->n_running)
	return;
    if (squid_curtime - hlp->last_queue_warn < 600)
	return;
    if (shutting_down || reconfiguring)
	return;
    hlp->last_queue_warn = squid_curtime;
    debug(14, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);
    debug(14, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);
    if (hlp->stats.queue_size > hlp->n_running * 2)
	fatalf("Too many queued %s requests", hlp->id_name);
    debug(14, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);
}

static void
StatefulServerEnqueue(helper_stateful_server * srv, helper_stateful_request * r)
{
    dlink_node *link = memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &srv->queue);
/* TODO: warning if the queue on this server is more than X
 * We don't check the queue size at the moment, because
 * requests hitting here are deferrable 
 */
/*    hlp->stats.queue_size++;
 * if (hlp->stats.queue_size < hlp->n_running)
 * return;
 * if (squid_curtime - hlp->last_queue_warn < 600)
 * return;
 * if (shutting_down || reconfiguring)
 * return;
 * hlp->last_queue_warn = squid_curtime;
 * debug(14, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);
 * debug(14, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);
 * if (hlp->stats.queue_size > hlp->n_running * 2)
 * fatalf("Too many queued %s requests", hlp->id_name);
 * debug(14, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);  */
}


static helper_request *
Dequeue(helper * hlp)
{
    dlink_node *link;
    helper_request *r = NULL;
    if ((link = hlp->queue.head)) {
	r = link->data;
	dlinkDelete(link, &hlp->queue);
	memFree(link, MEM_DLINK_NODE);
	hlp->stats.queue_size--;
    }
    return r;
}

static helper_stateful_request *
StatefulServerDequeue(helper_stateful_server * srv)
{
    dlink_node *link;
    helper_stateful_request *r = NULL;
    if ((link = srv->queue.head)) {
	r = link->data;
	dlinkDelete(link, &srv->queue);
	memFree(link, MEM_DLINK_NODE);
    }
    return r;
}

static helper_stateful_request *
StatefulDequeue(statefulhelper * hlp)
{
    dlink_node *link;
    helper_stateful_request *r = NULL;
    if ((link = hlp->queue.head)) {
	r = link->data;
	dlinkDelete(link, &hlp->queue);
	memFree(link, MEM_DLINK_NODE);
	hlp->stats.queue_size--;
    }
    return r;
}

static helper_server *
GetFirstAvailable(helper * hlp)
{
    dlink_node *n;
    helper_server *srv = NULL;
    if (hlp->n_running == 0)
	return NULL;
    for (n = hlp->servers.head; n != NULL; n = n->next) {
	srv = n->data;
	if (srv->flags.busy)
	    continue;
	if (!srv->flags.alive)
	    continue;
	return srv;
    }
    return NULL;
}

static helper_stateful_server *
StatefulGetFirstAvailable(statefulhelper * hlp)
{
    dlink_node *n;
    helper_stateful_server *srv = NULL;
    debug(29, 5) ("StatefulGetFirstAvailable: Running servers %d.\n", hlp->n_running);
    if (hlp->n_running == 0)
	return NULL;
    for (n = hlp->servers.head; n != NULL; n = n->next) {
	srv = n->data;
	if (srv->flags.busy)
	    continue;
	if (srv->flags.reserved == S_HELPER_RESERVED)
	    continue;
	if (!srv->flags.alive)
	    continue;
	if ((hlp->IsAvailable != NULL) && (srv->data != NULL) && !(hlp->IsAvailable(srv->data)))
	    continue;
	return srv;
    }
    debug(29, 5) ("StatefulGetFirstAvailable: None available.\n");
    return NULL;
}


static void
helperDispatch(helper_server * srv, helper_request * r)
{
    helper *hlp = srv->parent;
    if (!cbdataValid(r->data)) {
	debug(29, 1) ("helperDispatch: invalid callback data\n");
	helperRequestFree(r);
	return;
    }
    assert(!srv->flags.busy);
    srv->flags.busy = 1;
    srv->request = r;
    srv->dispatch_time = current_time;
    comm_write(srv->wfd,
	r->buf,
	strlen(r->buf),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	NULL);			/* free */
    commSetSelect(srv->rfd,
	COMM_SELECT_READ,
	helperHandleRead,
	srv, 0);
    debug(29, 5) ("helperDispatch: Request sent to %s #%d, %d bytes\n",
	hlp->id_name, srv->index + 1, (int) strlen(r->buf));
    srv->stats.uses++;
    hlp->stats.requests++;
}

static void
helperStatefulDispatch(helper_stateful_server * srv, helper_stateful_request * r)
{
    statefulhelper *hlp = srv->parent;
    if (!cbdataValid(r->data)) {
	debug(29, 1) ("helperStatefulDispatch: invalid callback data\n");
	helperStatefulRequestFree(r);
	return;
    }
    debug(29, 9) ("helperStatefulDispatch busying helper %s #%d\n", hlp->id_name, srv->index + 1);
    if (r->placeholder == 1) {
	/* a callback is needed before this request can _use_ a helper. */
	/* we don't care about releasing/deferring this helper. The request NEVER
	 * gets to the helper. So we throw away the return code */
	r->callback(r->data, srv, NULL);
	/* throw away the placeholder */
	helperStatefulRequestFree(r);
	/* and push the queue. Note that the callback may have submitted a new 
	 * request to the helper which is why we test for the request*/
	if (srv->request == NULL) {
	    if (srv->flags.shutdown
		&& srv->flags.reserved == S_HELPER_FREE
		&& !srv->deferred_requests) {
		comm_close(srv->wfd);
		srv->wfd = -1;
	    } else {
		if (srv->queue.head)
		    helperStatefulServerKickQueue(srv);
		else
		    helperStatefulKickQueue(hlp);
	    }
	}
	return;
    }
    srv->flags.busy = 1;
    srv->request = r;
    srv->dispatch_time = current_time;
    comm_write(srv->wfd,
	r->buf,
	strlen(r->buf),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	NULL);			/* free */
    commSetSelect(srv->rfd,
	COMM_SELECT_READ,
	helperStatefulHandleRead,
	srv, 0);
    debug(29, 5) ("helperStatefulDispatch: Request sent to %s #%d, %d bytes\n",
	hlp->id_name, srv->index + 1, (int) strlen(r->buf));
    srv->stats.uses++;
    hlp->stats.requests++;
}


static void
helperKickQueue(helper * hlp)
{
    helper_request *r;
    helper_server *srv;
    while ((srv = GetFirstAvailable(hlp)) && (r = Dequeue(hlp)))
	helperDispatch(srv, r);
}

static void
helperStatefulKickQueue(statefulhelper * hlp)
{
    helper_stateful_request *r;
    helper_stateful_server *srv;
    while ((srv = StatefulGetFirstAvailable(hlp)) && (r = StatefulDequeue(hlp)))
	helperStatefulDispatch(srv, r);
}

static void
helperStatefulServerKickQueue(helper_stateful_server * srv)
{
    helper_stateful_request *r;
    if ((r = StatefulServerDequeue(srv)))
	helperStatefulDispatch(srv, r);
}

static void
helperRequestFree(helper_request * r)
{
    cbdataUnlock(r->data);
    xfree(r->buf);
    memFree(r, MEM_HELPER_REQUEST);
}

static void
helperStatefulRequestFree(helper_stateful_request * r)
{
    cbdataUnlock(r->data);
    xfree(r->buf);
    memFree(r, MEM_HELPER_STATEFUL_REQUEST);
}
