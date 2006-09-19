
/*
 * $Id: helper.cc,v 1.78 2006/09/19 07:56:57 adrian Exp $
 *
 * DEBUG: section 84    Helper process maintenance
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
#include "helper.h"
#include "SquidTime.h"
#include "Store.h"
#include "comm.h"
#include "MemBuf.h"
#include "wordlist.h"

#define HELPER_MAX_ARGS 64

static IOCB helperHandleRead;
static IOCB helperStatefulHandleRead;
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

CBDATA_TYPE(helper);
CBDATA_TYPE(helper_server);
CBDATA_TYPE(statefulhelper);
CBDATA_TYPE(helper_stateful_server);

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
    pid_t pid;
    int rfd;
    int wfd;
    void * hIpc;
    wordlist *w;

    if (hlp->cmdline == NULL)
        return;

    progname = hlp->cmdline->key;

    if ((s = strrchr(progname, '/')))
        shortname = xstrdup(s + 1);
    else
        shortname = xstrdup(progname);

    debug(84, 1) ("helperOpenServers: Starting %d '%s' processes\n",
                  hlp->n_to_start, shortname);

    procname = (char *)xmalloc(strlen(shortname) + 3);

    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);

    args[nargs++] = procname;

    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
        args[nargs++] = w->key;

    args[nargs++] = NULL;

    assert(nargs <= HELPER_MAX_ARGS);

    for (k = 0; k < hlp->n_to_start; k++) {
        getCurrentTime();
        rfd = wfd = -1;
        pid = ipcCreate(hlp->ipc_type,
                        progname,
                        args,
                        shortname,
                        &rfd,
                        &wfd,
                        &hIpc);

        if (pid < 0) {
            debug(84, 1) ("WARNING: Cannot run '%s' process.\n", progname);
            continue;
        }

        hlp->n_running++;
        hlp->n_active++;
        CBDATA_INIT_TYPE(helper_server);
        srv = cbdataAlloc(helper_server);
        srv->hIpc = hIpc;
        srv->pid = pid;
        srv->index = k;
        srv->rfd = rfd;
        srv->wfd = wfd;
        srv->rbuf = (char *)memAllocBuf(8192, &srv->rbuf_sz);
        srv->wqueue = new MemBuf;
        srv->roffset = 0;
        srv->requests = (helper_request **)xcalloc(hlp->concurrency ? hlp->concurrency : 1, sizeof(*srv->requests));
        srv->parent = cbdataReference(hlp);
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

        comm_read(srv->rfd, srv->rbuf, srv->rbuf_sz - 1, helperHandleRead, srv);
    }

    hlp->last_restart = squid_curtime;
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
    pid_t pid;
    int rfd;
    int wfd;
    void * hIpc;
    wordlist *w;

    if (hlp->cmdline == NULL)
        return;

    progname = hlp->cmdline->key;

    if ((s = strrchr(progname, '/')))
        shortname = xstrdup(s + 1);
    else
        shortname = xstrdup(progname);

    debug(84, 1) ("helperStatefulOpenServers: Starting %d '%s' processes\n",
                  hlp->n_to_start, shortname);

    procname = (char *)xmalloc(strlen(shortname) + 3);

    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);

    args[nargs++] = procname;

    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
        args[nargs++] = w->key;

    args[nargs++] = NULL;

    assert(nargs <= HELPER_MAX_ARGS);

    for (k = 0; k < hlp->n_to_start; k++) {
        getCurrentTime();
        rfd = wfd = -1;
        pid = ipcCreate(hlp->ipc_type,
                        progname,
                        args,
                        shortname,
                        &rfd,
                        &wfd,
                        &hIpc);

        if (pid < 0) {
            debug(84, 1) ("WARNING: Cannot run '%s' process.\n", progname);
            continue;
        }

        hlp->n_running++;
        hlp->n_active++;
        CBDATA_INIT_TYPE(helper_stateful_server);
        srv = cbdataAlloc(helper_stateful_server);
        srv->hIpc = hIpc;
        srv->pid = pid;
        srv->flags.reserved = S_HELPER_FREE;
        srv->deferred_requests = 0;
        srv->stats.deferbyfunc = 0;
        srv->stats.deferbycb = 0;
        srv->stats.submits = 0;
        srv->stats.releases = 0;
        srv->index = k;
        srv->rfd = rfd;
        srv->wfd = wfd;
        srv->rbuf = (char *)memAllocBuf(8192, &srv->rbuf_sz);
        srv->roffset = 0;
        srv->parent = cbdataReference(hlp);

        if (hlp->datapool != NULL)
            srv->data = hlp->datapool->alloc();

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

        comm_read(srv->rfd, srv->rbuf, srv->rbuf_sz - 1, helperStatefulHandleRead, srv);

    }

    hlp->last_restart = squid_curtime;
    safe_free(shortname);
    safe_free(procname);
    helperStatefulKickQueue(hlp);
}


void
helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data)
{
    helper_request *r = new helper_request;
    helper_server *srv;

    if (hlp == NULL) {
        debug(84, 3) ("helperSubmit: hlp == NULL\n");
        callback(data, NULL);
        return;
    }

    r->callback = callback;
    r->data = cbdataReference(data);
    r->buf = xstrdup(buf);

    if ((srv = GetFirstAvailable(hlp)))
        helperDispatch(srv, r);
    else
        Enqueue(hlp, r);

    debug(84, 9) ("helperSubmit: %s\n", buf);
}

/* lastserver = "server last used as part of a deferred or reserved
 * request sequence"
 */
void
helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver)
{
    helper_stateful_request *r = new helper_stateful_request;
    helper_stateful_server *srv;

    if (hlp == NULL) {
        debug(84, 3) ("helperStatefulSubmit: hlp == NULL\n");
        callback(data, 0, NULL);
        return;
    }

    r->callback = callback;
    r->data = cbdataReference(data);

    if (buf != NULL) {
        r->buf = xstrdup(buf);
        r->placeholder = 0;
    } else {
        r->buf = NULL;
        r->placeholder = 1;
    }

    if ((buf != NULL) && lastserver) {
        debug(84, 5) ("StatefulSubmit with lastserver %p\n", lastserver);
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
            debug(84, 5) ("StatefulSubmit dispatching\n");
            helperStatefulDispatch(lastserver, r);
        } else {
            debug(84, 5) ("StatefulSubmit queuing\n");
            StatefulServerEnqueue(lastserver, r);
        }
    } else {
        if ((srv = StatefulGetFirstAvailable(hlp))) {
            helperStatefulDispatch(srv, r);
        } else
            StatefulEnqueue(hlp, r);
    }

    debug(84, 9) ("helperStatefulSubmit: placeholder: '%d', buf '%s'.\n", r->placeholder, buf);
}

helper_stateful_server *
helperStatefulDefer(statefulhelper * hlp)
/* find and add a deferred request to a server */
{
    dlink_node *n;
    helper_stateful_server *srv = NULL, *rv = NULL;

    if (hlp == NULL)
    {
        debug(84, 3) ("helperStatefulDefer: hlp == NULL\n");
        return NULL;
    }

    debug(84, 5) ("helperStatefulDefer: Running servers %d.\n", hlp->n_running);

    if (hlp->n_running == 0)
    {
        debug(84, 1) ("helperStatefulDefer: No running servers!. \n");
        return NULL;
    }

    rv = srv = StatefulGetFirstAvailable(hlp);

    if (rv == NULL)
    {
        /*
         * all currently busy; loop through servers and find server
         * with the shortest queue
         */

        for (n = hlp->servers.head; n != NULL; n = n->next) {
            srv = (helper_stateful_server *)n->data;

            if (srv->flags.reserved == S_HELPER_RESERVED)
                continue;

            if (!srv->flags.shutdown)
                continue;

            if ((hlp->IsAvailable != NULL) && (srv->data != NULL) &&
                    !(hlp->IsAvailable(srv->data)))
                continue;

            if ((rv != NULL) && (rv->deferred_requests < srv->deferred_requests))
                continue;

            rv = srv;
        }
    }

    if (rv == NULL)
    {
        debug(84, 1) ("helperStatefulDefer: None available.\n");
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

    if (r != NULL)
    {
        /* reset attempt DURING an outstaning request */
        debug(84, 1) ("helperStatefulReset: RESET During request %s \n",
                      hlp->id_name);
        srv->flags.busy = 0;
        srv->roffset = 0;
        helperStatefulRequestFree(r);
        srv->request = NULL;
    }

    srv->flags.busy = 0;

    if (srv->queue.head)
    {
        srv->flags.reserved = S_HELPER_DEFERRED;
        helperStatefulServerKickQueue(srv);
    } else
    {
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

    if (srv->flags.reserved == S_HELPER_DEFERRED)
    {
        assert(srv->deferred_requests);
        srv->deferred_requests--;
    }

    if (!(srv->deferred_requests) && (srv->flags.reserved == S_HELPER_DEFERRED) && !(srv->queue.head))
    {
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
    dlink_node *link;
    storeAppendPrintf(sentry, "program: %s\n",
                      hlp->cmdline->key);
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
    storeAppendPrintf(sentry, "%7s\t%7s\t%7s\t%11s\t%s\t%7s\t%7s\t%7s\n",
                      "#",
                      "FD",
                      "PID",
                      "# Requests",
                      "Flags",
                      "Time",
                      "Offset",
                      "Request");

    for (link = hlp->servers.head; link; link = link->next) {
        helper_server *srv = (helper_server*)link->data;
        double tt = 0.001 * (srv->requests[0] ? tvSubMsec(srv->requests[0]->dispatch_time, current_time) : tvSubMsec(srv->dispatch_time, srv->answer_time));
        storeAppendPrintf(sentry, "%7d\t%7d\t%7d\t%11d\t%c%c%c%c\t%7.3f\t%7d\t%s\n",
                          srv->index + 1,
                          srv->rfd,
                          srv->pid,
                          srv->stats.uses,
                          srv->stats.pending ? 'B' : ' ',
                          srv->flags.writing ? 'W' : ' ',
                          srv->flags.closing ? 'C' : ' ',
                          srv->flags.shutdown ? 'S' : ' ',
                          tt < 0.0 ? 0.0 : tt,
                          (int) srv->roffset,
                          srv->requests[0] ? log_quote(srv->requests[0]->buf) : "(none)");
    }

    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   W = WRITING\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
    storeAppendPrintf(sentry, "   S = SHUTDOWN\n");
}

void
helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp)
{
    helper_stateful_server *srv;
    dlink_node *link;
    double tt;
    storeAppendPrintf(sentry, "program: %s\n",
                      hlp->cmdline->key);
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
    storeAppendPrintf(sentry, "%7s\t%7s\t%7s\t%11s\t%20s\t%s\t%7s\t%7s\t%7s\n",
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
        srv = (helper_stateful_server *)link->data;
        tt = 0.001 * tvSubMsec(srv->dispatch_time,
                               srv->flags.busy ? current_time : srv->answer_time);
        storeAppendPrintf(sentry, "%7d\t%7d\t%7d\t%11d\t%20d\t%c%c%c%c%c\t%7.3f\t%7d\t%s\n",
                          srv->index + 1,
                          srv->rfd,
                          srv->pid,
                          srv->stats.uses,
                          (int) srv->deferred_requests,
                          srv->flags.busy ? 'B' : ' ',
                          srv->flags.closing ? 'C' : ' ',
                          srv->flags.reserved != S_HELPER_FREE ? 'R' : ' ',
                          srv->flags.shutdown ? 'S' : ' ',
                          srv->request ? (srv->request->placeholder ? 'P' : ' ') : ' ',
                                  tt < 0.0 ? 0.0 : tt,
                                  (int) srv->roffset,
                                  srv->request ? log_quote(srv->request->buf) : "(none)");
    }

    storeAppendPrintf(sentry, "\nFlags key:\n\n");
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
#ifdef _SQUID_MSWIN_

    HANDLE hIpc;
    pid_t pid;
    int no;
#endif

    while (link) {
        helper_server *srv;
        srv = (helper_server *)link->data;
        link = link->next;

        if (srv->flags.shutdown) {
            debug(84, 3) ("helperShutdown: %s #%d has already SHUT DOWN.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        hlp->n_active--;
        assert(hlp->n_active >= 0);

        srv->flags.shutdown = 1;	/* request it to shut itself down */

        if (srv->flags.closing) {
            debug(84, 3) ("helperShutdown: %s #%d is CLOSING.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        if (srv->stats.pending) {
            debug(84, 3) ("helperShutdown: %s #%d is BUSY.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        srv->flags.closing = 1;
#ifdef _SQUID_MSWIN_

        hIpc = srv->hIpc;
        pid = srv->pid;
        no = srv->index + 1;
        shutdown(srv->wfd, SD_BOTH);
#endif

        debug(84, 3) ("helperShutdown: %s #%d shutting down.\n",
                      hlp->id_name, srv->index + 1);
        /* the rest of the details is dealt with in the helperServerFree
         * close handler
         */
        comm_close(srv->rfd);
#ifdef _SQUID_MSWIN_

        if (hIpc) {
            if (WaitForSingleObject(hIpc, 5000) != WAIT_OBJECT_0) {
                getCurrentTime();
                debug(84, 1) ("helperShutdown: WARNING: %s #%d (%s,%ld) "
                              "didn't exit in 5 seconds\n",
                              hlp->id_name, no, hlp->cmdline->key, (long int)pid);
            }

            CloseHandle(hIpc);
        }

#endif

    }
}

void
helperStatefulShutdown(statefulhelper * hlp)
{
    dlink_node *link = hlp->servers.head;
    helper_stateful_server *srv;
#ifdef _SQUID_MSWIN_

    HANDLE hIpc;
    pid_t pid;
    int no;
#endif

    while (link) {
        srv = (helper_stateful_server *)link->data;
        link = link->next;

        if (srv->flags.shutdown) {
            debug(84, 3) ("helperStatefulShutdown: %s #%d has already SHUT DOWN.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        hlp->n_active--;
        assert(hlp->n_active >= 0);
        srv->flags.shutdown = 1;	/* request it to shut itself down */

        if (srv->flags.busy) {
            debug(84, 3) ("helperStatefulShutdown: %s #%d is BUSY.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        if (srv->flags.closing) {
            debug(84, 3) ("helperStatefulShutdown: %s #%d is CLOSING.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        if (srv->flags.reserved != S_HELPER_FREE) {
            debug(84, 3) ("helperStatefulShutdown: %s #%d is RESERVED.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        if (srv->deferred_requests) {
            debug(84, 3) ("helperStatefulShutdown: %s #%d has DEFERRED requests.\n",
                          hlp->id_name, srv->index + 1);
            continue;
        }

        srv->flags.closing = 1;
#ifdef _SQUID_MSWIN_

        hIpc = srv->hIpc;
        pid = srv->pid;
        no = srv->index + 1;
        shutdown(srv->wfd, SD_BOTH);
#endif

        debug(84, 3) ("helperStatefulShutdown: %s #%d shutting down.\n",
                      hlp->id_name, srv->index + 1);
        /* the rest of the details is dealt with in the helperStatefulServerFree
         * close handler
         */
        comm_close(srv->rfd);
#ifdef _SQUID_MSWIN_

        if (hIpc) {
            if (WaitForSingleObject(hIpc, 5000) != WAIT_OBJECT_0) {
                getCurrentTime();
                debug(84, 1) ("helperShutdown: WARNING: %s #%d (%s,%ld) "
                              "didn't exit in 5 seconds\n",
                              hlp->id_name, no, hlp->cmdline->key, (long int)pid);
            }

            CloseHandle(hIpc);
        }

#endif

    }
}


helper *
helperCreate(const char *name)
{
    helper *hlp;
    CBDATA_INIT_TYPE(helper);
    hlp = cbdataAlloc(helper);
    hlp->id_name = name;
    return hlp;
}

statefulhelper *
helperStatefulCreate(const char *name)
{
    statefulhelper *hlp;
    CBDATA_INIT_TYPE(statefulhelper);
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
        debug(84, 0) ("WARNING: freeing %s helper with %d requests queued\n",
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
        debug(84, 0) ("WARNING: freeing %s helper with %d requests queued\n",
                      hlp->id_name, hlp->stats.queue_size);

    cbdataFree(hlp);
}


/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

static void
helperServerFree(int fd, void *data)
{
    helper_server *srv = (helper_server *)data;
    helper *hlp = srv->parent;
    helper_request *r;
    int i, concurrency = hlp->concurrency;

    if (!concurrency)
        concurrency = 1;

    assert(srv->rfd == fd);

    if (srv->rbuf) {
        memFreeBuf(srv->rbuf_sz, srv->rbuf);
        srv->rbuf = NULL;
    }

    srv->wqueue->clean();
    delete srv->wqueue;

    if (srv->writebuf) {
        srv->writebuf->clean();
        delete srv->writebuf;
        srv->writebuf = NULL;
    }

    for (i = 0; i < concurrency; i++) {
        if ((r = srv->requests[i])) {
            void *cbdata;

            if (cbdataReferenceValidDone(r->data, &cbdata))
                r->callback(cbdata, NULL);

            helperRequestFree(r);

            srv->requests[i] = NULL;
        }
    }

    safe_free(srv->requests);

    if (srv->wfd != srv->rfd && srv->wfd != -1)
        comm_close(srv->wfd);

    dlinkDelete(&srv->link, &hlp->servers);

    hlp->n_running--;

    assert(hlp->n_running >= 0);

    if (!srv->flags.shutdown) {
        hlp->n_active--;
        assert(hlp->n_active >= 0);
        debug(84, 0) ("WARNING: %s #%d (FD %d) exited\n",
                      hlp->id_name, srv->index + 1, fd);

        if (hlp->n_active < hlp->n_to_start / 2) {
            debug(80, 0) ("Too few %s processes are running\n", hlp->id_name);

            if (hlp->last_restart > squid_curtime - 30)
                fatalf("The %s helpers are crashing too rapidly, need help!\n", hlp->id_name);

            debug(80, 0) ("Starting new helpers\n");

            helperOpenServers(hlp);
        }
    }

    cbdataReferenceDone(srv->parent);
    cbdataFree(srv);
}

static void
helperStatefulServerFree(int fd, void *data)
{
    helper_stateful_server *srv = (helper_stateful_server *)data;
    statefulhelper *hlp = srv->parent;
    helper_stateful_request *r;
    assert(srv->rfd == fd);

    if (srv->rbuf) {
        memFreeBuf(srv->rbuf_sz, srv->rbuf);
        srv->rbuf = NULL;
    }

#if 0
    srv->wqueue->clean();

    delete srv->wqueue;

#endif

    if ((r = srv->request)) {
        void *cbdata;

        if (cbdataReferenceValidDone(r->data, &cbdata))
            r->callback(cbdata, srv, NULL);

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
        hlp->n_active--;
        assert( hlp->n_active >= 0);
        debug(84, 0) ("WARNING: %s #%d (FD %d) exited\n",
                      hlp->id_name, srv->index + 1, fd);

        if (hlp->n_active <= hlp->n_to_start / 2) {
            debug(80, 0) ("Too few %s processes are running\n", hlp->id_name);

            if (hlp->last_restart > squid_curtime - 30)
                fatalf("The %s helpers are crashing too rapidly, need help!\n", hlp->id_name);

            debug(80, 0) ("Starting new helpers\n");

            helperStatefulOpenServers(hlp);
        }
    }

    if (srv->data != NULL)
        hlp->datapool->free(srv->data);

    cbdataReferenceDone(srv->parent);

    cbdataFree(srv);
}


static void
helperHandleRead(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    char *t = NULL;
    helper_server *srv = (helper_server *)data;
    helper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataReferenceValid(data));

    /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us */

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    debug(84, 5) ("helperHandleRead: %d bytes from %s #%d.\n",
                  (int)len, hlp->id_name, srv->index + 1);

    if (flag != COMM_OK || len <= 0) {
        if (len < 0)
            debug(84, 1) ("helperHandleRead: FD %d read: %s\n", fd, xstrerror());

        comm_close(fd);

        return;
    }

    srv->roffset += len;
    srv->rbuf[srv->roffset] = '\0';
    debug(84, 9) ("helperHandleRead: '%s'\n", srv->rbuf);

    if (!srv->stats.pending) {
        /* someone spoke without being spoken to */
        debug(84, 1) ("helperHandleRead: unexpected read from %s #%d, %d bytes '%s'\n",
                      hlp->id_name, srv->index + 1, (int)len, srv->rbuf);
        srv->roffset = 0;
        srv->rbuf[0] = '\0';
    }

    while ((t = strchr(srv->rbuf, '\n'))) {
        /* end of reply found */
        helper_request *r;
        char *msg = srv->rbuf;
        int i = 0;
        debug(84, 3) ("helperHandleRead: end of reply found\n");

        if (t > srv->rbuf && t[-1] == '\r')
            t[-1] = '\0';

        *t++ = '\0';

        if (hlp->concurrency) {
            i = strtol(msg, &msg, 10);

            while (*msg && isspace(*msg))
                msg++;
        }

        r = srv->requests[i];

        if (r) {
            HLPCB *callback = r->callback;
            void *cbdata;

            srv->requests[i] = NULL;

            r->callback = NULL;

            if (cbdataReferenceValidDone(r->data, &cbdata))
                callback(cbdata, msg);

            srv->stats.pending--;

            hlp->stats.replies++;

            srv->answer_time = current_time;

            srv->dispatch_time = r->dispatch_time;

            hlp->stats.avg_svc_time =
                intAverage(hlp->stats.avg_svc_time,
                           tvSubMsec(r->dispatch_time, current_time),
                           hlp->stats.replies, REDIRECT_AV_FACTOR);

            helperRequestFree(r);
        } else {
            debug(84, 1) ("helperHandleRead: unexpected reply on channel %d from %s #%d '%s'\n",
                          i, hlp->id_name, srv->index + 1, srv->rbuf);
        }

        srv->roffset -= (t - srv->rbuf);
        memmove(srv->rbuf, t, srv->roffset + 1);

        if (srv->flags.shutdown) {
            int wfd = srv->wfd;
            srv->wfd = -1;
            srv->flags.closing=1;
            comm_close(wfd);
        } else
            helperKickQueue(hlp);
    }

    comm_read(fd, srv->rbuf + srv->roffset, srv->rbuf_sz - srv->roffset - 1, helperHandleRead, srv);
}

static void
helperStatefulHandleRead(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    char *t = NULL;
    helper_stateful_server *srv = (helper_stateful_server *)data;
    helper_stateful_request *r;
    statefulhelper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataReferenceValid(data));

    /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us */

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    debug(84, 5) ("helperStatefulHandleRead: %d bytes from %s #%d.\n",
                  (int)len, hlp->id_name, srv->index + 1);

    if (flag != COMM_OK || len <= 0) {
        if (len < 0)
            debug(84, 1) ("helperStatefulHandleRead: FD %d read: %s\n", fd, xstrerror());

        comm_close(fd);

        return;
    }

    srv->roffset += len;
    srv->rbuf[srv->roffset] = '\0';
    r = srv->request;

    if (r == NULL) {
        /* someone spoke without being spoken to */
        debug(84, 1) ("helperStatefulHandleRead: unexpected read from %s #%d, %d bytes '%s'\n",
                      hlp->id_name, srv->index + 1, (int)len, srv->rbuf);
        srv->roffset = 0;
    }

    if ((t = strchr(srv->rbuf, '\n'))) {
        /* end of reply found */
        debug(84, 3) ("helperStatefulHandleRead: end of reply found\n");

        if (t > srv->rbuf && t[-1] == '\r')
            t[-1] = '\0';

        *t = '\0';

        if (cbdataReferenceValid(r->data)) {
            switch ((r->callback(r->data, srv, srv->rbuf))) {	/*if non-zero reserve helper */

            case S_HELPER_UNKNOWN:
                    fatal("helperStatefulHandleRead: either a non-state aware callback was give to the stateful helper routines, or an uninitialised callback response was recieved.\n");
                break;

            case S_HELPER_RELEASE:	/* helper finished with */

                if (!srv->deferred_requests && !srv->queue.head) {
                    srv->flags.reserved = S_HELPER_FREE;

                    if ((srv->parent->OnEmptyQueue != NULL) && (srv->data))
                        srv->parent->OnEmptyQueue(srv->data);

                    debug(84, 5) ("StatefulHandleRead: releasing %s #%d\n", hlp->id_name, srv->index + 1);
                } else {
                    srv->flags.reserved = S_HELPER_DEFERRED;
                    debug(84, 5) ("StatefulHandleRead: outstanding deferred requests on %s #%d. reserving for deferred requests.\n", hlp->id_name, srv->index + 1);
                }

                break;

            case S_HELPER_RESERVE:	/* 'pin' this helper for the caller */

                if (!srv->queue.head) {
                    assert(srv->deferred_requests == 0);
                    srv->flags.reserved = S_HELPER_RESERVED;
                    debug(84, 5) ("StatefulHandleRead: reserving %s #%d\n", hlp->id_name, srv->index + 1);
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
                debug(84, 5) ("StatefulHandleRead: reserving %s #%d for deferred requests.\n", hlp->id_name, srv->index + 1);
                break;

            default:
                fatal("helperStatefulHandleRead: unknown stateful helper callback result.\n");
            }

        } else {
            debug(84, 1) ("StatefulHandleRead: no callback data registered\n");
        }

        srv->flags.busy = 0;
        srv->roffset = 0;
        helperStatefulRequestFree(r);
        srv->request = NULL;
        hlp->stats.replies++;
        srv->answer_time = current_time;
        hlp->stats.avg_svc_time =
            intAverage(hlp->stats.avg_svc_time,
                       tvSubMsec(srv->dispatch_time, current_time),
                       hlp->stats.replies, REDIRECT_AV_FACTOR);

        if (srv->flags.shutdown
                && srv->flags.reserved == S_HELPER_FREE
                && !srv->deferred_requests) {
            int wfd = srv->wfd;
            srv->wfd = -1;
            srv->flags.closing=1;
            comm_close(wfd);
        } else {
            if (srv->queue.head)
                helperStatefulServerKickQueue(srv);
            else
                helperStatefulKickQueue(hlp);
        }
    }

    comm_read(srv->rfd, srv->rbuf + srv->roffset, srv->rbuf_sz - srv->roffset - 1,
              helperStatefulHandleRead, srv);
}

static void
Enqueue(helper * hlp, helper_request * r)
{
    dlink_node *link = (dlink_node *)memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;

    if (hlp->stats.queue_size < hlp->n_running)
        return;

    if (squid_curtime - hlp->last_queue_warn < 600)
        return;

    if (shutting_down || reconfiguring)
        return;

    hlp->last_queue_warn = squid_curtime;

    debug(84, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);

    debug(84, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);

    if (hlp->stats.queue_size > hlp->n_running * 2)
        fatalf("Too many queued %s requests", hlp->id_name);

    debug(84, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);
}

static void
StatefulEnqueue(statefulhelper * hlp, helper_stateful_request * r)
{
    dlink_node *link = (dlink_node *)memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;

    if (hlp->stats.queue_size < hlp->n_running)
        return;

    if (hlp->stats.queue_size > hlp->n_running * 2)
        fatalf("Too many queued %s requests", hlp->id_name);

    if (squid_curtime - hlp->last_queue_warn < 600)
        return;

    if (shutting_down || reconfiguring)
        return;

    hlp->last_queue_warn = squid_curtime;

    debug(84, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);

    debug(84, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);

    debug(84, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);
}

static void
StatefulServerEnqueue(helper_stateful_server * srv, helper_stateful_request * r)
{
    dlink_node *link = (dlink_node *)memAllocate(MEM_DLINK_NODE);
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
     * debug(84, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);
     * debug(84, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);
     * if (hlp->stats.queue_size > hlp->n_running * 2)
     * fatalf("Too many queued %s requests", hlp->id_name);
     * debug(84, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);  */
}


static helper_request *
Dequeue(helper * hlp)
{
    dlink_node *link;
    helper_request *r = NULL;

    if ((link = hlp->queue.head)) {
        r = (helper_request *)link->data;
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
        r = (helper_stateful_request *)link->data;
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
        r = (helper_stateful_request *)link->data;
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
    helper_server *srv;
    helper_server *selected = NULL;

    if (hlp->n_running == 0)
        return NULL;

    /* Find "least" loaded helper (approx) */
    for (n = hlp->servers.head; n != NULL; n = n->next) {
        srv = (helper_server *)n->data;

        if (selected && selected->stats.pending <= srv->stats.pending)
            continue;

        if (srv->flags.shutdown)
            continue;

        if (!srv->stats.pending)
            return srv;

        if (selected) {
            selected = srv;
            break;
        }

        selected = srv;
    }

    /* Check for overload */
    if (!selected)
        return NULL;

    if (selected->stats.pending >= (hlp->concurrency ? hlp->concurrency : 1))
        return NULL;

    return selected;
}

static helper_stateful_server *
StatefulGetFirstAvailable(statefulhelper * hlp)
{
    dlink_node *n;
    helper_stateful_server *srv = NULL;
    debug(84, 5) ("StatefulGetFirstAvailable: Running servers %d.\n", hlp->n_running);

    if (hlp->n_running == 0)
        return NULL;

    for (n = hlp->servers.head; n != NULL; n = n->next) {
        srv = (helper_stateful_server *)n->data;

        if (srv->flags.busy)
            continue;

        if (srv->flags.reserved == S_HELPER_RESERVED)
            continue;

        if (srv->flags.shutdown)
            continue;

        if ((hlp->IsAvailable != NULL) && (srv->data != NULL) && !(hlp->IsAvailable(srv->data)))
            continue;

        return srv;
    }

    debug(84, 5) ("StatefulGetFirstAvailable: None available.\n");
    return NULL;
}


static void
helperDispatchWriteDone(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    helper_server *srv = (helper_server *)data;

    srv->writebuf->clean();
    delete srv->writebuf;
    srv->writebuf = NULL;
    srv->flags.writing = 0;

    if (flag != COMM_OK) {
        /* Helper server has crashed */
        debug(84, 0) ("helperDispatch: Helper %s #%d has crashed\n",
                      srv->parent->id_name, srv->index + 1);
        return;
    }

    if (!srv->wqueue->isNull()) {
        srv->writebuf = srv->wqueue;
        srv->wqueue = new MemBuf;
        srv->flags.writing = 1;
        comm_write(srv->wfd,
                   srv->writebuf->content(),
                   srv->writebuf->contentSize(),
                   helperDispatchWriteDone,	/* Handler */
                   srv, NULL);			/* Handler-data, freefunc */
    }
}

static void
helperDispatch(helper_server * srv, helper_request * r)
{
    helper *hlp = srv->parent;
    helper_request **ptr = NULL;
    unsigned int slot;

    if (!cbdataReferenceValid(r->data)) {
        debug(84, 1) ("helperDispatch: invalid callback data\n");
        helperRequestFree(r);
        return;
    }

    for (slot = 0; slot < (hlp->concurrency ? hlp->concurrency : 1); slot++) {
        if (!srv->requests[slot]) {
            ptr = &srv->requests[slot];
            break;
        }
    }

    assert(ptr);
    *ptr = r;
    srv->stats.pending += 1;
    r->dispatch_time = current_time;

    if (srv->wqueue->isNull())
        srv->wqueue->init();

    if (hlp->concurrency)
        srv->wqueue->Printf("%d %s", slot, r->buf);
    else
        srv->wqueue->append(r->buf, strlen(r->buf));

    if (!srv->flags.writing) {
        assert(NULL == srv->writebuf);
        srv->writebuf = srv->wqueue;
        srv->wqueue = new MemBuf;
        srv->flags.writing = 1;
        comm_write(srv->wfd,
                   srv->writebuf->content(),
                   srv->writebuf->contentSize(),
                   helperDispatchWriteDone,	/* Handler */
                   srv, NULL);			/* Handler-data, free func */
    }

    debug(84, 5) ("helperDispatch: Request sent to %s #%d, %d bytes\n",
                  hlp->id_name, srv->index + 1, (int) strlen(r->buf));
    srv->stats.uses++;
    hlp->stats.requests++;
}

static void
helperStatefulDispatchWriteDone(int fd, char *buf, size_t len, comm_err_t flag,
                                int xerrno, void *data)
{
    /* nothing! */
}


static void
helperStatefulDispatch(helper_stateful_server * srv, helper_stateful_request * r)
{
    statefulhelper *hlp = srv->parent;

    if (!cbdataReferenceValid(r->data)) {
        debug(84, 1) ("helperStatefulDispatch: invalid callback data\n");
        helperStatefulRequestFree(r);
        return;
    }

    debug(84, 9) ("helperStatefulDispatch busying helper %s #%d\n", hlp->id_name, srv->index + 1);

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
                int wfd = srv->wfd;
                srv->wfd = -1;
                comm_close(wfd);
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
               helperStatefulDispatchWriteDone,	/* Handler */
               hlp, NULL);				/* Handler-data, free func */
    debug(84, 5) ("helperStatefulDispatch: Request sent to %s #%d, %d bytes\n",
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
    cbdataReferenceDone(r->data);
    xfree(r->buf);
    delete r;
}

static void
helperStatefulRequestFree(helper_stateful_request * r)
{
    cbdataReferenceDone(r->data);
    xfree(r->buf);
    delete r;
}
