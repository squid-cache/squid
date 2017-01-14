/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#include "squid.h"
#include "base/AsyncCbdataCalls.h"
#include "base/Packable.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "fd.h"
#include "fde.h"
#include "format/Quoting.h"
#include "helper.h"
#include "helper/Reply.h"
#include "helper/Request.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "SquidIpc.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "Store.h"
#include "wordlist.h"

// helper_stateful_server::data uses explicit alloc()/freeOne() */
#include "mem/Pool.h"

#define HELPER_MAX_ARGS 64

/// The maximum allowed request retries.
#define MAX_RETRIES 2

/// Helpers input buffer size.
const size_t ReadBufSize(32*1024);

static IOCB helperHandleRead;
static IOCB helperStatefulHandleRead;
static void helperServerFree(helper_server *srv);
static void helperStatefulServerFree(helper_stateful_server *srv);
static void Enqueue(helper * hlp, Helper::Xaction *);
static helper_server *GetFirstAvailable(const helper * hlp);
static helper_stateful_server *StatefulGetFirstAvailable(const statefulhelper * hlp);
static void helperDispatch(helper_server * srv, Helper::Xaction * r);
static void helperStatefulDispatch(helper_stateful_server * srv, Helper::Xaction * r);
static void helperKickQueue(helper * hlp);
static void helperStatefulKickQueue(statefulhelper * hlp);
static void helperStatefulServerDone(helper_stateful_server * srv);
static void StatefulEnqueue(statefulhelper * hlp, Helper::Xaction * r);

CBDATA_CLASS_INIT(helper);
CBDATA_CLASS_INIT(helper_server);
CBDATA_CLASS_INIT(statefulhelper);
CBDATA_CLASS_INIT(helper_stateful_server);

InstanceIdDefinitions(HelperServerBase, "Hlpr");

void
HelperServerBase::initStats()
{
    stats.uses=0;
    stats.replies=0;
    stats.pending=0;
    stats.releases=0;
    stats.timedout = 0;
}

void
HelperServerBase::closePipesSafely(const char *id_name)
{
#if _SQUID_WINDOWS_
    shutdown(writePipe->fd, SD_BOTH);
#endif

    flags.closing = true;
    if (readPipe->fd == writePipe->fd)
        readPipe->fd = -1;
    else
        readPipe->close();
    writePipe->close();

#if _SQUID_WINDOWS_
    if (hIpc) {
        if (WaitForSingleObject(hIpc, 5000) != WAIT_OBJECT_0) {
            getCurrentTime();
            debugs(84, DBG_IMPORTANT, "WARNING: " << id_name <<
                   " #" << index << " (PID " << (long int)pid << ") didn't exit in 5 seconds");
        }
        CloseHandle(hIpc);
    }
#endif
}

void
HelperServerBase::closeWritePipeSafely(const char *id_name)
{
#if _SQUID_WINDOWS_
    shutdown(writePipe->fd, (readPipe->fd == writePipe->fd ? SD_BOTH : SD_SEND));
#endif

    flags.closing = true;
    if (readPipe->fd == writePipe->fd)
        readPipe->fd = -1;
    writePipe->close();

#if _SQUID_WINDOWS_
    if (hIpc) {
        if (WaitForSingleObject(hIpc, 5000) != WAIT_OBJECT_0) {
            getCurrentTime();
            debugs(84, DBG_IMPORTANT, "WARNING: " << id_name <<
                   " #" << index << " (PID " << (long int)pid << ") didn't exit in 5 seconds");
        }
        CloseHandle(hIpc);
    }
#endif
}

void
helperOpenServers(helper * hlp)
{
    char *s;
    char *progname;
    char *shortname;
    char *procname;
    const char *args[HELPER_MAX_ARGS+1]; // save space for a NULL terminator
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

    /* figure out how many new child are actually needed. */
    int need_new = hlp->childs.needNew();

    debugs(84, DBG_IMPORTANT, "helperOpenServers: Starting " << need_new << "/" << hlp->childs.n_max << " '" << shortname << "' processes");

    if (need_new < 1) {
        debugs(84, DBG_IMPORTANT, "helperOpenServers: No '" << shortname << "' processes needed.");
    }

    procname = (char *)xmalloc(strlen(shortname) + 3);

    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);

    args[nargs] = procname;
    ++nargs;

    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next) {
        args[nargs] = w->key;
        ++nargs;
    }

    args[nargs] = NULL;
    ++nargs;

    assert(nargs <= HELPER_MAX_ARGS);

    for (k = 0; k < need_new; ++k) {
        getCurrentTime();
        rfd = wfd = -1;
        pid = ipcCreate(hlp->ipc_type,
                        progname,
                        args,
                        shortname,
                        hlp->addr,
                        &rfd,
                        &wfd,
                        &hIpc);

        if (pid < 0) {
            debugs(84, DBG_IMPORTANT, "WARNING: Cannot run '" << progname << "' process.");
            continue;
        }

        ++ hlp->childs.n_running;
        ++ hlp->childs.n_active;
        srv = new helper_server;
        srv->hIpc = hIpc;
        srv->pid = pid;
        srv->initStats();
        srv->addr = hlp->addr;
        srv->readPipe = new Comm::Connection;
        srv->readPipe->fd = rfd;
        srv->writePipe = new Comm::Connection;
        srv->writePipe->fd = wfd;
        srv->rbuf = (char *)memAllocBuf(ReadBufSize, &srv->rbuf_sz);
        srv->wqueue = new MemBuf;
        srv->roffset = 0;
        srv->nextRequestId = 0;
        srv->replyXaction = NULL;
        srv->ignoreToEom = false;
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

        AsyncCall::Pointer closeCall = asyncCall(5,4, "helperServerFree", cbdataDialer(helperServerFree, srv));
        comm_add_close_handler(rfd, closeCall);

        if (hlp->timeout && hlp->childs.concurrency) {
            AsyncCall::Pointer timeoutCall = commCbCall(84, 4, "helper_server::requestTimeout",
                                             CommTimeoutCbPtrFun(helper_server::requestTimeout, srv));
            commSetConnTimeout(srv->readPipe, hlp->timeout, timeoutCall);
        }

        AsyncCall::Pointer call = commCbCall(5,4, "helperHandleRead",
                                             CommIoCbPtrFun(helperHandleRead, srv));
        comm_read(srv->readPipe, srv->rbuf, srv->rbuf_sz - 1, call);
    }

    hlp->last_restart = squid_curtime;
    safe_free(shortname);
    safe_free(procname);
    helperKickQueue(hlp);
}

/**
 * DPW 2007-05-08
 *
 * helperStatefulOpenServers: create the stateful child helper processes
 */
void
helperStatefulOpenServers(statefulhelper * hlp)
{
    char *shortname;
    const char *args[HELPER_MAX_ARGS+1]; // save space for a NULL terminator
    char fd_note_buf[FD_DESC_SZ];
    int nargs = 0;

    if (hlp->cmdline == NULL)
        return;

    if (hlp->childs.concurrency)
        debugs(84, DBG_CRITICAL, "ERROR: concurrency= is not yet supported for stateful helpers ('" << hlp->cmdline << "')");

    char *progname = hlp->cmdline->key;

    char *s;
    if ((s = strrchr(progname, '/')))
        shortname = xstrdup(s + 1);
    else
        shortname = xstrdup(progname);

    /* figure out haw mant new helpers are needed. */
    int need_new = hlp->childs.needNew();

    debugs(84, DBG_IMPORTANT, "helperOpenServers: Starting " << need_new << "/" << hlp->childs.n_max << " '" << shortname << "' processes");

    if (need_new < 1) {
        debugs(84, DBG_IMPORTANT, "helperStatefulOpenServers: No '" << shortname << "' processes needed.");
    }

    char *procname = (char *)xmalloc(strlen(shortname) + 3);

    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);

    args[nargs] = procname;
    ++nargs;

    for (wordlist *w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next) {
        args[nargs] = w->key;
        ++nargs;
    }

    args[nargs] = NULL;
    ++nargs;

    assert(nargs <= HELPER_MAX_ARGS);

    for (int k = 0; k < need_new; ++k) {
        getCurrentTime();
        int rfd = -1;
        int wfd = -1;
        void * hIpc;
        pid_t pid = ipcCreate(hlp->ipc_type,
                              progname,
                              args,
                              shortname,
                              hlp->addr,
                              &rfd,
                              &wfd,
                              &hIpc);

        if (pid < 0) {
            debugs(84, DBG_IMPORTANT, "WARNING: Cannot run '" << progname << "' process.");
            continue;
        }

        ++ hlp->childs.n_running;
        ++ hlp->childs.n_active;
        helper_stateful_server *srv = new helper_stateful_server;
        srv->hIpc = hIpc;
        srv->pid = pid;
        srv->flags.reserved = false;
        srv->initStats();
        srv->addr = hlp->addr;
        srv->readPipe = new Comm::Connection;
        srv->readPipe->fd = rfd;
        srv->writePipe = new Comm::Connection;
        srv->writePipe->fd = wfd;
        srv->rbuf = (char *)memAllocBuf(ReadBufSize, &srv->rbuf_sz);
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

        AsyncCall::Pointer closeCall = asyncCall(5,4, "helperStatefulServerFree", cbdataDialer(helperStatefulServerFree, srv));
        comm_add_close_handler(rfd, closeCall);

        AsyncCall::Pointer call = commCbCall(5,4, "helperStatefulHandleRead",
                                             CommIoCbPtrFun(helperStatefulHandleRead, srv));
        comm_read(srv->readPipe, srv->rbuf, srv->rbuf_sz - 1, call);
    }

    hlp->last_restart = squid_curtime;
    safe_free(shortname);
    safe_free(procname);
    helperStatefulKickQueue(hlp);
}

void
helper::submitRequest(Helper::Xaction *r)
{
    helper_server *srv;

    if ((srv = GetFirstAvailable(this)))
        helperDispatch(srv, r);
    else
        Enqueue(this, r);

    syncQueueStats();
}

/// handles helperSubmit() and helperStatefulSubmit() failures
static void
SubmissionFailure(helper *hlp, HLPCB *callback, void *data)
{
    auto result = Helper::Error;
    if (!hlp) {
        debugs(84, 3, "no helper");
        result = Helper::Unknown;
    }
    // else pretend the helper has responded with ERR

    callback(data, Helper::Reply(result));
}

void
helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data)
{
    if (!hlp || !hlp->trySubmit(buf, callback, data))
        SubmissionFailure(hlp, callback, data);
}

/// whether queuing an additional request would overload the helper
bool
helper::queueFull() const {
    return stats.queue_size >= static_cast<int>(childs.queue_size);
}

bool
helper::overloaded() const {
    return stats.queue_size > static_cast<int>(childs.queue_size);
}

/// synchronizes queue-dependent measurements with the current queue state
void
helper::syncQueueStats()
{
    if (overloaded()) {
        if (overloadStart) {
            debugs(84, 5, id_name << " still overloaded; dropped " << droppedRequests);
        } else {
            overloadStart = squid_curtime;
            debugs(84, 3, id_name << " became overloaded");
        }
    } else {
        if (overloadStart) {
            debugs(84, 5, id_name << " is no longer overloaded");
            if (droppedRequests) {
                debugs(84, DBG_IMPORTANT, "helper " << id_name <<
                       " is no longer overloaded after dropping " << droppedRequests <<
                       " requests in " << (squid_curtime - overloadStart) << " seconds");
                droppedRequests = 0;
            }
            overloadStart = 0;
        }
    }
}

/// prepares the helper for request submission
/// returns true if and only if the submission should proceed
/// may kill Squid if the helper remains overloaded for too long
bool
helper::prepSubmit()
{
    // re-sync for the configuration may have changed since the last submission
    syncQueueStats();

    // Nothing special to do if the new request does not overload (i.e., the
    // queue is not even full yet) or only _starts_ overloading this helper
    // (i.e., the queue is currently at its limit).
    if (!overloaded())
        return true;

    if (squid_curtime - overloadStart <= 180)
        return true; // also OK: overload has not persisted long enough to panic

    if (childs.onPersistentOverload == Helper::ChildConfig::actDie)
        fatalf("Too many queued %s requests; see on-persistent-overload.", id_name);

    if (!droppedRequests) {
        debugs(84, DBG_IMPORTANT, "WARNING: dropping requests to overloaded " <<
               id_name << " helper configured with on-persistent-overload=err");
    }
    ++droppedRequests;
    debugs(84, 3, "failed to send " << droppedRequests << " helper requests to " << id_name);
    return false;
}

bool
helper::trySubmit(const char *buf, HLPCB * callback, void *data)
{
    if (!prepSubmit())
        return false; // request was dropped

    submit(buf, callback, data); // will send or queue
    return true; // request submitted or queued
}

/// dispatches or enqueues a helper requests; does not enforce queue limits
void
helper::submit(const char *buf, HLPCB * callback, void *data)
{
    Helper::Xaction *r = new Helper::Xaction(callback, data, buf);
    submitRequest(r);
    debugs(84, DBG_DATA, Raw("buf", buf, strlen(buf)));
}

/// lastserver = "server last used as part of a reserved request sequence"
void
helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPCB * callback, void *data, helper_stateful_server * lastserver)
{
    if (!hlp || !hlp->trySubmit(buf, callback, data, lastserver))
        SubmissionFailure(hlp, callback, data);
}

/// If possible, submit request. Otherwise, either kill Squid or return false.
bool
statefulhelper::trySubmit(const char *buf, HLPCB * callback, void *data, helper_stateful_server *lastserver)
{
    if (!prepSubmit())
        return false; // request was dropped

    submit(buf, callback, data, lastserver); // will send or queue
    return true; // request submitted or queued
}

void statefulhelper::submit(const char *buf, HLPCB * callback, void *data, helper_stateful_server * lastserver)
{
    Helper::Xaction *r = new Helper::Xaction(callback, data, buf);

    if ((buf != NULL) && lastserver) {
        debugs(84, 5, "StatefulSubmit with lastserver " << lastserver);
        assert(lastserver->flags.reserved);
        assert(!lastserver->requests.size());

        debugs(84, 5, "StatefulSubmit dispatching");
        helperStatefulDispatch(lastserver, r);
    } else {
        helper_stateful_server *srv;
        if ((srv = StatefulGetFirstAvailable(this))) {
            helperStatefulDispatch(srv, r);
        } else
            StatefulEnqueue(this, r);
    }

    debugs(84, DBG_DATA, "placeholder: '" << r->request.placeholder <<
           "', " << Raw("buf", buf, (!buf?0:strlen(buf))));

    syncQueueStats();
}

/**
 * DPW 2007-05-08
 *
 * helperStatefulReleaseServer tells the helper that whoever was
 * using it no longer needs its services.
 */
void
helperStatefulReleaseServer(helper_stateful_server * srv)
{
    debugs(84, 3, HERE << "srv-" << srv->index << " flags.reserved = " << srv->flags.reserved);
    if (!srv->flags.reserved)
        return;

    ++ srv->stats.releases;

    srv->flags.reserved = false;

    helperStatefulServerDone(srv);
}

/** return a pointer to the stateful routines data area */
void *
helperStatefulServerGetData(helper_stateful_server * srv)
{
    return srv->data;
}

void
helper::packStatsInto(Packable *p, const char *label) const
{
    if (label)
        p->appendf("%s:\n", label);

    p->appendf("  program: %s\n", cmdline->key);
    p->appendf("  number active: %d of %d (%d shutting down)\n", childs.n_active, childs.n_max, (childs.n_running - childs.n_active));
    p->appendf("  requests sent: %d\n", stats.requests);
    p->appendf("  replies received: %d\n", stats.replies);
    p->appendf("  requests timedout: %d\n", stats.timedout);
    p->appendf("  queue length: %d\n", stats.queue_size);
    p->appendf("  avg service time: %d msec\n", stats.avg_svc_time);
    p->append("\n",1);
    p->appendf("%7s\t%7s\t%7s\t%11s\t%11s\t%11s\t%6s\t%7s\t%7s\t%7s\n",
               "ID #",
               "FD",
               "PID",
               "# Requests",
               "# Replies",
               "# Timed-out",
               "Flags",
               "Time",
               "Offset",
               "Request");

    for (dlink_node *link = servers.head; link; link = link->next) {
        HelperServerBase *srv = static_cast<HelperServerBase *>(link->data);
        assert(srv);
        Helper::Xaction *xaction = srv->requests.empty() ? NULL : srv->requests.front();
        double tt = 0.001 * (xaction ? tvSubMsec(xaction->request.dispatch_time, current_time) : tvSubMsec(srv->dispatch_time, srv->answer_time));
        p->appendf("%7u\t%7d\t%7d\t%11" PRIu64 "\t%11" PRIu64 "\t%11" PRIu64 "\t%c%c%c%c%c%c\t%7.3f\t%7d\t%s\n",
                   srv->index.value,
                   srv->readPipe->fd,
                   srv->pid,
                   srv->stats.uses,
                   srv->stats.replies,
                   srv->stats.timedout,
                   srv->stats.pending ? 'B' : ' ',
                   srv->flags.writing ? 'W' : ' ',
                   srv->flags.closing ? 'C' : ' ',
                   srv->flags.reserved ? 'R' : ' ',
                   srv->flags.shutdown ? 'S' : ' ',
                   xaction && xaction->request.placeholder ? 'P' : ' ',
                   tt < 0.0 ? 0.0 : tt,
                   (int) srv->roffset,
                   xaction ? Format::QuoteMimeBlob(xaction->request.buf) : "(none)");
    }

    p->append("\nFlags key:\n"
              "   B\tBUSY\n"
              "   W\tWRITING\n"
              "   C\tCLOSING\n"
              "   R\tRESERVED\n"
              "   S\tSHUTDOWN PENDING\n"
              "   P\tPLACEHOLDER\n", 101);
}

bool
helper::willOverload() const {
    return queueFull() && !(childs.needNew() || GetFirstAvailable(this));
}

void
helperShutdown(helper * hlp)
{
    dlink_node *link = hlp->servers.head;

    while (link) {
        helper_server *srv;
        srv = (helper_server *)link->data;
        link = link->next;

        if (srv->flags.shutdown) {
            debugs(84, 3, "helperShutdown: " << hlp->id_name << " #" << srv->index << " has already SHUT DOWN.");
            continue;
        }

        assert(hlp->childs.n_active > 0);
        -- hlp->childs.n_active;
        srv->flags.shutdown = true; /* request it to shut itself down */

        if (srv->flags.closing) {
            debugs(84, 3, "helperShutdown: " << hlp->id_name << " #" << srv->index << " is CLOSING.");
            continue;
        }

        if (srv->stats.pending) {
            debugs(84, 3, "helperShutdown: " << hlp->id_name << " #" << srv->index << " is BUSY.");
            continue;
        }

        debugs(84, 3, "helperShutdown: " << hlp->id_name << " #" << srv->index << " shutting down.");
        /* the rest of the details is dealt with in the helperServerFree
         * close handler
         */
        srv->closePipesSafely(hlp->id_name);
    }
}

void
helperStatefulShutdown(statefulhelper * hlp)
{
    dlink_node *link = hlp->servers.head;
    helper_stateful_server *srv;

    while (link) {
        srv = (helper_stateful_server *)link->data;
        link = link->next;

        if (srv->flags.shutdown) {
            debugs(84, 3, "helperStatefulShutdown: " << hlp->id_name << " #" << srv->index << " has already SHUT DOWN.");
            continue;
        }

        assert(hlp->childs.n_active > 0);
        -- hlp->childs.n_active;
        srv->flags.shutdown = true; /* request it to shut itself down */

        if (srv->stats.pending) {
            debugs(84, 3, "helperStatefulShutdown: " << hlp->id_name << " #" << srv->index << " is BUSY.");
            continue;
        }

        if (srv->flags.closing) {
            debugs(84, 3, "helperStatefulShutdown: " << hlp->id_name << " #" << srv->index << " is CLOSING.");
            continue;
        }

        if (srv->flags.reserved) {
            if (shutting_down) {
                debugs(84, 3, "helperStatefulShutdown: " << hlp->id_name << " #" << srv->index << " is RESERVED. Closing anyway.");
            } else {
                debugs(84, 3, "helperStatefulShutdown: " << hlp->id_name << " #" << srv->index << " is RESERVED. Not Shutting Down Yet.");
                continue;
            }
        }

        debugs(84, 3, "helperStatefulShutdown: " << hlp->id_name << " #" << srv->index << " shutting down.");

        /* the rest of the details is dealt with in the helperStatefulServerFree
         * close handler
         */
        srv->closePipesSafely(hlp->id_name);
    }
}

helper::~helper()
{
    /* note, don't free id_name, it probably points to static memory */

    // TODO: if the queue is not empty it will leak Helper::Request's
    if (!queue.empty())
        debugs(84, DBG_CRITICAL, "WARNING: freeing " << id_name << " helper with " << stats.queue_size << " requests queued");
}

/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

static void
helperServerFree(helper_server *srv)
{
    helper *hlp = srv->parent;
    int concurrency = hlp->childs.concurrency;

    if (!concurrency)
        concurrency = 1;

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

    if (Comm::IsConnOpen(srv->writePipe))
        srv->closeWritePipeSafely(hlp->id_name);

    dlinkDelete(&srv->link, &hlp->servers);

    assert(hlp->childs.n_running > 0);
    -- hlp->childs.n_running;

    if (!srv->flags.shutdown) {
        assert(hlp->childs.n_active > 0);
        -- hlp->childs.n_active;
        debugs(84, DBG_CRITICAL, "WARNING: " << hlp->id_name << " #" << srv->index << " exited");

        if (hlp->childs.needNew() > 0) {
            debugs(80, DBG_IMPORTANT, "Too few " << hlp->id_name << " processes are running (need " << hlp->childs.needNew() << "/" << hlp->childs.n_max << ")");

            if (hlp->childs.n_active < hlp->childs.n_startup && hlp->last_restart > squid_curtime - 30) {
                if (srv->stats.replies < 1)
                    fatalf("The %s helpers are crashing too rapidly, need help!\n", hlp->id_name);
                else
                    debugs(80, DBG_CRITICAL, "ERROR: The " << hlp->id_name << " helpers are crashing too rapidly, need help!");
            }

            debugs(80, DBG_IMPORTANT, "Starting new helpers");
            helperOpenServers(hlp);
        }
    }

    while (!srv->requests.empty()) {
        // XXX: re-schedule these on another helper?
        Helper::Xaction *r = srv->requests.front();
        srv->requests.pop_front();
        void *cbdata;

        if (cbdataReferenceValidDone(r->request.data, &cbdata)) {
            r->reply.result = Helper::Unknown;
            r->request.callback(cbdata, r->reply);
        }

        delete r;
    }
    srv->requestsIndex.clear();

    cbdataReferenceDone(srv->parent);
    delete srv;
}

static void
helperStatefulServerFree(helper_stateful_server *srv)
{
    statefulhelper *hlp = srv->parent;

    if (srv->rbuf) {
        memFreeBuf(srv->rbuf_sz, srv->rbuf);
        srv->rbuf = NULL;
    }

#if 0
    srv->wqueue->clean();

    delete srv->wqueue;

#endif

    /* TODO: walk the local queue of requests and carry them all out */
    if (Comm::IsConnOpen(srv->writePipe))
        srv->closeWritePipeSafely(hlp->id_name);

    dlinkDelete(&srv->link, &hlp->servers);

    assert(hlp->childs.n_running > 0);
    -- hlp->childs.n_running;

    if (!srv->flags.shutdown) {
        assert( hlp->childs.n_active > 0);
        -- hlp->childs.n_active;
        debugs(84, DBG_CRITICAL, "WARNING: " << hlp->id_name << " #" << srv->index << " exited");

        if (hlp->childs.needNew() > 0) {
            debugs(80, DBG_IMPORTANT, "Too few " << hlp->id_name << " processes are running (need " << hlp->childs.needNew() << "/" << hlp->childs.n_max << ")");

            if (hlp->childs.n_active < hlp->childs.n_startup && hlp->last_restart > squid_curtime - 30) {
                if (srv->stats.replies < 1)
                    fatalf("The %s helpers are crashing too rapidly, need help!\n", hlp->id_name);
                else
                    debugs(80, DBG_CRITICAL, "ERROR: The " << hlp->id_name << " helpers are crashing too rapidly, need help!");
            }

            debugs(80, DBG_IMPORTANT, "Starting new helpers");
            helperStatefulOpenServers(hlp);
        }
    }

    while (!srv->requests.empty()) {
        // XXX: re-schedule these on another helper?
        Helper::Xaction *r = srv->requests.front();
        srv->requests.pop_front();
        void *cbdata;

        if (cbdataReferenceValidDone(r->request.data, &cbdata)) {
            r->reply.result = Helper::Unknown;
            r->request.callback(cbdata, r->reply);
        }

        delete r;
    }

    if (srv->data != NULL)
        hlp->datapool->freeOne(srv->data);

    cbdataReferenceDone(srv->parent);

    delete srv;
}

Helper::Xaction *
helper_server::popRequest(int request_number)
{
    Helper::Xaction *r = nullptr;
    helper_server::RequestIndex::iterator it;
    if (parent->childs.concurrency) {
        // If concurency supported retrieve request from ID
        it = requestsIndex.find(request_number);
        if (it != requestsIndex.end()) {
            r = *(it->second);
            requests.erase(it->second);
            requestsIndex.erase(it);
        }
    } else if(!requests.empty()) {
        // Else get the first request from queue, if any
        r = requests.front();
        requests.pop_front();
    }

    return r;
}

/// Calls back with a pointer to the buffer with the helper output
static void
helperReturnBuffer(helper_server * srv, helper * hlp, char * msg, size_t msgSize, char * msgEnd)
{
    if (Helper::Xaction *r = srv->replyXaction) {
        const bool hasSpace = r->reply.accumulate(msg, msgSize);
        if (!hasSpace) {
            debugs(84, DBG_IMPORTANT, "ERROR: Disconnecting from a " <<
                   "helper that overflowed " << srv->rbuf_sz << "-byte " <<
                   "Squid input buffer: " << hlp->id_name << " #" << srv->index);
            srv->closePipesSafely(hlp->id_name);
            return;
        }

        if (!msgEnd)
            return; // We are waiting for more data.

        bool retry = false;
        if (cbdataReferenceValid(r->request.data)) {
            r->reply.finalize();
            if (r->reply.result == Helper::BrokenHelper && r->request.retries < MAX_RETRIES) {
                debugs(84, DBG_IMPORTANT, "ERROR: helper: " << r->reply << ", attempt #" << (r->request.retries + 1) << " of 2");
                retry = true;
            } else {
                HLPCB *callback = r->request.callback;
                r->request.callback = nullptr;
                void *cbdata = nullptr;
                if (cbdataReferenceValidDone(r->request.data, &cbdata))
                    callback(cbdata, r->reply);
            }
        }

        -- srv->stats.pending;
        ++ srv->stats.replies;

        ++ hlp->stats.replies;

        srv->answer_time = current_time;

        srv->dispatch_time = r->request.dispatch_time;

        hlp->stats.avg_svc_time =
            Math::intAverage(hlp->stats.avg_svc_time,
                             tvSubMsec(r->request.dispatch_time, current_time),
                             hlp->stats.replies, REDIRECT_AV_FACTOR);

        // release or re-submit parsedRequestXaction object
        srv->replyXaction = nullptr;
        if (retry) {
            ++r->request.retries;
            hlp->submitRequest(r);
        } else
            delete r;
    }

    if (hlp->timeout && hlp->childs.concurrency)
        srv->checkForTimedOutRequests(hlp->retryTimedOut);

    if (!srv->flags.shutdown) {
        helperKickQueue(hlp);
    } else if (!srv->flags.closing && !srv->stats.pending) {
        srv->flags.closing=true;
        srv->writePipe->close();
    }
}

static void
helperHandleRead(const Comm::ConnectionPointer &conn, char *, size_t len, Comm::Flag flag, int, void *data)
{
    helper_server *srv = (helper_server *)data;
    helper *hlp = srv->parent;
    assert(cbdataReferenceValid(data));

    /* Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us */

    if (flag == Comm::ERR_CLOSING) {
        return;
    }

    assert(conn->fd == srv->readPipe->fd);

    debugs(84, 5, "helperHandleRead: " << len << " bytes from " << hlp->id_name << " #" << srv->index);

    if (flag != Comm::OK || len == 0) {
        srv->closePipesSafely(hlp->id_name);
        return;
    }

    srv->roffset += len;
    srv->rbuf[srv->roffset] = '\0';
    debugs(84, DBG_DATA, Raw("accumulated", srv->rbuf, srv->roffset));

    if (!srv->stats.pending && !srv->stats.timedout) {
        /* someone spoke without being spoken to */
        debugs(84, DBG_IMPORTANT, "helperHandleRead: unexpected read from " <<
               hlp->id_name << " #" << srv->index << ", " << (int)len <<
               " bytes '" << srv->rbuf << "'");

        srv->roffset = 0;
        srv->rbuf[0] = '\0';
    }

    bool needsMore = false;
    char *msg = srv->rbuf;
    while (*msg && !needsMore) {
        int skip = 0;
        char *eom = strchr(msg, hlp->eom);
        if (eom) {
            skip = 1;
            debugs(84, 3, "helperHandleRead: end of reply found");
            if (eom > msg && eom[-1] == '\r' && hlp->eom == '\n') {
                *eom = '\0';
                // rewind to the \r octet which is the real terminal now
                // and remember that we have to skip forward 2 places now.
                skip = 2;
                --eom;
            }
            *eom = '\0';
        }

        if (!srv->ignoreToEom && !srv->replyXaction) {
            int i = 0;
            if (hlp->childs.concurrency) {
                char *e = NULL;
                i = strtol(msg, &e, 10);
                // Do we need to check for e == msg? Means wrong response from helper.
                // Will be droped as "unexpected reply on channel 0"
                needsMore = !(xisspace(*e) || (eom && e == eom));
                if (!needsMore) {
                    msg = e;
                    while (*msg && xisspace(*msg))
                        ++msg;
                } // else not enough data to compute request number
            }
            if (!(srv->replyXaction = srv->popRequest(i))) {
                if (srv->stats.timedout) {
                    debugs(84, 3, "Timedout reply received for request-ID: " << i << " , ignore");
                } else {
                    debugs(84, DBG_IMPORTANT, "helperHandleRead: unexpected reply on channel " <<
                           i << " from " << hlp->id_name << " #" << srv->index <<
                           " '" << srv->rbuf << "'");
                }
                srv->ignoreToEom = true;
            }
        } // else we need to just append reply data to the current Xaction

        if (!needsMore) {
            size_t msgSize  = eom ? eom - msg : (srv->roffset - (msg - srv->rbuf));
            assert(msgSize <= srv->rbuf_sz);
            helperReturnBuffer(srv, hlp, msg, msgSize, eom);
            msg += msgSize + skip;
            assert(static_cast<size_t>(msg - srv->rbuf) <= srv->rbuf_sz);

            // The next message should not ignored.
            if (eom && srv->ignoreToEom)
                srv->ignoreToEom = false;
        } else
            assert(skip == 0 && eom == NULL);
    }

    if (needsMore) {
        size_t msgSize = (srv->roffset - (msg - srv->rbuf));
        assert(msgSize <= srv->rbuf_sz);
        memmove(srv->rbuf, msg, msgSize);
        srv->roffset = msgSize;
        srv->rbuf[srv->roffset] = '\0';
    } else {
        // All of the responses parsed and msg points at the end of read data
        assert(static_cast<size_t>(msg - srv->rbuf) == srv->roffset);
        srv->roffset = 0;
    }

    if (Comm::IsConnOpen(srv->readPipe) && !fd_table[srv->readPipe->fd].closing()) {
        int spaceSize = srv->rbuf_sz - srv->roffset - 1;
        assert(spaceSize >= 0);

        AsyncCall::Pointer call = commCbCall(5,4, "helperHandleRead",
                                             CommIoCbPtrFun(helperHandleRead, srv));
        comm_read(srv->readPipe, srv->rbuf + srv->roffset, spaceSize, call);
    }
}

static void
helperStatefulHandleRead(const Comm::ConnectionPointer &conn, char *, size_t len, Comm::Flag flag, int, void *data)
{
    char *t = NULL;
    helper_stateful_server *srv = (helper_stateful_server *)data;
    statefulhelper *hlp = srv->parent;
    assert(cbdataReferenceValid(data));

    /* Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us */

    if (flag == Comm::ERR_CLOSING) {
        return;
    }

    assert(conn->fd == srv->readPipe->fd);

    debugs(84, 5, "helperStatefulHandleRead: " << len << " bytes from " <<
           hlp->id_name << " #" << srv->index);

    if (flag != Comm::OK || len == 0) {
        srv->closePipesSafely(hlp->id_name);
        return;
    }

    srv->roffset += len;
    srv->rbuf[srv->roffset] = '\0';
    Helper::Xaction *r = srv->requests.front();
    debugs(84, DBG_DATA, Raw("accumulated", srv->rbuf, srv->roffset));

    if (r == NULL) {
        /* someone spoke without being spoken to */
        debugs(84, DBG_IMPORTANT, "helperStatefulHandleRead: unexpected read from " <<
               hlp->id_name << " #" << srv->index << ", " << (int)len <<
               " bytes '" << srv->rbuf << "'");

        srv->roffset = 0;
    }

    if ((t = strchr(srv->rbuf, hlp->eom))) {
        debugs(84, 3, "helperStatefulHandleRead: end of reply found");

        if (t > srv->rbuf && t[-1] == '\r' && hlp->eom == '\n') {
            *t = '\0';
            // rewind to the \r octet which is the real terminal now
            --t;
        }

        *t = '\0';
    }

    if (r && !r->reply.accumulate(srv->rbuf, t ? (t - srv->rbuf) : srv->roffset)) {
        debugs(84, DBG_IMPORTANT, "ERROR: Disconnecting from a " <<
               "helper that overflowed " << srv->rbuf_sz << "-byte " <<
               "Squid input buffer: " << hlp->id_name << " #" << srv->index);
        srv->closePipesSafely(hlp->id_name);
        return;
    }
    /**
     * BUG: the below assumes that only one response per read() was received and discards any octets remaining.
     *      Doing this prohibits concurrency support with multiple replies per read().
     * TODO: check that read() setup on these buffers pays attention to roffest!=0
     * TODO: check that replies bigger than the buffer are discarded and do not to affect future replies
     */
    srv->roffset = 0;

    if (t) {
        /* end of reply found */
        srv->requests.pop_front(); // we already have it in 'r'
        int called = 1;

        if (r && cbdataReferenceValid(r->request.data)) {
            r->reply.finalize();
            r->reply.whichServer = srv;
            r->request.callback(r->request.data, r->reply);
        } else {
            debugs(84, DBG_IMPORTANT, "StatefulHandleRead: no callback data registered");
            called = 0;
        }

        delete r;

        -- srv->stats.pending;
        ++ srv->stats.replies;

        ++ hlp->stats.replies;
        srv->answer_time = current_time;
        hlp->stats.avg_svc_time =
            Math::intAverage(hlp->stats.avg_svc_time,
                             tvSubMsec(srv->dispatch_time, current_time),
                             hlp->stats.replies, REDIRECT_AV_FACTOR);

        if (called)
            helperStatefulServerDone(srv);
        else
            helperStatefulReleaseServer(srv);
    }

    if (Comm::IsConnOpen(srv->readPipe) && !fd_table[srv->readPipe->fd].closing()) {
        int spaceSize = srv->rbuf_sz - 1;

        AsyncCall::Pointer call = commCbCall(5,4, "helperStatefulHandleRead",
                                             CommIoCbPtrFun(helperStatefulHandleRead, srv));
        comm_read(srv->readPipe, srv->rbuf, spaceSize, call);
    }
}

/// Handles a request when all running helpers, if any, are busy.
static void
Enqueue(helper * hlp, Helper::Xaction * r)
{
    hlp->queue.push(r);
    ++ hlp->stats.queue_size;

    /* do this first so idle=N has a chance to grow the child pool before it hits critical. */
    if (hlp->childs.needNew() > 0) {
        debugs(84, DBG_CRITICAL, "Starting new " << hlp->id_name << " helpers...");
        helperOpenServers(hlp);
        return;
    }

    if (hlp->stats.queue_size < (int)hlp->childs.queue_size)
        return;

    if (squid_curtime - hlp->last_queue_warn < 600)
        return;

    if (shutting_down || reconfiguring)
        return;

    hlp->last_queue_warn = squid_curtime;

    debugs(84, DBG_CRITICAL, "WARNING: All " << hlp->childs.n_active << "/" << hlp->childs.n_max << " " << hlp->id_name << " processes are busy.");
    debugs(84, DBG_CRITICAL, "WARNING: " << hlp->stats.queue_size << " pending requests queued");
    debugs(84, DBG_CRITICAL, "WARNING: Consider increasing the number of " << hlp->id_name << " processes in your config file.");
}

static void
StatefulEnqueue(statefulhelper * hlp, Helper::Xaction * r)
{
    hlp->queue.push(r);
    ++ hlp->stats.queue_size;

    /* do this first so idle=N has a chance to grow the child pool before it hits critical. */
    if (hlp->childs.needNew() > 0) {
        debugs(84, DBG_CRITICAL, "Starting new " << hlp->id_name << " helpers...");
        helperStatefulOpenServers(hlp);
        return;
    }

    if (hlp->stats.queue_size < (int)hlp->childs.queue_size)
        return;

    if (squid_curtime - hlp->last_queue_warn < 600)
        return;

    if (shutting_down || reconfiguring)
        return;

    hlp->last_queue_warn = squid_curtime;

    debugs(84, DBG_CRITICAL, "WARNING: All " << hlp->childs.n_active << "/" << hlp->childs.n_max << " " << hlp->id_name << " processes are busy.");
    debugs(84, DBG_CRITICAL, "WARNING: " << hlp->stats.queue_size << " pending requests queued");
    debugs(84, DBG_CRITICAL, "WARNING: Consider increasing the number of " << hlp->id_name << " processes in your config file.");
}

Helper::Xaction *
helper::nextRequest()
{
    if (queue.empty())
        return nullptr;

    auto *r = queue.front();
    queue.pop();
    --stats.queue_size;
    return r;
}

static helper_server *
GetFirstAvailable(const helper * hlp)
{
    dlink_node *n;
    helper_server *srv;
    helper_server *selected = NULL;
    debugs(84, 5, "GetFirstAvailable: Running servers " << hlp->childs.n_running);

    if (hlp->childs.n_running == 0)
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

    if (!selected) {
        debugs(84, 5, "GetFirstAvailable: None available.");
        return NULL;
    }

    if (selected->stats.pending >= (hlp->childs.concurrency ? hlp->childs.concurrency : 1)) {
        debugs(84, 3, "GetFirstAvailable: Least-loaded helper is fully loaded!");
        return NULL;
    }

    debugs(84, 5, "GetFirstAvailable: returning srv-" << selected->index);
    return selected;
}

static helper_stateful_server *
StatefulGetFirstAvailable(const statefulhelper * hlp)
{
    dlink_node *n;
    helper_stateful_server *srv = NULL;
    debugs(84, 5, "StatefulGetFirstAvailable: Running servers " << hlp->childs.n_running);

    if (hlp->childs.n_running == 0)
        return NULL;

    for (n = hlp->servers.head; n != NULL; n = n->next) {
        srv = (helper_stateful_server *)n->data;

        if (srv->stats.pending)
            continue;

        if (srv->flags.reserved)
            continue;

        if (srv->flags.shutdown)
            continue;

        debugs(84, 5, "StatefulGetFirstAvailable: returning srv-" << srv->index);
        return srv;
    }

    debugs(84, 5, "StatefulGetFirstAvailable: None available.");
    return NULL;
}

static void
helperDispatchWriteDone(const Comm::ConnectionPointer &, char *, size_t, Comm::Flag flag, int, void *data)
{
    helper_server *srv = (helper_server *)data;

    srv->writebuf->clean();
    delete srv->writebuf;
    srv->writebuf = NULL;
    srv->flags.writing = false;

    if (flag != Comm::OK) {
        /* Helper server has crashed */
        debugs(84, DBG_CRITICAL, "helperDispatch: Helper " << srv->parent->id_name << " #" << srv->index << " has crashed");
        return;
    }

    if (!srv->wqueue->isNull()) {
        srv->writebuf = srv->wqueue;
        srv->wqueue = new MemBuf;
        srv->flags.writing = true;
        AsyncCall::Pointer call = commCbCall(5,5, "helperDispatchWriteDone",
                                             CommIoCbPtrFun(helperDispatchWriteDone, srv));
        Comm::Write(srv->writePipe, srv->writebuf->content(), srv->writebuf->contentSize(), call, NULL);
    }
}

static void
helperDispatch(helper_server * srv, Helper::Xaction * r)
{
    helper *hlp = srv->parent;
    const uint64_t reqId = ++srv->nextRequestId;

    if (!cbdataReferenceValid(r->request.data)) {
        debugs(84, DBG_IMPORTANT, "helperDispatch: invalid callback data");
        delete r;
        return;
    }

    r->request.Id = reqId;
    helper_server::Requests::iterator it = srv->requests.insert(srv->requests.end(), r);
    r->request.dispatch_time = current_time;

    if (srv->wqueue->isNull())
        srv->wqueue->init();

    if (hlp->childs.concurrency) {
        srv->requestsIndex.insert(helper_server::RequestIndex::value_type(reqId, it));
        assert(srv->requestsIndex.size() == srv->requests.size());
        srv->wqueue->appendf("%" PRIu64 " %s", reqId, r->request.buf);
    } else
        srv->wqueue->append(r->request.buf, strlen(r->request.buf));

    if (!srv->flags.writing) {
        assert(NULL == srv->writebuf);
        srv->writebuf = srv->wqueue;
        srv->wqueue = new MemBuf;
        srv->flags.writing = true;
        AsyncCall::Pointer call = commCbCall(5,5, "helperDispatchWriteDone",
                                             CommIoCbPtrFun(helperDispatchWriteDone, srv));
        Comm::Write(srv->writePipe, srv->writebuf->content(), srv->writebuf->contentSize(), call, NULL);
    }

    debugs(84, 5, "helperDispatch: Request sent to " << hlp->id_name << " #" << srv->index << ", " << strlen(r->request.buf) << " bytes");

    ++ srv->stats.uses;
    ++ srv->stats.pending;
    ++ hlp->stats.requests;
}

static void
helperStatefulDispatchWriteDone(const Comm::ConnectionPointer &, char *, size_t, Comm::Flag, int, void *)
{}

static void
helperStatefulDispatch(helper_stateful_server * srv, Helper::Xaction * r)
{
    statefulhelper *hlp = srv->parent;

    if (!cbdataReferenceValid(r->request.data)) {
        debugs(84, DBG_IMPORTANT, "helperStatefulDispatch: invalid callback data");
        delete r;
        helperStatefulReleaseServer(srv);
        return;
    }

    debugs(84, 9, "helperStatefulDispatch busying helper " << hlp->id_name << " #" << srv->index);

    if (r->request.placeholder == 1) {
        /* a callback is needed before this request can _use_ a helper. */
        /* we don't care about releasing this helper. The request NEVER
         * gets to the helper. So we throw away the return code */
        r->reply.result = Helper::Unknown;
        r->reply.whichServer = srv;
        r->request.callback(r->request.data, r->reply);
        /* throw away the placeholder */
        delete r;
        /* and push the queue. Note that the callback may have submitted a new
         * request to the helper which is why we test for the request */

        if (!srv->requests.size())
            helperStatefulServerDone(srv);

        return;
    }

    srv->flags.reserved = true;
    srv->requests.push_back(r);
    srv->dispatch_time = current_time;
    AsyncCall::Pointer call = commCbCall(5,5, "helperStatefulDispatchWriteDone",
                                         CommIoCbPtrFun(helperStatefulDispatchWriteDone, hlp));
    Comm::Write(srv->writePipe, r->request.buf, strlen(r->request.buf), call, NULL);
    debugs(84, 5, "helperStatefulDispatch: Request sent to " <<
           hlp->id_name << " #" << srv->index << ", " <<
           (int) strlen(r->request.buf) << " bytes");

    ++ srv->stats.uses;
    ++ srv->stats.pending;
    ++ hlp->stats.requests;
}

static void
helperKickQueue(helper * hlp)
{
    Helper::Xaction *r;
    helper_server *srv;

    while ((srv = GetFirstAvailable(hlp)) && (r = hlp->nextRequest()))
        helperDispatch(srv, r);
}

static void
helperStatefulKickQueue(statefulhelper * hlp)
{
    Helper::Xaction *r;
    helper_stateful_server *srv;

    while ((srv = StatefulGetFirstAvailable(hlp)) && (r = hlp->nextRequest()))
        helperStatefulDispatch(srv, r);
}

static void
helperStatefulServerDone(helper_stateful_server * srv)
{
    if (!srv->flags.shutdown) {
        helperStatefulKickQueue(srv->parent);
    } else if (!srv->flags.closing && !srv->flags.reserved && !srv->stats.pending) {
        srv->closeWritePipeSafely(srv->parent->id_name);
        return;
    }
}

void
helper_server::checkForTimedOutRequests(bool const retry)
{
    assert(parent->childs.concurrency);
    while(!requests.empty() && requests.front()->request.timedOut(parent->timeout)) {
        Helper::Xaction *r = requests.front();
        RequestIndex::iterator it;
        it = requestsIndex.find(r->request.Id);
        assert(it != requestsIndex.end());
        requestsIndex.erase(it);
        requests.pop_front();
        debugs(84, 2, "Request " << r->request.Id << " timed-out, remove it from queue");
        void *cbdata;
        bool retried = false;
        if (retry && r->request.retries < MAX_RETRIES && cbdataReferenceValid(r->request.data)) {
            debugs(84, 2, "Retry request " << r->request.Id);
            ++r->request.retries;
            parent->submitRequest(r);
            retried = true;
        } else if (cbdataReferenceValidDone(r->request.data, &cbdata)) {
            if (!parent->onTimedOutResponse.isEmpty()) {
                if (r->reply.accumulate(parent->onTimedOutResponse.rawContent(), parent->onTimedOutResponse.length()))
                    r->reply.finalize();
                else
                    r->reply.result = Helper::TimedOut;
                r->request.callback(cbdata, r->reply);
            } else {
                r->reply.result = Helper::TimedOut;
                r->request.callback(cbdata, r->reply);
            }
        }
        --stats.pending;
        ++stats.timedout;
        ++parent->stats.timedout;
        if (!retried)
            delete r;
    }
}

void
helper_server::requestTimeout(const CommTimeoutCbParams &io)
{
    debugs(26, 3, HERE << io.conn);
    helper_server *srv = static_cast<helper_server *>(io.data);

    if (!cbdataReferenceValid(srv))
        return;

    srv->checkForTimedOutRequests(srv->parent->retryTimedOut);

    debugs(84, 3, HERE << io.conn << " establish new helper_server::requestTimeout");
    AsyncCall::Pointer timeoutCall = commCbCall(84, 4, "helper_server::requestTimeout",
                                     CommTimeoutCbPtrFun(helper_server::requestTimeout, srv));

    const int timeSpent = srv->requests.empty() ? 0 : (squid_curtime - srv->requests.front()->request.dispatch_time.tv_sec);
    const int timeLeft = max(1, (static_cast<int>(srv->parent->timeout) - timeSpent));

    commSetConnTimeout(io.conn, timeLeft, timeoutCall);
}

