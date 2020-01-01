/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

/*
 * The idea for this came from these two websites:
 * http://www.xmailserver.org/linux-patches/nio-improve.html
 * http://www.kegel.com/c10k.html
 *
 * This is to support the epoll sysctl being added to the linux 2.5
 * kernel tree.  The new sys_epoll is an event based poller without
 * most of the fuss of rtsignals.
 *
 * -- David Nicklay <dnicklay@web.turner.com>
 */

/*
 * XXX Currently not implemented / supported by this module XXX
 *
 * - delay pools
 * - deferred reads
 *
 */

#include "squid.h"

#if USE_EPOLL

#include "base/CodeContext.h"
#include "comm/Loops.h"
#include "fde.h"
#include "globals.h"
#include "mgr/Registration.h"
#include "profiler/Profiler.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"

#define DEBUG_EPOLL 0

#include <cerrno>
#if HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif

static int kdpfd = -1;
static int max_poll_time = 1000;

static struct epoll_event *pevents;

static void commEPollRegisterWithCacheManager(void);

/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Public functions */

/*
 * This is a needed exported function which will be called to initialise
 * the network loop code.
 */
void
Comm::SelectLoopInit(void)
{
    pevents = (struct epoll_event *) xmalloc(SQUID_MAXFD * sizeof(struct epoll_event));

    if (!pevents) {
        int xerrno = errno;
        fatalf("comm_select_init: xmalloc() failed: %s\n", xstrerr(xerrno));
    }

    kdpfd = epoll_create(SQUID_MAXFD);

    if (kdpfd < 0) {
        int xerrno = errno;
        fatalf("comm_select_init: epoll_create(): %s\n", xstrerr(xerrno));
    }

    commEPollRegisterWithCacheManager();
}

static const char* epolltype_atoi(int x)
{
    switch (x) {

    case EPOLL_CTL_ADD:
        return "EPOLL_CTL_ADD";

    case EPOLL_CTL_DEL:
        return "EPOLL_CTL_DEL";

    case EPOLL_CTL_MOD:
        return "EPOLL_CTL_MOD";

    default:
        return "UNKNOWN_EPOLLCTL_OP";
    }
}

/**
 * This is a needed exported function which will be called to register
 * and deregister interest in a pending IO state for a given FD.
 */
void
Comm::SetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    fde *F = &fd_table[fd];
    int epoll_ctl_type = 0;

    assert(fd >= 0);
    debugs(5, 5, HERE << "FD " << fd << ", type=" << type <<
           ", handler=" << handler << ", client_data=" << client_data <<
           ", timeout=" << timeout);

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.fd = fd;

    if (!F->flags.open) {
        epoll_ctl(kdpfd, EPOLL_CTL_DEL, fd, &ev);
        return;
    }

    // If read is an interest

    if (type & COMM_SELECT_READ) {
        if (handler) {
            // Hack to keep the events flowing if there is data immediately ready
            if (F->flags.read_pending)
                ev.events |= EPOLLOUT;
            ev.events |= EPOLLIN;
        }

        F->read_handler = handler;

        F->read_data = client_data;

        // Otherwise, use previously stored value
    } else if (F->epoll_state & EPOLLIN) {
        ev.events |= EPOLLIN;
    }

    // If write is an interest
    if (type & COMM_SELECT_WRITE) {
        if (handler)
            ev.events |= EPOLLOUT;

        F->write_handler = handler;

        F->write_data = client_data;

        // Otherwise, use previously stored value
    } else if (F->epoll_state & EPOLLOUT) {
        ev.events |= EPOLLOUT;
    }

    if (ev.events)
        ev.events |= EPOLLHUP | EPOLLERR;

    if (ev.events != F->epoll_state) {
        if (F->epoll_state) // already monitoring something.
            epoll_ctl_type = ev.events ? EPOLL_CTL_MOD : EPOLL_CTL_DEL;
        else
            epoll_ctl_type = EPOLL_CTL_ADD;

        F->epoll_state = ev.events;

        if (epoll_ctl(kdpfd, epoll_ctl_type, fd, &ev) < 0) {
            int xerrno = errno;
            debugs(5, DEBUG_EPOLL ? 0 : 8, "epoll_ctl(," << epolltype_atoi(epoll_ctl_type) <<
                   ",,): failed on FD " << fd << ": " << xstrerr(xerrno));
        }
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;

    if (timeout || handler) // all non-cleanup requests
        F->codeContext = CodeContext::Current(); // TODO: Avoid clearing if set?
    else if (!ev.events) // full cleanup: no more FD-associated work expected
        F->codeContext = nullptr;
    // else: direction-specific/timeout cleanup requests preserve F->codeContext
}

static void commIncomingStats(StoreEntry * sentry);

static void
commEPollRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("comm_epoll_incoming",
                        "comm_incoming() stats",
                        commIncomingStats, 0, 1);
}

static void
commIncomingStats(StoreEntry * sentry)
{
    StatCounters *f = &statCounter;
    storeAppendPrintf(sentry, "Total number of epoll(2) loops: %ld\n", statCounter.select_loops);
    storeAppendPrintf(sentry, "Histogram of returned filedescriptors\n");
    f->select_fds_hist.dump(sentry, statHistIntDumper);
}

/**
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 *
 * Called to do the new-style IO, courtesy of of squid (like most of this
 * new IO code). This routine handles the stuff we've hidden in
 * comm_setselect and fd_table[] and calls callbacks for IO ready
 * events.
 */
Comm::Flag
Comm::DoSelect(int msec)
{
    int num, i,fd;
    fde *F;
    PF *hdl;

    struct epoll_event *cevents;

    PROF_start(comm_check_incoming);

    if (msec > max_poll_time)
        msec = max_poll_time;

    for (;;) {
        num = epoll_wait(kdpfd, pevents, SQUID_MAXFD, msec);
        ++ statCounter.select_loops;

        if (num >= 0)
            break;

        if (ignoreErrno(errno))
            break;

        getCurrentTime();

        PROF_stop(comm_check_incoming);

        return Comm::COMM_ERROR;
    }

    PROF_stop(comm_check_incoming);
    getCurrentTime();

    statCounter.select_fds_hist.count(num);

    if (num == 0)
        return Comm::TIMEOUT;       /* No error.. */

    PROF_start(comm_handle_ready_fd);

    for (i = 0, cevents = pevents; i < num; ++i, ++cevents) {
        fd = cevents->data.fd;
        F = &fd_table[fd];
        CodeContext::Reset(F->codeContext);
        debugs(5, DEBUG_EPOLL ? 0 : 8, HERE << "got FD " << fd << " events=" <<
               std::hex << cevents->events << " monitoring=" << F->epoll_state <<
               " F->read_handler=" << F->read_handler << " F->write_handler=" << F->write_handler);

        // TODO: add EPOLLPRI??

        if (cevents->events & (EPOLLIN|EPOLLHUP|EPOLLERR) || F->flags.read_pending) {
            if ((hdl = F->read_handler) != NULL) {
                debugs(5, DEBUG_EPOLL ? 0 : 8, HERE << "Calling read handler on FD " << fd);
                PROF_start(comm_write_handler);
                F->read_handler = NULL;
                hdl(fd, F->read_data);
                PROF_stop(comm_write_handler);
                ++ statCounter.select_fds;
            } else {
                debugs(5, DEBUG_EPOLL ? 0 : 8, HERE << "no read handler for FD " << fd);
                // remove interest since no handler exist for this event.
                SetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
            }
        }

        if (cevents->events & (EPOLLOUT|EPOLLHUP|EPOLLERR)) {
            if ((hdl = F->write_handler) != NULL) {
                debugs(5, DEBUG_EPOLL ? 0 : 8, HERE << "Calling write handler on FD " << fd);
                PROF_start(comm_read_handler);
                F->write_handler = NULL;
                hdl(fd, F->write_data);
                PROF_stop(comm_read_handler);
                ++ statCounter.select_fds;
            } else {
                debugs(5, DEBUG_EPOLL ? 0 : 8, HERE << "no write handler for FD " << fd);
                // remove interest since no handler exist for this event.
                SetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
            }
        }
    }

    CodeContext::Reset();

    PROF_stop(comm_handle_ready_fd);

    return Comm::OK;
}

void
Comm::QuickPollRequired(void)
{
    max_poll_time = 10;
}

#endif /* USE_EPOLL */

