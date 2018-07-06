/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

/*
 * This code was originally written by Benno Rice and hacked on quite
 * a bit by Adrian. Adrian then took it to the hybrid-ircd project to use
 * in their new IO subsystem. After a year of modifications and some
 * rather interesting changes (event aggregation) its back in squid.
 * Thanks to the ircd-hybrid guys.
 */

/*
 * XXX Currently not implemented / supported by this module XXX
 *
 * - delay pools
 * - deferred reads
 * - flags.read_pending
 *
 * So, its not entirely useful in a production setup since if a read
 * is meant to be deferred it isn't (we're not even throwing the event
 * away here). Eventually the rest of the code will be rewritten
 * so deferred reads aren't required.
 *  -- adrian
 */
#include "squid.h"

#if USE_KQUEUE
#include "comm/Loops.h"
#include "fde.h"
#include "globals.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"

#include <cerrno>
#if HAVE_SYS_EVENT_H
#include <sys/event.h>
#endif

#define KE_LENGTH        128

/* jlemon goofed up and didn't add EV_SET until fbsd 4.3 */

#ifndef EV_SET
#define EV_SET(kevp, a, b, c, d, e, f) do {     \
        (kevp)->ident = (a);                    \
        (kevp)->filter = (b);                   \
        (kevp)->flags = (c);                    \
        (kevp)->fflags = (d);                   \
        (kevp)->data = (e);                     \
        (kevp)->udata = (f);                    \
} while(0)
#endif

static void kq_update_events(int, short, PF *);
static int kq;

static struct timespec zero_timespec;

static struct kevent *kqlst;        /* kevent buffer */
static int kqmax;                /* max structs to buffer */
static int kqoff;                /* offset into the buffer */
static int max_poll_time = 1000;

static void commKQueueRegisterWithCacheManager(void);

/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Private functions */

void
kq_update_events(int fd, short filter, PF * handler)
{
    PF *cur_handler;
    int kep_flags;

    switch (filter) {

    case EVFILT_READ:
        cur_handler = fd_table[fd].read_handler;
        break;

    case EVFILT_WRITE:
        cur_handler = fd_table[fd].write_handler;
        break;

    default:
        /* XXX bad! -- adrian */
        return;
        break;
    }

    if ((cur_handler == NULL && handler != NULL)
            || (cur_handler != NULL && handler == NULL)) {

        struct kevent *kep;

        kep = kqlst + kqoff;

        if (handler != NULL) {
            kep_flags = (EV_ADD | EV_ONESHOT);
        } else {
            kep_flags = EV_DELETE;
        }

        EV_SET(kep, (uintptr_t) fd, filter, kep_flags, 0, 0, 0);

        /* Check if we've used the last one. If we have then submit them all */
        if (kqoff == kqmax - 1) {
            int ret;

            ret = kevent(kq, kqlst, kqmax, NULL, 0, &zero_timespec);
            /* jdc -- someone needs to do error checking... */

            if (ret == -1) {
                perror("kq_update_events(): kevent()");
                return;
            }

            kqoff = 0;
        } else {
            ++kqoff;
        }
    }
}

/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Public functions */

/*
 * comm_select_init
 *
 * This is a needed exported function which will be called to initialise
 * the network loop code.
 */
void
Comm::SelectLoopInit(void)
{
    kq = kqueue();

    if (kq < 0) {
        fatal("comm_select_init: Couldn't open kqueue fd!\n");
    }

    kqmax = getdtablesize();

    kqlst = (struct kevent *)xmalloc(sizeof(*kqlst) * kqmax);
    zero_timespec.tv_sec = 0;
    zero_timespec.tv_nsec = 0;

    commKQueueRegisterWithCacheManager();
}

/*
 * comm_setselect
 *
 * This is a needed exported function which will be called to register
 * and deregister interest in a pending IO state for a given FD.
 */
void
Comm::SetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->flags.open || (!handler && !client_data && !timeout));
    debugs(5, 5, HERE << "FD " << fd << ", type=" << type <<
           ", handler=" << handler << ", client_data=" << client_data <<
           ", timeout=" << timeout);

    if (type & COMM_SELECT_READ) {
        if (F->flags.read_pending)
            kq_update_events(fd, EVFILT_WRITE, handler);

        kq_update_events(fd, EVFILT_READ, handler);

        F->read_handler = handler;
        F->read_data = client_data;
    }

    if (type & COMM_SELECT_WRITE) {
        kq_update_events(fd, EVFILT_WRITE, handler);
        F->write_handler = handler;
        F->write_data = client_data;
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;

}

/*
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 */

/*
 * comm_select
 *
 * Called to do the new-style IO, courtesy of of squid (like most of this
 * new IO code). This routine handles the stuff we've hidden in
 * comm_setselect and fd_table[] and calls callbacks for IO ready
 * events.
 */

Comm::Flag
Comm::DoSelect(int msec)
{
    int num, i;

    static struct kevent ke[KE_LENGTH];

    struct timespec poll_time;

    if (msec > max_poll_time)
        msec = max_poll_time;

    poll_time.tv_sec = msec / 1000;

    poll_time.tv_nsec = (msec % 1000) * 1000000;

    for (;;) {
        num = kevent(kq, kqlst, kqoff, ke, KE_LENGTH, &poll_time);
        ++statCounter.select_loops;
        kqoff = 0;

        if (num >= 0)
            break;

        if (ignoreErrno(errno))
            break;

        getCurrentTime();

        return Comm::COMM_ERROR;

        /* NOTREACHED */
    }

    getCurrentTime();

    if (num == 0)
        return Comm::OK;        /* No error.. */

    for (i = 0; i < num; ++i) {
        int fd = (int) ke[i].ident;
        PF *hdl = NULL;
        fde *F = &fd_table[fd];

        if (ke[i].flags & EV_ERROR) {
            errno = ke[i].data;
            /* XXX error == bad! -- adrian */
            continue;        /* XXX! */
        }

        if (ke[i].filter == EVFILT_READ || F->flags.read_pending) {
            if ((hdl = F->read_handler) != NULL) {
                F->read_handler = NULL;
                F->flags.read_pending = 0;
                hdl(fd, F->read_data);
            }
        }

        if (ke[i].filter == EVFILT_WRITE) {
            if ((hdl = F->write_handler) != NULL) {
                F->write_handler = NULL;
                hdl(fd, F->write_data);
            }
        }

        if (ke[i].filter != EVFILT_WRITE && ke[i].filter != EVFILT_READ) {
            /* Bad! -- adrian */
            debugs(5, DBG_IMPORTANT, "comm_select: kevent returned " << ke[i].filter << "!");
        }
    }

    return Comm::OK;
}

void
Comm::QuickPollRequired(void)
{
    max_poll_time = 10;
}

static void
commKQueueRegisterWithCacheManager(void)
{
}

#endif /* USE_KQUEUE */

