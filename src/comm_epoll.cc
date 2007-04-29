
/*
 * $Id: comm_epoll.cc,v 1.15 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 5     Socket Functions
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
#include "comm_epoll.h"
#include "CacheManager.h"
#include "Store.h"
#include "fde.h"
#include "SquidTime.h"

#ifdef USE_EPOLL

#define DEBUG_EPOLL 0

#include <sys/epoll.h>

static int kdpfd;
static int max_poll_time = 1000;

static struct epoll_event *pevents;



/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Public functions */


/*
 * comm_select_init
 *
 * This is a needed exported function which will be called to initialise
 * the network loop code.
 */
void
comm_select_init(void)
{

    pevents = (struct epoll_event *) xmalloc(SQUID_MAXFD * sizeof(struct epoll_event));

    if (!pevents) {
        fatalf("comm_select_init: xmalloc() failed: %s\n",xstrerror());
    }

    kdpfd = epoll_create(SQUID_MAXFD);

    if (kdpfd < 0) {
        fatalf("comm_select_init: epoll_create(): %s\n",xstrerror());
    }
}

static const char* epolltype_atoi(int x)
{
    switch(x) {

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

/*
 * comm_setselect
 *
 * This is a needed exported function which will be called to register
 * and deregister interest in a pending IO state for a given FD.
 *
 */
void
commSetSelect(int fd, unsigned int type, PF * handler,
              void *client_data, time_t timeout)
{
    fde *F = &fd_table[fd];
    int epoll_ctl_type = 0;

    struct epoll_event ev;
    assert(fd >= 0);
    debugs(5, DEBUG_EPOLL ? 0 : 8, "commSetSelect(FD " << fd << ",type=" << type << 
           ",handler=" << handler << ",client_data=" << client_data << 
           ",timeout=" << timeout << ")");

    if (RUNNING_ON_VALGRIND) {
	/* Keep valgrind happy.. complains about uninitialized bytes otherwise */
	memset(&ev, 0, sizeof(ev));
    }
    ev.events = 0;
    ev.data.fd = fd;

    if (!F->flags.open) {
        epoll_ctl(kdpfd, EPOLL_CTL_DEL, fd, &ev);
        return;
    }

    // If read is an interest

    if (type & COMM_SELECT_READ) {
        if (handler)
            ev.events |= EPOLLIN;

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
            debugs(5, DEBUG_EPOLL ? 0 : 8, "commSetSelect: epoll_ctl(," << epolltype_atoi(epoll_ctl_type) << 
                   ",,): failed on FD " << fd << ": " << xstrerror());
        }
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;
}


static void commIncomingStats(StoreEntry * sentry);

void
commEPollRegisterWithCacheManager(CacheManager& manager)
{
    manager.registerAction("comm_epoll_incoming",
                           "comm_incoming() stats",
                           commIncomingStats, 0, 1);
}

static void
commIncomingStats(StoreEntry * sentry)
{
    StatCounters *f = &statCounter;
    storeAppendPrintf(sentry, "Total number of epoll(2) loops: %d\n", statCounter.select_loops);
    storeAppendPrintf(sentry, "Histogram of returned filedescriptors\n");
    statHistDump(&f->select_fds_hist, sentry, statHistIntDumper);
}

/*
 * comm_select
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 *
 * Called to do the new-style IO, courtesy of of squid (like most of this
 * new IO code). This routine handles the stuff we've hidden in
 * comm_setselect and fd_table[] and calls callbacks for IO ready
 * events.
 */

comm_err_t
comm_select(int msec)
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
        statCounter.select_loops++;

        if (num >= 0)
            break;

        if (ignoreErrno(errno))
            break;

        getCurrentTime();

        PROF_stop(comm_check_incoming);

        return COMM_ERROR;
    }

    PROF_stop(comm_check_incoming);
    getCurrentTime();

    statHistCount(&statCounter.select_fds_hist, num);

    if (num == 0)
        return COMM_TIMEOUT;		/* No error.. */

    PROF_start(comm_handle_ready_fd);

    for (i = 0, cevents = pevents; i < num; i++, cevents++) {
        fd = cevents->data.fd;
        F = &fd_table[fd];
        debugs(5, DEBUG_EPOLL ? 0 : 8, "comm_select(): got FD " << fd << " events=" << 
              std::hex << cevents->events << " monitoring=" << F->epoll_state << 
              " F->read_handler=" << F->read_handler << " F->write_handler=" << F->write_handler);

        // TODO: add EPOLLPRI??

        if (cevents->events & (EPOLLIN|EPOLLHUP|EPOLLERR)) {
            if ((hdl = F->read_handler) != NULL) {
                debugs(5, DEBUG_EPOLL ? 0 : 8, "comm_select(): Calling read handler on FD " << fd);
                PROF_start(comm_write_handler);
                F->read_handler = NULL;
                hdl(fd, F->read_data);
                PROF_stop(comm_write_handler);
                statCounter.select_fds++;
            } else {
                debugs(5, DEBUG_EPOLL ? 0 : 8, "comm_select(): no read handler for FD " << fd);
                fd_table[fd].flags.read_pending = 1;
                // remove interest since no handler exist for this event.
                commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
            }
        }

        if (cevents->events & (EPOLLOUT|EPOLLHUP|EPOLLERR)) {
            if ((hdl = F->write_handler) != NULL) {
                debugs(5, DEBUG_EPOLL ? 0 : 8, "comm_select(): Calling write handler on FD " << fd);
                PROF_start(comm_read_handler);
                F->write_handler = NULL;
                hdl(fd, F->write_data);
                PROF_stop(comm_read_handler);
                statCounter.select_fds++;
            } else {
                fd_table[fd].flags.write_pending = 1;
                debugs(5, DEBUG_EPOLL ? 0 : 8, "comm_select(): no write handler for FD " << fd);
                // remove interest since no handler exist for this event.
                commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
            }
        }
    }

    PROF_stop(comm_handle_ready_fd);

    return COMM_OK;
}

void
comm_quick_poll_required(void)
{
    max_poll_time = 100;
}

#endif /* USE_EPOLL */
