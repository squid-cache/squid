
/*
 * $Id: comm_epoll.cc,v 1.3 2003/04/22 07:38:30 robertc Exp $
 *
 * DEBUG: section 5    Socket functions
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
#include "Store.h"
#include "fde.h"

#if USE_EPOLL
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
    int change = 0;
    int events = 0;
    int pollin = 0;
    int pollout = 0;

    struct epoll_event ev;
    assert(fd >= 0);
    assert(F->flags.open);
    debug(5, DEBUG_EPOLL ? 0 : 8) ("commSetSelect(fd=%d,type=%u,handler=%p,client_data=%p,timeout=%ld)\n",
                                   fd,type,handler,client_data,timeout);

    if(F->read_handler != NULL)
        pollin = 1;

    if(F->write_handler != NULL)
        pollout = 1;

    if (type & COMM_SELECT_READ) {
        if(F->read_handler != handler)
            change = 1;

        if(handler == NULL)
            pollin = 0;
        else
            pollin = 1;

        F->read_handler = handler;

        F->read_data = client_data;
    }

    if (type & COMM_SELECT_WRITE) {
        if(F->write_handler != handler)
            change = 1;

        if(handler == NULL)
            pollout = 0;
        else
            pollout = 1;

        F->write_handler = handler;

        F->write_data = client_data;
    }

    if(pollin)
        events |= EPOLLIN;

    if(pollout)
        events |= EPOLLOUT;

    if(events)
        events |= EPOLLHUP | EPOLLERR;

    ev.data.fd = fd;

    ev.events = events;

    if(events) {
        if (epoll_ctl(kdpfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
            if(errno == ENOENT) {
                debug(5,4) ("commSetSelect: epoll_ctl(,EPOLL_CTL_MOD,,) failed on fd=%d: entry does not exist\n",fd);

                if (epoll_ctl(kdpfd, EPOLL_CTL_ADD, fd, &ev) < 0)
                    debug(5,1) ("commSetSelect: cpoll_ctl(,EPOLL_CTL_ADD,,) failed on fd=%d!: %s\n",fd,xstrerror());
            } else {
                debug(5,1) ("commSetSelect: cpoll_ctl(,EPOLL_CTL_MOD,,) failed on fd=%d!: %s\n",fd,xstrerror());
            }
        }
    } else if(change) {
        if(epoll_ctl(kdpfd,EPOLL_CTL_DEL,fd,&ev) < 0) {
            if(errno != ENOENT)
                debug(5,1) ("commSetSelect: cpoll_ctl(,EPOLL_CTL_DEL,,) failed on fd=%d!: %s\n",fd,xstrerror());
            else
                debug(5,4) ("commSetSelect: epoll_ctl(,EPOLL_CTL_DEL,,) failed on fd=%d: entry does not exist\n",fd);
        }
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

comm_err_t
comm_select(int msec)
{
    int num, i,fd;
    fde *F;
    PF *hdl;

    struct epoll_event *cevents;
    static time_t last_timeout = 0;

    if (squid_curtime > last_timeout) {
        last_timeout = squid_curtime;
        checkTimeouts();
    }

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

        return COMM_ERROR;
    }

    getCurrentTime();

    if (num == 0)
        return COMM_OK;		/* No error.. */

    for (i = 0, cevents = pevents; i < num; i++, cevents++) {
        fd = cevents->data.fd;
        F = &fd_table[fd];
        debug(5, DEBUG_EPOLL ? 0 : 8) ("comm_select(): got fd=%d events=%d F->read_handler=%p F->write_handler=%p\n",
                                       fd,cevents->events,F->read_handler,F->write_handler);

        if(cevents->events & (EPOLLIN|EPOLLHUP|EPOLLERR)) {
            if((hdl = F->read_handler) != NULL) {
                debug(5, DEBUG_EPOLL ? 0 : 8) ("comm_select(): Calling read handler on fd=%d\n",fd);
                F->read_handler = NULL;
                hdl(fd, F->read_data);
            }
        }

        if(cevents->events & (EPOLLOUT|EPOLLHUP|EPOLLERR)) {
            if((hdl = F->write_handler) != NULL) {
                debug(5, DEBUG_EPOLL ? 0 : 8) ("comm_select(): Calling write handler on fd=%d\n",fd);
                F->write_handler = NULL;
                hdl(fd, F->write_data);
            }
        }
    }

    return COMM_OK;
}

void
comm_quick_poll_required(void)
{
    max_poll_time = 100;
}

#endif /* USE_EPOLL */
