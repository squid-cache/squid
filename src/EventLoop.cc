
/*
 * $Id: EventLoop.cc,v 1.1 2006/08/07 02:28:22 robertc Exp $
 *
 * DEBUG: section 1     Main Loop
 * AUTHOR: Harvest Derived
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
#include "event.h"
#include "EventLoop.h"
#include "comm.h"

EventLoop::EventLoop() : errcount(0), last_loop(false)
{}

void
EventLoop::prepareToRun()
{
    last_loop = false;
    errcount = 0;
}

void
EventLoop::registerDispatcher(CompletionDispatcher *dispatcher)
{
    dispatchers.push_back(dispatcher);
}

void
EventLoop::run()
{
    prepareToRun();

    while (!last_loop)
        runOnce();
}

void
EventLoop::runOnce()
{
    int loop_delay = EventScheduler::GetInstance()->checkEvents();

    for (dispatcher_vector::iterator i = dispatchers.begin();
            i != dispatchers.end(); ++i)
        (*i)->dispatch();

    if (loop_delay < 0)
        loop_delay = 0;

    switch (comm_select(loop_delay)) {

    case COMM_OK:
        errcount = 0;	/* reset if successful */
        break;

    case COMM_IDLE:
        /* TODO: rather than busy loop, if everything has returned IDLE we should
         * wait for a reasonable timeout period, - if everything returned IDLE
         * then not only is there no work to do, there is no work coming in -
         * all the comm loops have no fds registered, and  all the other 
         * async engines have no work active or pending.
         * ... perhaps we can have a query method to say 'when could there be 
         * work' - i.e. the event dispatcher can return the next event in its
         * queue, and everything else can return -1.
         */
        errcount = 0;
        break;

    case COMM_ERROR:
        errcount++;
        debugs(1, 0, "Select loop Error. Retry " << errcount);

        if (errcount == 10)
            fatal_dump("Select Loop failed 10 times.!");

        break;

    case COMM_TIMEOUT:
        break;

    case COMM_SHUTDOWN:
        stop();

        break;

    default:
        fatal_dump("MAIN: Internal error -- this should never happen.");

        break;
    }
}

void
EventLoop::stop()
{
    last_loop = true;
}
