
/*
 * $Id: EventLoop.cc,v 1.2 2006/08/12 01:43:10 robertc Exp $
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

#include "EventLoop.h"

EventLoop::EventLoop() : errcount(0), last_loop(false), timeService(NULL)
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
EventLoop::registerEngine(AsyncEngine *engine)
{
    engines.push_back(engine);
}

void
EventLoop::run()
{
    prepareToRun();

    while (!runOnce())

        ;
}

bool
EventLoop::runOnce()
{
    bool result = true;
    bool error = false;
    int loop_delay = 10; /* 10 ms default delay */

    for (engine_vector::iterator i = engines.begin();
            i != engines.end(); ++i) {
        int requested_delay;
        /* special case the last engine */

        if (i - engines.end() != -1)
            requested_delay = (*i)->checkEvents(0);
        else /* last engine gets the delay */
            requested_delay = (*i)->checkEvents(loop_delay);

        if (requested_delay < 0)
            switch (requested_delay) {

            case AsyncEngine::EVENT_IDLE:
                debugs(1, 9, "Engine " << *i << " is idle.");
                break;

            case AsyncEngine::EVENT_ERROR:
                result = false;
                error = true;
                break;

            default:
                fatal_dump("unknown AsyncEngine result");
            }
        else if (requested_delay < loop_delay) {
            loop_delay = requested_delay;
            result = false;
        }
    }

    if (timeService != NULL)
        timeService->tick();

    for (dispatcher_vector::iterator i = dispatchers.begin();
            i != dispatchers.end(); ++i)
        if ((*i)->dispatch())
            result = false;

    if (error) {
        ++errcount;
        debugs(1, 0, "Select loop Error. Retry " << errcount);
    } else
        errcount = 0;

    if (errcount == 10)
        return true;

    if (last_loop)
        return true;

    return result;
}

void
EventLoop::setTimeService(TimeEngine *engine)
{
    timeService = engine;
}

void
EventLoop::stop()
{
    last_loop = true;
}
