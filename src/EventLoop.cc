
/*
 * $Id: EventLoop.cc,v 1.3 2006/08/19 12:31:21 robertc Exp $
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

EventLoop::EventLoop() : errcount(0), last_loop(false), timeService(NULL),
        primaryEngine(NULL)
{}

void
EventLoop::checkEngine(AsyncEngine * engine, bool const primary)
{
    int requested_delay;

    if (!primary)
        requested_delay = engine->checkEvents(0);
    else
        requested_delay = engine->checkEvents(loop_delay);

    if (requested_delay < 0)
        switch (requested_delay) {

        case AsyncEngine::EVENT_IDLE:
            debugs(1, 9, "Engine " << engine << " is idle.");
            break;

        case AsyncEngine::EVENT_ERROR:
            runOnceResult = false;
            error = true;
            break;

        default:
            fatal_dump("unknown AsyncEngine result");
        }
    else {
        /* not idle or error */
        runOnceResult = false;

        if (requested_delay < loop_delay)
            loop_delay = requested_delay;
    }
}

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
    runOnceResult = true;
    error = false;
    loop_delay = 10; /* 10 ms default delay */

    for (engine_vector::iterator i = engines.begin();
            i != engines.end(); ++i) {
        /* check the primary outside the loop */

        if (*i == primaryEngine)
            continue;

        /* special case the last engine to be primary */
        checkEngine(*i, primaryEngine == NULL && (i - engines.end() == -1));
    }

    if (primaryEngine != NULL)
        checkEngine(primaryEngine, true);

    if (timeService != NULL)
        timeService->tick();

    for (dispatcher_vector::iterator i = dispatchers.begin();
            i != dispatchers.end(); ++i)
        if ((*i)->dispatch())
            runOnceResult = false;

    if (error) {
        ++errcount;
        debugs(1, 0, "Select loop Error. Retry " << errcount);
    } else
        errcount = 0;

    if (errcount == 10)
        return true;

    if (last_loop)
        return true;

    return runOnceResult;
}

void
EventLoop::setPrimaryEngine(AsyncEngine * engine)
{
    for (engine_vector::iterator i = engines.begin();
            i != engines.end(); ++i)
        if (*i == engine) {
            primaryEngine = engine;
            return;
        }

    fatal("EventLoop::setPrimaryEngine: No such engine!.");
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
