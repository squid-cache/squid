/*
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

#ifndef SQUID_EVENTLOOP_H
#define SQUID_EVENTLOOP_H

#include "base/Vector.h"

#define EVENT_LOOP_TIMEOUT	1000 /* 1s timeout */

class AsyncEngine;
class TimeEngine;

/** An event loop. An event loop is the core inner loop of squid.
 * The event loop can be run until exit, or once. After it finishes control
 * returns to the caller. If desired it can be run again.
 \par
 * The event loop cannot be run once it is running until it has finished.
 */
class EventLoop
{

public:
    EventLoop();

    /** register an async engine which will be given the opportunity to perform
     * in-main-thread tasks each event loop.
     */
    void registerEngine(AsyncEngine *engine);

    /** start the event loop running. The loop will run until it is stopped by
     * calling stop(), or when the loop is completely idle - nothing
     * dispatched in a loop, and all engines idle.
     */
    void run();

    /** run the loop once. This may not complete all events! It should therefor
     * be used with care.
     * TODO: signal in runOnce whether or not the loop is over - IDLE vs OK vs
     * TIMEOUT?
     */
    bool runOnce();

    /** set the primary async engine. The primary async engine recieves the
     * lowest requested timeout gathered from the other engines each loop.
     * (There is a default of 10ms if all engines are idle or request higher
     * delays).
     * If no primary has been nominated, the last async engine added is
     * implicitly the default.
     */
    void setPrimaryEngine(AsyncEngine * engine);

    /** set the time service. There can be only one time service set at any
     * time. The time service is invoked on each loop
     */
    void setTimeService(TimeEngine *engine);

    /** stop the event loop - it will finish the current loop and then return to the
     * caller of run().
     */
    void stop();

    int errcount;

private:
    /** setup state variables prior to running */
    void prepareToRun();

    /** check an individual engine */
    void checkEngine(AsyncEngine * engine, bool const primary);

    /** dispatch calls and events scheduled during checkEngine() */
    bool dispatchCalls();

    bool last_loop;
    typedef Vector<AsyncEngine *> engine_vector;
    engine_vector engines;
    TimeEngine * timeService;
    AsyncEngine * primaryEngine;
    int loop_delay; /**< the delay to be given to the primary engine */
    bool error; /**< has an error occured in this loop */
    bool runOnceResult; /**< the result from runOnce */
};

#endif /* SQUID_EVENTLOOP_H */
