
/*
 * $Id: EventLoop.h,v 1.1 2006/08/07 02:28:22 robertc Exp $
 *
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

#include "squid.h"
#include "Array.h"
#include "CompletionDispatcher.h"

/* An event loop. An event loop is the core inner loop of squid.
 * The event loop can be run until exit, or once. After it finishes control
 * returns to the caller. If desired it can be run again.
 *
 * The event loop cannot be run once it is running until it has finished.
 */

class EventLoop
{

public:
    EventLoop();
    /* register an event dispatcher to be invoked on each event loop. */
    void registerDispatcher(CompletionDispatcher *dispatcher);
    /* start the event loop running */
    void run();
    /* run the loop once. This may not complete all events! It should therefor
     * be used with care.
     * TODO: signal in runOnce whether or not the loop is over - IDLE vs OK vs
     * TIMEOUT?
     */
    void runOnce();
    /* stop the event loop - it will finish the current loop and then return to the
     * caller of run().
     */
    void stop();

private:
    /* setup state variables prior to running */
    void prepareToRun();
    int errcount;
    bool last_loop;
    typedef Vector<CompletionDispatcher *> dispatcher_vector;
    dispatcher_vector dispatchers;
};


#endif /* SQUID_EVENTLOOP_H */
