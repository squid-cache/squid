
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

#ifndef SQUID_ASYNCENGINE_H
#define SQUID_ASYNCENGINE_H

/* Abstract interface for async engines which an event loop can utilise.
 *
 * Some implementations will be truely async, others like the event engine
 * will be pseudo async.
 */

class AsyncEngine
{

public:
    /* error codes returned from checkEvents. If the return value is not
     * negative, then it is the requested delay until the next call. If it is
     * negative, it is one of the following codes:
     */
    enum CheckError {
        /* this engine is completely idle: it has no pending events, and nothing
         * registered with it that can create events
         */
        EVENT_IDLE = -1,
        /* some error has occured in this engine */
        EVENT_ERROR = -2
    };

    virtual ~AsyncEngine() {}

    /* Check the engine for events. If there are events that have completed,
     * the engine should at this point hand them off to their dispatcher.
     * Engines that operate asynchronously - i.e. the DiskThreads engine -
     * should hand events off to their dispatcher as they arrive rather than
     * waiting for checkEvents to be called. Engines like poll and select should
     * use this call as the time to perform their checks with the OS for new
     * events.
     *
     * The return value is the status code of the event checking. If its a
     * non-negative value then it is used as hint for the minimum requested
     * time before checkEvents is called again. I.e. the event engine knows
     * how long it is until the next event will be scheduled - so it will
     * return that time (in milliseconds).
     *
     * The timeout value is a requested timeout for this engine - the engine
     * should not block for more than this period. (If it takes longer than the
     * timeout to do actual checks thats fine though undesirable).
     */
    virtual int checkEvents(int timeout) = 0;
};

#endif /* SQUID_ASYNCENGINE_H */
