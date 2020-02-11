/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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
        /* some error has occurred in this engine */
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

