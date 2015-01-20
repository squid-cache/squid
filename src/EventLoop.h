/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_EVENTLOOP_H
#define SQUID_EVENTLOOP_H

#include <vector>

#define EVENT_LOOP_TIMEOUT  1000 /* 1s timeout */

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

    /// the [main program] loop running now; may be nil
    /// for simplicity, we assume there are no concurrent loops
    static EventLoop *Running;

private:
    /** setup state variables prior to running */
    void prepareToRun();

    /** check an individual engine */
    void checkEngine(AsyncEngine * engine, bool const primary);

    /** dispatch calls and events scheduled during checkEngine() */
    bool dispatchCalls();

    bool last_loop;
    typedef std::vector<AsyncEngine *> engine_vector;
    engine_vector engines;
    TimeEngine * timeService;
    AsyncEngine * primaryEngine;
    int loop_delay; /**< the delay to be given to the primary engine */
    bool error; /**< has an error occured in this loop */
    bool runOnceResult; /**< the result from runOnce */
};

#endif /* SQUID_EVENTLOOP_H */

