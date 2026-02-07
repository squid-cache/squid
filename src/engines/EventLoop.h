/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_EVENTLOOP_H
#define SQUID_SRC_EVENTLOOP_H

#include "engines/AsyncEngine.h"
#include "time/forward.h"

#include <vector>

#define EVENT_LOOP_TIMEOUT  1000 /* 1s timeout */

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

    /**
     * Register an engine which will be given the opportunity to perform
     * in-main-thread tasks each event loop.
     */
    void registerEngine(AsyncEngine *);

    /**
     * Start this event loop running. The loop will run until it is stopped by
     * calling stop(), or when the loop is completely idle - nothing
     * dispatched in a loop, and all engines idle.
     */
    void run();

    /**
     * This may not complete all events! use with care.
     * TODO: signal in runOnce whether or not the loop is over - IDLE vs OK vs
     * TIMEOUT?
     */
    bool runOnce();

    /**
     * The primary async engine receives the lowest requested timeout gathered
     * from the other engines each loop.
     * There is a default of 10ms if all engines are idle or request higher
     * delays.
     *
     * If no primary has been nominated, the last async engine added is
     * implicitly the default.
     */
    void setPrimaryEngine(AsyncEngine *);

    /**
     * Nominate a time service to invoke on each loop.
     * There can be only one engine acting as time service.
     */
    void setTimeService(Time::Engine *);

    /// Finish the current loop and then return to the caller of run().
    void stop();

    int errcount;

    /**
     * The [main program] loop running now; may be nil.
     * For simplicity, we assume there are no concurrent loops
     */
    static EventLoop *Running;

private:
    /** setup state variables prior to running */
    void prepareToRun();

    /** check an individual engine */
    void checkEngine(AsyncEngine *, const bool primary);

    /** dispatch calls and events scheduled during checkEngine() */
    bool dispatchCalls();

    bool last_loop;
    typedef std::vector<AsyncEngine *> engine_vector;
    engine_vector engines;
    Time::Engine *timeService;
    AsyncEngine * primaryEngine;

    /// the delay to be given to the primary engine
    int loop_delay;

    /// has an error occurred in this loop
    bool error;

    /// the result from runOnce
    bool runOnceResult;
};

#endif /* SQUID_SRC_ENGINES_EVENTLOOP_H */
