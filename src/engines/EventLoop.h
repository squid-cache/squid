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

#if !defined(EVENT_LOOP_TIMEOUT)
/// Maximum timeout for loop checks of the primary engine, in milliseconds.
#define EVENT_LOOP_TIMEOUT  1000
#endif

/** An event loop. An event loop is the core inner loop of squid.
 * The event loop can be run until exit, or once. After it finishes control
 * returns to the caller. If desired it can be run again.
 \par
 * The event loop cannot be run once it is running until it has finished.
 */
class EventLoop
{
public:
    /**
     * Register an engine which will be given the opportunity to perform
     * in-main-thread tasks each event loop.
     */
    void registerEngine(AsyncEngine *e) { engines.emplace_back(e); }

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
     * There is a default of EVENT_LOOP_TIMEOUT if all engines are idle,
     * or request higher delays.
     *
     * If no primary has been nominated, the last async engine added is
     * implicitly the default.
     */
    void setPrimaryEngine(AsyncEngine * const);

    /**
     * Nominate a time service to invoke on each loop.
     * There can be only one engine acting as time service.
     */
    void setTimeService(Time::Engine * const e) { timeService = e; }

    /// Finish the current loop and then return to the caller of run().
    void stop() { last_loop = true; }

public:
    /**
     * The [main program] loop running now; may be nil.
     * For simplicity, we assume there are no concurrent loops
     */
    static EventLoop *Running;

    /// How many errors have occured so far in this iteration of the loop.
    int errcount = 0;

private:
    /** setup state variables prior to running */
    void prepareToRun();

    /** check an individual engine */
    void checkEngine(AsyncEngine * const, const bool primary);

    /** dispatch AsyncCalls scheduled during checkEngine() */
    bool dispatchCalls() const;

private:
    bool last_loop = false;
    std::vector<AsyncEngine *> engines;
    Time::Engine *timeService = nullptr;
    AsyncEngine *primaryEngine = nullptr;

    /// the delay to be given to the primary engine
    int loop_delay = EVENT_LOOP_TIMEOUT;

    /// has an error occurred in this loop
    bool error = false;

    /// the result from runOnce
    bool runOnceResult = false;
};

#endif /* SQUID_SRC_ENGINES_EVENTLOOP_H */
