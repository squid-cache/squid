/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 01    Main Loop */

#include "squid.h"
#include "base/AsyncCallQueue.h"
#include "debug/Stream.h"
#include "engines/EventLoop.h"
#include "fatal.h"
#include "time/Engine.h"

EventLoop *EventLoop::Running = nullptr;

void
EventLoop::checkEngine(AsyncEngine * const engine, const bool primary)
{
    auto requested_delay = engine->checkEvents(primary ? loop_delay : 0);

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
EventLoop::run()
{
    prepareToRun();

    assert(!Running);
    Running = this;

    while (!runOnce());

    Running = nullptr;
}

bool
EventLoop::runOnce()
{
    bool sawActivity = false;
    runOnceResult = true;
    error = false;
    loop_delay = EVENT_LOOP_TIMEOUT;

    AsyncEngine *waitingEngine = primaryEngine;
    if (!waitingEngine && !engines.empty())
        waitingEngine = engines.back();

    do {
        // generate calls and events
        for (auto engine : engines) {
            if (engine != waitingEngine)
                checkEngine(engine, false);
        }

        // dispatch calls accumulated so far
        sawActivity = dispatchCalls();
        if (sawActivity)
            runOnceResult = false;
    } while (sawActivity);

    if (waitingEngine != nullptr)
        checkEngine(waitingEngine, true);

    if (timeService != nullptr)
        timeService->tick();

    // dispatch calls scheduled by waitingEngine and timeService
    sawActivity = dispatchCalls();
    if (sawActivity)
        runOnceResult = false;

    if (error) {
        ++errcount;
        debugs(1, DBG_CRITICAL, "ERROR: Select loop Error. Retry " << errcount);
    } else
        errcount = 0;

    if (errcount == 10)
        return true;

    if (last_loop)
        return true;

    return runOnceResult;
}

// dispatches calls accumulated during checkEngine()
bool
EventLoop::dispatchCalls() const
{
    bool dispatchedSome = AsyncCallQueue::Instance().fire();
    return dispatchedSome;
}

void
EventLoop::setPrimaryEngine(AsyncEngine * const e)
{
    for (auto engine : engines) {
        if (engine == e) {
            primaryEngine = engine;
            return;
        }
    }

    fatal("EventLoop::setPrimaryEngine: No such engine!.");
}
