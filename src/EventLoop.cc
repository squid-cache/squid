/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 01    Main Loop */

#include "squid.h"
#include "AsyncEngine.h"
#include "base/AsyncCallQueue.h"
#include "Debug.h"
#include "EventLoop.h"
#include "fatal.h"
#include "SquidTime.h"

EventLoop *EventLoop::Running = NULL;

EventLoop::EventLoop() : errcount(0), last_loop(false), timeService(NULL),
    primaryEngine(NULL),
    loop_delay(EVENT_LOOP_TIMEOUT),
    error(false),
    runOnceResult(false)
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
EventLoop::registerEngine(AsyncEngine *engine)
{
    engines.push_back(engine);
}

void
EventLoop::run()
{
    prepareToRun();

    assert(!Running);
    Running = this;

    while (!runOnce());

    Running = NULL;
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
        typedef engine_vector::iterator EVI;
        for (EVI i = engines.begin(); i != engines.end(); ++i) {
            if (*i != waitingEngine)
                checkEngine(*i, false);
        }

        // dispatch calls accumulated so far
        sawActivity = dispatchCalls();
        if (sawActivity)
            runOnceResult = false;
    } while (sawActivity);

    if (waitingEngine != NULL)
        checkEngine(waitingEngine, true);

    if (timeService != NULL)
        timeService->tick();

    // dispatch calls scheduled by waitingEngine and timeService
    sawActivity = dispatchCalls();
    if (sawActivity)
        runOnceResult = false;

    if (error) {
        ++errcount;
        debugs(1, DBG_CRITICAL, "Select loop Error. Retry " << errcount);
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
EventLoop::dispatchCalls()
{
    bool dispatchedSome = AsyncCallQueue::Instance().fire();
    return dispatchedSome;
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

