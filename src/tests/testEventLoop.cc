/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AsyncEngine.h"
#include "EventLoop.h"
#include "tests/testEventLoop.h"
#include "time/Engine.h"
#include "unitTestMain.h"

#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( testEventLoop );

void
testEventLoop::testCreate()
{
    EventLoop();
}

class RecordingEngine : public AsyncEngine
{
public:
    RecordingEngine(int aTimeout = 0) : return_timeout(aTimeout) {}

    int checkEvents(int timeout) override {
        ++calls;
        lasttimeout = timeout;
        return return_timeout;
    }

    int calls = 0;
    int lasttimeout = 0;
    int return_timeout = 0;
};

/* test that a registered async engine is invoked on each loop run
 * we do this with an instrumented async engine.
 */
void
testEventLoop::testRunOnce()
{
    {
        /* trivial case - no engine, should quit immediately */
        EventLoop theLoop;
        CPPUNIT_ASSERT_EQUAL(true, theLoop.runOnce());
    }

    {
        /* An event loop with all idle engines, and nothing dispatched in a run should
         * automatically quit. The runOnce call should return True when the loop is
         * entirely idle to make it easy for people running the loop by hand.
         */
        EventLoop theLoop;
        RecordingEngine engine(AsyncEngine::EVENT_IDLE);
        theLoop.registerEngine(&engine);
        CPPUNIT_ASSERT_EQUAL(true, theLoop.runOnce());
        CPPUNIT_ASSERT_EQUAL(1, engine.calls);
        theLoop.run();
        CPPUNIT_ASSERT_EQUAL(2, engine.calls);
    }

    {
        /* an engine that asks for a timeout should not be detected as idle:
         * use runOnce which should return false
         */
        EventLoop theLoop;
        RecordingEngine engine;
        theLoop.registerEngine(&engine);
        CPPUNIT_ASSERT_EQUAL(false, theLoop.runOnce());
        CPPUNIT_ASSERT_EQUAL(1, engine.calls);
        CPPUNIT_ASSERT_EQUAL(EVENT_LOOP_TIMEOUT, engine.lasttimeout);
    }
}

/* each AsyncEngine needs to be given a timeout. We want one engine in each
 * loop to be given the timeout value - and the rest to have a timeout of 0.
 * The last registered engine should be given this timeout, which will mean
 * that we do not block in the loop until the last engine. This will allow for
 * dynamic introduction and removal of engines, as long as the last engine
 * is one which can do a os call rather than busy waiting.
 *
 * So - we want the timeout hints returned from the earlier engines to be
 * tracked, and the lowest non-negative value given to the last engine.
 */
void
testEventLoop::testEngineTimeout()
{
    EventLoop theLoop;
    RecordingEngine engineOne(5);
    RecordingEngine engineTwo;
    theLoop.registerEngine(&engineOne);
    theLoop.registerEngine(&engineTwo);
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(1, engineOne.calls);
    CPPUNIT_ASSERT_EQUAL(0, engineOne.lasttimeout);
    CPPUNIT_ASSERT_EQUAL(1, engineTwo.calls);
    CPPUNIT_ASSERT_EQUAL(5, engineTwo.lasttimeout);
}

/* An engine which is suffering errors. This should result in 10
 * loops until the loop stops - because that's the error retry amount
 * hard-coded into EventLoop::runOnce()
 */
void
testEventLoop::testEngineErrors()
{
    EventLoop theLoop;
    RecordingEngine failing_engine(AsyncEngine::EVENT_ERROR);
    theLoop.registerEngine(&failing_engine);
    CPPUNIT_ASSERT_EQUAL(false, theLoop.runOnce());
    CPPUNIT_ASSERT_EQUAL(1, failing_engine.calls);
    CPPUNIT_ASSERT_EQUAL(1, theLoop.errcount);
    theLoop.run();
    /* run resets the error count ... */
    CPPUNIT_ASSERT_EQUAL(10, theLoop.errcount);
    CPPUNIT_ASSERT_EQUAL(11, failing_engine.calls);
}

/* An event loop has a time service which is like an async engine but never
 * generates events and there can only be one such service.
 */
class StubTime : public Time::Engine
{
public:
    StubTime() : calls(0) {}

    int calls;
    void tick() override {
        ++calls;
    }
};

void
testEventLoop::testSetTimeService()
{
    EventLoop theLoop;
    StubTime myTime;
    /* the loop will not error without a time service */
    theLoop.runOnce();
    /* we can set the time service */
    theLoop.setTimeService(&myTime);
    /* it invokes our tick() call */
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(1, myTime.calls);
    /* it invokes our tick() call again */
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(2, myTime.calls);
}

/* one async engine is the primary engine - the engine that is allowed to block.
 * this defaults to the last added one, but can be explicitly nominated
 */
void
testEventLoop::testSetPrimaryEngine()
{
    EventLoop theLoop;
    RecordingEngine first_engine(10);
    RecordingEngine second_engine(10);
    /* one engine - gets a timeout */
    theLoop.registerEngine(&first_engine);
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(EVENT_LOOP_TIMEOUT, first_engine.lasttimeout);
    /* two engines - the second gets the timeout */
    theLoop.registerEngine(&second_engine);
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(0, first_engine.lasttimeout);
    CPPUNIT_ASSERT_EQUAL(10, second_engine.lasttimeout);
    /* set the first engine to be primary explicitly  and now gets the timeout */
    theLoop.setPrimaryEngine(&first_engine);
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(10, first_engine.lasttimeout);
    CPPUNIT_ASSERT_EQUAL(0, second_engine.lasttimeout);
}

