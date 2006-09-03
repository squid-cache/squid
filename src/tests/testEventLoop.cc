#include "squid.h"
#include <cppunit/TestAssert.h>

#include "AsyncEngine.h"
#include "CompletionDispatcher.h"
#include "Mem.h"
#include "testEventLoop.h"
#include "EventLoop.h"
#include "event.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testEventLoop );

/* stub functions to link successfully */
void
shut_down(int)
{}

/* end stubs */

/* init legacy static-initialized modules */

struct Initer
{
    Initer()
    {
        Mem::Init();
        statInit();
    }
};

static Initer ensure_mempools;

/*
 * Test creating a EventLoop
 */
void
testEventLoop::testCreate()
{
    EventLoop();
}


/*
 * Running the loop once is useful for integration with other loops, such as 
 * migrating to it in incrementally.
 *
 * This test works by having a custom dispatcher and engine which record how
 * many times they are called.
 */

class RecordDispatcher : public CompletionDispatcher
{

public:
    int calls;
    RecordDispatcher(): calls(0)
    {}

    bool dispatch()
    {
        ++calls;
        /* claim we dispatched calls to be useful for the testStopOnIdle test.
         */
        return true;
    }
};

class RecordingEngine : public AsyncEngine
{

public:
    int calls;
    int lasttimeout;
    int return_timeout;
    RecordingEngine(int return_timeout=0): calls(0), lasttimeout(0),
            return_timeout(return_timeout)
          {}

          virtual int checkEvents(int timeout)
          {
              ++calls;
              lasttimeout = timeout;
              return return_timeout;
          }
      };

void
testEventLoop::testRunOnce()
{
    EventLoop theLoop;
    RecordDispatcher dispatcher;
    theLoop.registerDispatcher(&dispatcher);
    RecordingEngine engine;
    theLoop.registerEngine(&engine);
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(1, dispatcher.calls);
    CPPUNIT_ASSERT_EQUAL(1, engine.calls);
}

/*
 * completion dispatchers registered with the event loop are invoked by the
 * event loop.
 *
 * This test works by having a customer dispatcher which shuts the loop down
 * once its been invoked twice.
 *
 * It also tests that loop.run() and loop.stop() work, because if they dont
 * work, this test will either hang, or fail.
 */

class ShutdownDispatcher : public CompletionDispatcher
{

public:
    EventLoop &theLoop;
    int calls;
    ShutdownDispatcher(EventLoop & theLoop):theLoop(theLoop), calls(0)
    {}

    bool dispatch()
    {
        if (++calls == 2)
            theLoop.stop();

        return true;
    }
};

void
testEventLoop::testRegisterDispatcher()
{
    EventLoop theLoop;
    ShutdownDispatcher testDispatcher(theLoop);
    theLoop.registerDispatcher(&testDispatcher);
    theLoop.run();
    /* we should get two calls because the test dispatched returns true from
     * dispatch(), and calls stop on the second call.
     */
    CPPUNIT_ASSERT_EQUAL(2, testDispatcher.calls);
}

/* test that a registered async engine is invoked on each loop run
 * we do this with an intstrumented async engine.
 */
void
testEventLoop::testRegisterEngine()
{
    EventLoop theLoop;
    ShutdownDispatcher testDispatcher(theLoop);
    theLoop.registerDispatcher(&testDispatcher);
    RecordingEngine testEngine;
    theLoop.registerEngine(&testEngine);
    theLoop.run();
    CPPUNIT_ASSERT_EQUAL(2, testEngine.calls);
}

/* each AsyncEngine needs to be given a timeout. We want one engine in each
 * loop to be given the timeout value - and the rest to have a timeout of 0.
 * The last registered engine should be given this timeout, which will mean
 * that we dont block in the loop until the last engine. This will allow for
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
    CPPUNIT_ASSERT_EQUAL(0, engineOne.lasttimeout);
    CPPUNIT_ASSERT_EQUAL(5, engineTwo.lasttimeout);
}

/* An event loop with all idle engines, and nothing dispatched in a run should
 * automatically quit. The runOnce call should return True when the loop is
 * entirely idle to make it easy for people running the loop by hand.
 */
void
testEventLoop::testStopOnIdle()
{
    EventLoop theLoop;
    /* trivial case - no dispatchers or engines, should quit immediately */
    CPPUNIT_ASSERT_EQUAL(true, theLoop.runOnce());
    theLoop.run();
    /* add a dispatcher with nothing to dispatch - use an EventDispatcher as its
     * sufficient and handy
     */
    EventDispatcher dispatcher;
    theLoop.registerDispatcher(&dispatcher);
    CPPUNIT_ASSERT_EQUAL(true, theLoop.runOnce());
    theLoop.run();
    /* add an engine which is idle.
     */
    RecordingEngine engine(AsyncEngine::EVENT_IDLE);
    theLoop.registerEngine(&engine);
    CPPUNIT_ASSERT_EQUAL(true, theLoop.runOnce());
    CPPUNIT_ASSERT_EQUAL(1, engine.calls);
    theLoop.run();
    CPPUNIT_ASSERT_EQUAL(2, engine.calls);
    /* add an engine which is suffering errors. This should result in 10
     * loops until the loop stops - because thats the error retry amount
     */
    RecordingEngine failing_engine(AsyncEngine::EVENT_ERROR);
    theLoop.registerEngine(&failing_engine);
    CPPUNIT_ASSERT_EQUAL(false, theLoop.runOnce());
    CPPUNIT_ASSERT_EQUAL(1, failing_engine.calls);
    theLoop.run();
    /* run resets the error count ... */
    CPPUNIT_ASSERT_EQUAL(11, failing_engine.calls);

    /* an engine that asks for a timeout should not be detected as idle:
     * use runOnce which should return false
     */
    theLoop = EventLoop();
    RecordingEngine non_idle_engine(1000);
    theLoop.registerEngine(&non_idle_engine);
    CPPUNIT_ASSERT_EQUAL(false, theLoop.runOnce());
}

/* An event loop has a time service which is like an async engine but never
 * generates events and there can only be one such service.
 */

class StubTime : public TimeEngine
{

public:
    StubTime() : calls(0) {}

    int calls;
    void tick()
    {
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
    CPPUNIT_ASSERT_EQUAL(10, first_engine.lasttimeout);
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
