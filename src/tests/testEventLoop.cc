#include "squid.h"
#include <cppunit/TestAssert.h>

#include "CompletionDispatcher.h"
#include "Mem.h"
#include "testEventLoop.h"
#include "EventLoop.h"


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
 * This test works by having a customer dispatcher which records how many times its
 * called.
 */

class RecordDispatcher : public CompletionDispatcher
{

public:
    int calls;
    RecordDispatcher(): calls(0)
    {}

    void dispatch()
    {
        ++calls;
    }
};

void
testEventLoop::testRunOnce()
{
    EventLoop theLoop;
    RecordDispatcher dispatcher;
    theLoop.registerDispatcher(&dispatcher);
    theLoop.runOnce();
    CPPUNIT_ASSERT_EQUAL(1, dispatcher.calls);
}

/*
 * completion dispatchers registered with the event loop are invoked by the event 
 * loop.
 *
 * This test works by having a customer dispatcher which shuts the loop down once its
 * been invoked twice.
 *
 * It also tests that loop.run() and loop.stop() work, because if they dont work,
 * this test will either hang, or fail.
 */

class ShutdownDispatcher : public CompletionDispatcher
{

public:
    EventLoop &theLoop;
    int calls;
    ShutdownDispatcher(EventLoop & theLoop):theLoop(theLoop), calls(0)
    {}

    void dispatch()
    {
        if (++calls == 2)
            theLoop.stop();
    }
};

void
testEventLoop::testRegisterDispatcher()
{
    EventLoop theLoop;
    ShutdownDispatcher testDispatcher(theLoop);
    theLoop.registerDispatcher(&testDispatcher);
    theLoop.run();
    CPPUNIT_ASSERT_EQUAL(2, testDispatcher.calls);
}
