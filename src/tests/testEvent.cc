/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/AsyncCallQueue.h"
#include "compat/cppunit.h"
#include "event.h"
#include "MemBuf.h"
#include "unitTestMain.h"

#include <sstream>

/*
 * test the event module.
 */

class TestEvent : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestEvent);
    CPPUNIT_TEST(testCreate);
    CPPUNIT_TEST(testDump);
    CPPUNIT_TEST(testFind);
    CPPUNIT_TEST(testCheckEvents);
    CPPUNIT_TEST(testSingleton);
    CPPUNIT_TEST(testCancel);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testCreate();
    void testDump();
    void testFind();
    void testCheckEvents();
    void testSingleton();
    void testCancel();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestEvent );

/*
 * Test creating a Scheduler
 */
void
TestEvent::testCreate()
{
    EventScheduler scheduler = EventScheduler();
}

/// Helper for tests - an event which records the number of calls it received
class CalledEvent
{
public:
    static void Handler(void *data) {
        static_cast<CalledEvent *>(data)->calls++;
    }

    int calls = 0;
};

/* submit two callbacks, and cancel one, then dispatch and only the other should run.
 */
void
TestEvent::testCancel()
{
    EventScheduler scheduler;
    CalledEvent event;
    CalledEvent event_to_cancel;
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event_to_cancel, 0, 0, false);
    scheduler.cancel(CalledEvent::Handler, &event_to_cancel);
    scheduler.checkEvents(0);
    AsyncCallQueue::Instance().fire();
    CPPUNIT_ASSERT_EQUAL(1, event.calls);
    CPPUNIT_ASSERT_EQUAL(0, event_to_cancel.calls);
}

// submit two callbacks, and then dump the queue.
void
TestEvent::testDump()
{
    EventScheduler scheduler;
    CalledEvent event;
    CalledEvent event2;

    scheduler.schedule("last event", CalledEvent::Handler, &event, 0, 0, false);

    /* schedule and dispatch to set the last run event */
    scheduler.checkEvents(0);
    AsyncCallQueue::Instance().fire();
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event2, 0, 0, false);

    std::ostringstream os;
    scheduler.dump(os);

    const std::string expected("last event to run: last event\n"
                               "scheduled events:\n"
                               "  - operation: test event\n"
                               "    secs to next execution: 0\n"
                               "    weight: 0\n"
                               "    callback valid: N/A\n"
                               "  - operation: test event2\n"
                               "    secs to next execution: 0\n"
                               "    weight: 0\n"
                               "    callback valid: N/A\n");

    CPPUNIT_ASSERT_EQUAL(expected, os.str());
}

/* submit two callbacks, and find the right one.
 */
void
TestEvent::testFind()
{
    EventScheduler scheduler;
    CalledEvent event;
    CalledEvent event_to_find;
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event_to_find, 0, 0, false);
    CPPUNIT_ASSERT_EQUAL(true, scheduler.find(CalledEvent::Handler, &event_to_find));
}

/* do a trivial test of invoking callbacks */
void
TestEvent::testCheckEvents()
{
    EventScheduler scheduler;
    CalledEvent event;
    /* with no events, its an idle engine */
    CPPUNIT_ASSERT_EQUAL(int(AsyncEngine::EVENT_IDLE), scheduler.checkEvents(0));
    /* event running now gets will get sent to the dispatcher and the
     * engine becomes idle.
     */
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    CPPUNIT_ASSERT_EQUAL(int(AsyncEngine::EVENT_IDLE), scheduler.checkEvents(0));
    AsyncCallQueue::Instance().fire();
    /* event running later results in  a delay of the time till it runs */
    scheduler.schedule("test event", CalledEvent::Handler, &event, 2, 0, false);
    CPPUNIT_ASSERT_EQUAL(2000, scheduler.checkEvents(0));
    AsyncCallQueue::Instance().fire();
    CPPUNIT_ASSERT_EQUAL(1, event.calls);
}

/* for convenience we have a singleton scheduler */
void
TestEvent::testSingleton()
{
    EventScheduler *scheduler = dynamic_cast<EventScheduler *>(EventScheduler::GetInstance());
    CPPUNIT_ASSERT(nullptr != scheduler);
}

/// customizes our test setup
class MyTestProgram: public TestProgram
{
public:
    /* TestProgram API */
    void startup() override { Mem::Init(); }
};

int
main(int argc, char *argv[])
{
    return MyTestProgram().run(argc, argv);
}

