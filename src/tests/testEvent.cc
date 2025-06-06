/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
    const char *expected = "Last event to run: last event\n"
                           "\n"
                           "Operation                \tNext Execution \tWeight\tCallback Valid?\n"
                           "test event               \t0.000 sec\t    0\t N/A\n"
                           "test event2              \t0.000 sec\t    0\t N/A\n";
    MemBuf expect;
    expect.init();
    expect.append(expected, strlen(expected));

    scheduler.schedule("last event", CalledEvent::Handler, &event, 0, 0, false);

    /* schedule and dispatch to set the last run event */
    scheduler.checkEvents(0);
    AsyncCallQueue::Instance().fire();
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event2, 0, 0, false);

    MemBuf result;
    result.init();
    scheduler.dump(&result);

    /* loop over the strings, showing exactly where they differ (if at all) */
    printf("Actual Text:\n");
    /* TODO: these should really be just [] lookups, but String doesn't have those here yet. */
    for (size_t i = 0; i < size_t(result.contentSize()); ++i) {
        CPPUNIT_ASSERT(expect.content()[i]);
        CPPUNIT_ASSERT(result.content()[i]);

        /* slight hack to make special chars visible */
        switch (result.content()[i]) {
        case '\t':
            printf("\\t");
            break;
        default:
            printf("%c", result.content()[i]);
        }
        /* make this an int comparison, so that we can see the ASCII code at failure */
        CPPUNIT_ASSERT_EQUAL(int(expect.content()[i]), int(result.content()[i]));
    }
    printf("\n");
    CPPUNIT_ASSERT_EQUAL(expect.contentSize(), result.contentSize());
    CPPUNIT_ASSERT(strcmp(expect.content(), result.content()) == 0);
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

