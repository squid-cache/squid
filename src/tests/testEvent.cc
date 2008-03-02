#include "squid.h"
#include <cppunit/TestAssert.h>

#include "CapturingStoreEntry.h"
#include "CompletionDispatcher.h"
#include "Mem.h"
#include "testEvent.h"
#include "event.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testEvent );

/* stub functions to link successfully */
void
shut_down(int)
{}

void
reconfigure(int)
{}

/* end stubs */

/* init legacy static-initialized modules */

void
testEvent::setUp()
{
    Mem::Init();
    statInit();
}

/*
 * Test creating a EventDispatcher and Scheduler
 */
void
testEvent::testCreate()
{
    EventDispatcher dispatcher = EventDispatcher();
    EventScheduler scheduler = EventScheduler(&dispatcher);
}


/* Helper for tests - an event which records the number of calls it received. */

struct CalledEvent
{
    CalledEvent() : calls(0) {}

    static void Handler(void *data)
    {
        static_cast<CalledEvent *>(data)->calls++;
    }

    int calls;
};

/* do a trivial test of invoking callbacks */
void
testEvent::testDispatch()
{
    EventDispatcher dispatcher;
    CalledEvent event;
    dispatcher.add(new ev_entry("test event", CalledEvent::Handler, &event, 0, 0, false));
    /* return true when an event is dispatched */
    CPPUNIT_ASSERT_EQUAL(true, dispatcher.dispatch());
    /* return false when none were dispatched */
    CPPUNIT_ASSERT_EQUAL(false, dispatcher.dispatch());
    CPPUNIT_ASSERT_EQUAL(1, event.calls);
}

/* submit two callbacks, and cancel one, then dispatch and only the other should run.
 */
void
testEvent::testCancel()
{
    EventDispatcher dispatcher;
    EventScheduler scheduler(&dispatcher);
    CalledEvent event;
    CalledEvent event_to_cancel;
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event_to_cancel, 0, 0, false);
    scheduler.cancel(CalledEvent::Handler, &event_to_cancel);
    scheduler.checkEvents(0);
    dispatcher.dispatch();
    CPPUNIT_ASSERT_EQUAL(1, event.calls);
    CPPUNIT_ASSERT_EQUAL(0, event_to_cancel.calls);
}

/* submit two callbacks, and then dump the queue.
 */
void
testEvent::testDump()
{
    EventDispatcher dispatcher;
    EventScheduler scheduler(&dispatcher);
    CalledEvent event;
    CalledEvent event2;
    CapturingStoreEntry * anEntry = new CapturingStoreEntry();
    scheduler.schedule("last event", CalledEvent::Handler, &event, 0, 0, false);
    /* schedule and dispatch to set the last run event */
    scheduler.checkEvents(0);
    dispatcher.dispatch();
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event2, 0, 0, false);
    scheduler.dump(anEntry);
    CPPUNIT_ASSERT_EQUAL(String(
                             "Last event to run: last event\n"
                             "\n"
                             "Operation\tNext Execution\tWeight\tCallback Valid?\n"
                             "test event\t0.000000 seconds\t0\tN/A\n"
                             "test event2\t0.000000 seconds\t0\tN/A\n"
                         ), anEntry->_appended_text);
    delete anEntry;
}

/* submit two callbacks, and find the right one.
 */
void
testEvent::testFind()
{
    EventDispatcher dispatcher;
    EventScheduler scheduler(&dispatcher);
    CalledEvent event;
    CalledEvent event_to_find;
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event_to_find, 0, 0, false);
    CPPUNIT_ASSERT_EQUAL(true, scheduler.find(CalledEvent::Handler, &event_to_find));
}

/* do a trivial test of invoking callbacks */
void
testEvent::testCheckEvents()
{
    EventDispatcher dispatcher;
    EventScheduler scheduler(&dispatcher);
    CalledEvent event;
    /* with no events, its an idle engine */
    CPPUNIT_ASSERT_EQUAL(int(AsyncEngine::EVENT_IDLE), scheduler.checkEvents(0));
    /* event running now gets will get sent to the dispatcher and the 
     * engine becomes idle.
     */
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    CPPUNIT_ASSERT_EQUAL(int(AsyncEngine::EVENT_IDLE), scheduler.checkEvents(0));
    dispatcher.dispatch();
    /* event running later results in  a delay of the time till it runs */
    scheduler.schedule("test event", CalledEvent::Handler, &event, 2, 0, false);
    CPPUNIT_ASSERT_EQUAL(2000, scheduler.checkEvents(0));
    dispatcher.dispatch();
    CPPUNIT_ASSERT_EQUAL(1, event.calls);
}

/* for convenience we have a singleton scheduler and dispatcher*/
void
testEvent::testSingleton()
{
    EventScheduler *scheduler = dynamic_cast<EventScheduler *>(EventScheduler::GetInstance());
    CPPUNIT_ASSERT(NULL != scheduler);
    EventDispatcher *dispatcher = dynamic_cast<EventDispatcher *>(EventDispatcher::GetInstance());
    CPPUNIT_ASSERT(NULL != dispatcher);
}
