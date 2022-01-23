/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include <cppunit/TestAssert.h>

#include "base/AsyncCallQueue.h"
#include "CapturingStoreEntry.h"
#include "event.h"
#include "stat.h"
#include "testEvent.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testEvent );

/* init legacy static-initialized modules */

void
testEvent::setUp()
{
    Mem::Init();
    statInit();
}

/*
 * Test creating a Scheduler
 */
void
testEvent::testCreate()
{
    EventScheduler scheduler = EventScheduler();
}

/* Helper for tests - an event which records the number of calls it received. */

struct CalledEvent {
    CalledEvent() : calls(0) {}

    static void Handler(void *data) {
        static_cast<CalledEvent *>(data)->calls++;
    }

    int calls;
};

/* submit two callbacks, and cancel one, then dispatch and only the other should run.
 */
void
testEvent::testCancel()
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

/* submit two callbacks, and then dump the queue.
 */
void
testEvent::testDump()
{
    EventScheduler scheduler;
    CalledEvent event;
    CalledEvent event2;
    CapturingStoreEntry * anEntry = new CapturingStoreEntry();
    String expect =  "Last event to run: last event\n"
                     "\n"
                     "Operation                \tNext Execution \tWeight\tCallback Valid?\n"
                     "test event               \t0.000 sec\t    0\t N/A\n"
                     "test event2              \t0.000 sec\t    0\t N/A\n";

    scheduler.schedule("last event", CalledEvent::Handler, &event, 0, 0, false);

    /* schedule and dispatch to set the last run event */
    scheduler.checkEvents(0);
    AsyncCallQueue::Instance().fire();
    scheduler.schedule("test event", CalledEvent::Handler, &event, 0, 0, false);
    scheduler.schedule("test event2", CalledEvent::Handler, &event2, 0, 0, false);
    scheduler.dump(anEntry);

    /* loop over the strings, showing exactly where they differ (if at all) */
    printf("Actual Text:\n");
    /* TODO: these should really be just [] lookups, but String doesn't have those here yet. */
    for ( unsigned int i = 0; i < anEntry->_appended_text.size(); ++i) {
        CPPUNIT_ASSERT( expect[i] );
        CPPUNIT_ASSERT( anEntry->_appended_text[i] );

        /* slight hack to make special chars visible */
        switch (anEntry->_appended_text[i]) {
        case '\t':
            printf("\\t");
            break;
        default:
            printf("%c", anEntry->_appended_text[i] );
        }
        /* make this an int comparison, so that we can see the ASCII code at failure */
        CPPUNIT_ASSERT_EQUAL( (int)(expect[i]), (int)anEntry->_appended_text[i] );
    }
    printf("\n");
    CPPUNIT_ASSERT_EQUAL( expect, anEntry->_appended_text);

    /* cleanup */
    delete anEntry;
}

/* submit two callbacks, and find the right one.
 */
void
testEvent::testFind()
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
testEvent::testCheckEvents()
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
testEvent::testSingleton()
{
    EventScheduler *scheduler = dynamic_cast<EventScheduler *>(EventScheduler::GetInstance());
    CPPUNIT_ASSERT(NULL != scheduler);
}

