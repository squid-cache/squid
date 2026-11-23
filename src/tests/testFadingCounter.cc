/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "FadingCounter.h"
#include "time/gadgets.h"
#include "unitTestMain.h"

class TestFadingCounter: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestFadingCounter);
    CPPUNIT_TEST(testConfigure);
    CPPUNIT_TEST(testFrequentUpdates);
    CPPUNIT_TEST(testNearlyFullRotation);
    CPPUNIT_TEST(testTimeReversal);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testConfigure();
    void testFrequentUpdates();
    void testNearlyFullRotation();
    void testTimeReversal();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestFadingCounter);

void
TestFadingCounter::testConfigure()
{
    FadingCounter counter;
    current_dtime = 100;

    // In fading mode, repeating the same configuration keeps recent events.
    counter.configure(10);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    counter.configure(10);
    CPPUNIT_ASSERT_EQUAL(3, counter.count(1));
    current_dtime += 10;
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1)); // previous events have expired

    // Switching to unlimited mode starts a fresh count that never expires.
    counter.configure(-1);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime += 100;
    CPPUNIT_ASSERT_EQUAL(3, counter.count(1));

    // A zero horizon reports only the events in the current call.
    counter.configure(0);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1));
}

void
TestFadingCounter::testFrequentUpdates()
{
    FadingCounter counter;
    current_dtime = 100;
    counter.configure(10);
    // Half-second updates add two events per slot. Once all slots are full,
    // reusing a slot drops both old events before adding the first new one.
    for (int i = 0; i < 60; ++i) {
        current_dtime = 100 + 0.5 * i;
        const int expected = i < 20 ? i + 1 : 19 + i % 2;
        CPPUNIT_ASSERT_EQUAL(expected, counter.count(1));
    }
}

void
TestFadingCounter::testNearlyFullRotation()
{
    FadingCounter counter;
    current_dtime = 100.75;
    counter.configure(10);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime = 100.875;
    CPPUNIT_ASSERT_EQUAL(3, counter.count(1));
    // Unlike the half-second steps above, this single step crosses all ten
    // slot boundaries in less than a horizon. Both endpoints use slot zero;
    // its three previous events must expire before adding the new event.
    current_dtime = 110.25;
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1));
}

void
TestFadingCounter::testTimeReversal()
{
    FadingCounter counter;
    current_dtime = 100;

    // A backward clock invalidates the ages of events in fading mode.
    counter.configure(10);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime -= 1;
    CPPUNIT_ASSERT_EQUAL(3, counter.count(3)); // only the three new events

    // Unlimited mode retains the two earlier events across the clock change.
    counter.configure(-1);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime -= 1;
    CPPUNIT_ASSERT_EQUAL(3, counter.count(1));

    // Zero-horizon mode ignores the two earlier events regardless of time.
    counter.configure(0);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime -= 1;
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

