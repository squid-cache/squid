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
    CPPUNIT_TEST(testFrequentUpdates);
    CPPUNIT_TEST(testNearlyFullRotation);
    CPPUNIT_TEST(testTimeChanges);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testFrequentUpdates();
    void testNearlyFullRotation();
    void testTimeChanges();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestFadingCounter);

void
TestFadingCounter::testFrequentUpdates()
{
    FadingCounter counter;
    current_dtime = 100;
    counter.configure(10);
    // Half-second updates span twenty updates per ten-slot window.
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
    current_dtime = 110.25; // same slot index, one turn later
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1));
}

void
TestFadingCounter::testTimeChanges()
{
    FadingCounter counter;
    current_dtime = 100;
    counter.configure(10);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime += 10;
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1));
    current_dtime -= 1;
    CPPUNIT_ASSERT_EQUAL(3, counter.count(3));
    counter.configure(-1);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    current_dtime += 100;
    CPPUNIT_ASSERT_EQUAL(3, counter.count(1));
    counter.configure(0);
    CPPUNIT_ASSERT_EQUAL(2, counter.count(2));
    CPPUNIT_ASSERT_EQUAL(1, counter.count(1));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

