/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "StatHist.h"
#include "unitTestMain.h"

class TestStatHist : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestStatHist);
    CPPUNIT_TEST(testStatHistBaseEquality);
    CPPUNIT_TEST(testStatHistBaseAssignment);
    CPPUNIT_TEST(testStatHistLog);
    CPPUNIT_TEST(testStatHistSum);
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testStatHistBaseEquality();
    void testStatHistBaseAssignment();
    void testStatHistLog();
    void testStatHistSum();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestStatHist );

typedef enum {
    ZERO, ONE, TWO, THREE, FOUR, FIVE
} number ;

class InspectingStatHist : public StatHist
{
public:
    bool operator==(const InspectingStatHist &);
    bins_type counter(double v) {
        return bins[findBin(v)];
    }
};

bool
InspectingStatHist::operator ==(const InspectingStatHist & src)
{
    assert(bins != nullptr && src.bins != nullptr); // TODO: remove after initializing bins at construction time
    if (capacity_ != src.capacity_ ||
            min_!=src.min_ ||
            max_!=src.max_ ||
            scale_!=src.scale_ ||
            val_in!=src.val_in ||
            val_out!=src.val_out)
        return false;
    return (memcmp(bins,src.bins,capacity_*sizeof(*bins))==0);
}

void
TestStatHist::testStatHistBaseEquality()
{
    InspectingStatHist raw, test;
    raw.enumInit(FIVE);
    test.enumInit(FIVE);
    CPPUNIT_ASSERT(raw==test);
    test.count(ZERO);
    CPPUNIT_ASSERT_ASSERTION_FAIL(CPPUNIT_ASSERT(raw==test));
}

void
TestStatHist::testStatHistBaseAssignment()
{
    InspectingStatHist raw, test;
    raw.enumInit(FIVE);
    test.enumInit(FIVE);
    test.count(ZERO);
    CPPUNIT_ASSERT_ASSERTION_FAIL(CPPUNIT_ASSERT(raw==test));
    test=raw;
    CPPUNIT_ASSERT(raw==test);
}

void
TestStatHist::testStatHistLog()
{
    const double min=0.0, max=10000.0;
    const int capacity=10;
    InspectingStatHist raw, test;
    raw.logInit(capacity,min,max);
    test=raw;
    CPPUNIT_ASSERT(test.counter(min)==0);
    test.count(min);
    CPPUNIT_ASSERT(test.counter(min)==1);
    CPPUNIT_ASSERT(test.counter(max)==0);
    test.count(max);
    CPPUNIT_ASSERT(test.counter(max)==1);
    test=raw;
    test.count(max);
    //CPPUNIT_ASSERT(test.val(capacity-1)==1); // XXX: val() returns a density
}

void
TestStatHist::testStatHistSum()
{
    InspectingStatHist s1, s2;
    s1.logInit(30,1.0,100.0);
    s2.logInit(30,1.0,100.0);
    s1.count(3);
    s2.count(30);
    InspectingStatHist ts1, ts2;
    ts1=s1;
    ts1+=s2;
    ts2=s2;
    ts2+=s1;
    CPPUNIT_ASSERT(ts1 == ts2);
    InspectingStatHist ts3;
    ts3.logInit(30,1.0,100.0);
    ts3.count(3);
    ts3.count(30);
    CPPUNIT_ASSERT(ts3 == ts1);

}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

