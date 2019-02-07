/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "StatHist.h"
#include "testStatHist.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION(testStatHist);

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
    assert(bins != NULL && src.bins != NULL); // TODO: remove after initializing bins at construction time
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
testStatHist::testStatHistBaseEquality()
{
    InspectingStatHist raw, test;
    raw.enumInit(FIVE);
    test.enumInit(FIVE);
    CPPUNIT_ASSERT(raw==test);
    test.count(ZERO);
    CPPUNIT_ASSERT_ASSERTION_FAIL(CPPUNIT_ASSERT(raw==test));
}

void
testStatHist::testStatHistBaseAssignment()
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
testStatHist::testStatHistLog()
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
    //CPPUNIT_ASSERT(test.val(capacity-1)==1); //FIXME: val() returns a density
}

void
testStatHist::testStatHistSum()
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

