/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "HttpHeaderRange.h"
#include "unitTestMain.h"

class TestHttpRange : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestHttpRange);
    CPPUNIT_TEST(testRangeParser);
    CPPUNIT_TEST(testRangeIter);
    CPPUNIT_TEST(testRangeCanonization);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testRangeParser();
    void testRangeParsing(char const *rangestring);
    void testRangeIter();
    void testRangeCanonization();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestHttpRange );

void
TestHttpRange::testRangeParser()
{
    testRangeParsing("bytes=0-3");
    testRangeParsing("bytes=-3");
    testRangeParsing("bytes=1-");
    testRangeParsing("bytes=0-3, 1-, -2");
}

void
TestHttpRange::testRangeParsing(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit(EXIT_FAILURE);

    HttpHdrRange copy(*range);

    CPPUNIT_ASSERT_EQUAL(range->specs.size(), copy.specs.size());

    HttpHdrRange::iterator pos = range->begin();

    CPPUNIT_ASSERT(*pos);

    delete range;
}

static HttpHdrRange *
rangeFromString(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit(EXIT_FAILURE);

    return range;
}

void
TestHttpRange::testRangeIter()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(3), range->specs.size());
    size_t counter = 0;
    HttpHdrRange::iterator i = range->begin();

    while (i != range->end()) {
        ++counter;
        ++i;
    }

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(3), counter);
    i = range->begin();
    CPPUNIT_ASSERT_EQUAL(static_cast<ptrdiff_t>(0), i - range->begin());
    ++i;
    CPPUNIT_ASSERT_EQUAL(static_cast<ptrdiff_t>(1), i - range->begin());
    CPPUNIT_ASSERT_EQUAL(static_cast<ptrdiff_t>(-2), i - range->end());
}

void
TestHttpRange::testRangeCanonization()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(3), range->specs.size());

    /* 0-3 needs a content length of 4 */
    /* This passes in the extant code - but should it? */

    if (!range->canonize(3))
        exit(EXIT_FAILURE);

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(3), range->specs.size());

    delete range;

    range=rangeFromString("bytes=0-3, 1-, -2");

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(3), range->specs.size());

    /* 0-3 needs a content length of 4 */
    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=3-6");

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), range->specs.size());

    /* 3-6 needs a content length of 4 or more */
    if (range->canonize(3))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=3-6");

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), range->specs.size());

    /* 3-6 needs a content length of 4 or more */
    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=1-1,2-3");

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), range->specs.size());

    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), range->specs.size());

    delete range;
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

