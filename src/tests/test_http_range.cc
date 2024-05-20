/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "fatal.h"
#include "HttpHeader.h"
#include "HttpHeaderRange.h"
#include "HttpHeaderTools.h"
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
    void testRangeParser(char const *rangestring);
    void testRangeIter();
    void testRangeCanonization();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestHttpRange );

void
TestHttpRange::testRangeParser()
{
    testRangeParser("bytes=0-3");
    testRangeParser("bytes=-3");
    testRangeParser("bytes=1-");
    testRangeParser("bytes=0-3, 1-, -2");
}

void
TestHttpRange::testRangeParser(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit(EXIT_FAILURE);

    HttpHdrRange copy(*range);

    assert (copy.specs.size() == range->specs.size());

    HttpHdrRange::iterator pos = range->begin();

    assert (*pos);

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
    assert (range->specs.size() == 3);
    size_t counter = 0;
    HttpHdrRange::iterator i = range->begin();

    while (i != range->end()) {
        ++counter;
        ++i;
    }

    assert (counter == 3);
    i = range->begin();
    assert (i - range->begin() == 0);
    ++i;
    assert (i - range->begin() == 1);
    assert (i - range->end() == -2);
}

void
TestHttpRange::testRangeCanonization()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    assert (range->specs.size() == 3);

    /* 0-3 needs a content length of 4 */
    /* This passes in the extant code - but should it? */

    if (!range->canonize(3))
        exit(EXIT_FAILURE);

    assert (range->specs.size() == 3);

    delete range;

    range=rangeFromString("bytes=0-3, 1-, -2");

    assert (range->specs.size() == 3);

    /* 0-3 needs a content length of 4 */
    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.size() == 1);

    /* 3-6 needs a content length of 4 or more */
    if (range->canonize(3))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.size() == 1);

    /* 3-6 needs a content length of 4 or more */
    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=1-1,2-3");

    assert (range->specs.size()== 2);

    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    assert (range->specs.size() == 2);

    delete range;
}

int
main(int argc, char **argv)
{
    Mem::Init();
    /* enable for debugging to console */
    // Debug::debugOptions = xstrdup("ALL,1 64,9");
    // Debug::BanCacheLogUse();

    return TestProgram().run(argc, argv);
}

