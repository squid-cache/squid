/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TESTENUMITERATOR_H_
#define SQUID_TESTENUMITERATOR_H_

#include "base/EnumIterator.h"

#include "compat/cppunit.h"

class testEnumIterator : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testEnumIterator );
    CPPUNIT_TEST( testForwardIter );
    CPPUNIT_TEST( testReverseIter );
    CPPUNIT_TEST( testBidirectionalIter );
    CPPUNIT_TEST( testRangeFor );
    CPPUNIT_TEST( testRangeForRange );
    CPPUNIT_TEST( testUnsignedEnum );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testForwardIter();
    void testReverseIter();
    void testBidirectionalIter();
    void testRangeFor();
    void testRangeForRange();
    void testUnsignedEnum();
};

#endif /* SQUID_TESTENUMITERATOR_H_ */

