/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TESTLOOKUPTABLE_H_
#define SQUID_TESTLOOKUPTABLE_H_

#include "compat/cppunit.h"

class testLookupTable : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testLookupTable );
    CPPUNIT_TEST( testLookupTableLookup );
    CPPUNIT_TEST_SUITE_END();
public:
    void testLookupTableLookup();
};

#endif /* SQUID_TESTLOOKUPTABLE_H_ */

