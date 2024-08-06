/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTREFCOUNT_H
#define SQUID_SRC_TESTS_TESTREFCOUNT_H

#include "compat/cppunit.h"

class testRefCount : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testRefCount );
    CPPUNIT_TEST( testCountability );
    CPPUNIT_TEST( testObjectToRefCounted );
    CPPUNIT_TEST( testStandalonePointer );
    CPPUNIT_TEST( testCheckPointers );
    CPPUNIT_TEST( testPointerConst );
    CPPUNIT_TEST( testRefCountFromConst );
    CPPUNIT_TEST( testPointerFromRefCounter );
    CPPUNIT_TEST( testDoubleInheritToSingleInherit );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testCountability();
    void testObjectToRefCounted();
    void testStandalonePointer();
    void testCheckPointers();
    void testPointerConst();
    void testRefCountFromConst();
    void testPointerFromRefCounter();
    void testDoubleInheritToSingleInherit();
};

#endif /* SQUID_SRC_TESTS_TESTREFCOUNT_H */

