/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_EVENT_H
#define SQUID_SRC_TEST_EVENT_H

#include "compat/cppunit.h"

/*
 * test the event module.
 */

class testEvent : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testEvent );
    CPPUNIT_TEST( testCreate );
    CPPUNIT_TEST( testDump );
    CPPUNIT_TEST( testFind );
    CPPUNIT_TEST( testCheckEvents );
    CPPUNIT_TEST( testSingleton );
    CPPUNIT_TEST( testCancel );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCreate();
    void testDump();
    void testFind();
    void testCheckEvents();
    void testSingleton();
    void testCancel();
};

#endif

