
#ifndef SQUID_SRC_TEST_EVENT_H
#define SQUID_SRC_TEST_EVENT_H

#include <cppunit/extensions/HelperMacros.h>

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

