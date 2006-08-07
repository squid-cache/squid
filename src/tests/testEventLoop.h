
#ifndef SQUID_SRC_TEST_EVENTLOOP_H
#define SQUID_SRC_TEST_EVENTLOOP_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the EventLoop implementation
 */

class testEventLoop : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testEventLoop );
    CPPUNIT_TEST( testCreate );
    CPPUNIT_TEST( testRunOnce );
    CPPUNIT_TEST( testRegisterDispatcher );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testCreate();
    void testRunOnce();
    void testRegisterDispatcher();
};

#endif

