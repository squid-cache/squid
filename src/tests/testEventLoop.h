
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
    CPPUNIT_TEST( testRegisterEngine );
    CPPUNIT_TEST( testEngineTimeout );
    CPPUNIT_TEST( testSetTimeService );
    CPPUNIT_TEST( testSetPrimaryEngine );
    CPPUNIT_TEST( testStopOnIdle );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCreate();
    void testEngineTimeout();
    void testRunOnce();
    void testRegisterDispatcher();
    void testRegisterEngine();
    void testSetTimeService();
    void testSetPrimaryEngine();
    void testStopOnIdle();
    /* TODO:
     * test that engine which errors a couple of times, then returns 0, then
     * errors 10 times in a row triggers a fail on the 10th time around
     */
};

#endif

