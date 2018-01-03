/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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

#if POLISHED_MAIN_LOOP
    CPPUNIT_TEST( testRunOnce );
    CPPUNIT_TEST( testRegisterDispatcher );
    CPPUNIT_TEST( testRegisterEngine );
    CPPUNIT_TEST( testEngineTimeout );
    CPPUNIT_TEST( testStopOnIdle );
#endif

    CPPUNIT_TEST( testSetTimeService );
    CPPUNIT_TEST( testSetPrimaryEngine );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCreate();

#if POLISHED_MAIN_LOOP
    void testEngineTimeout();
    void testRunOnce();
    void testRegisterDispatcher();
    void testRegisterEngine();
    void testStopOnIdle();
#endif

    void testSetTimeService();
    void testSetPrimaryEngine();
    /* TODO:
     * test that engine which errors a couple of times, then returns 0, then
     * errors 10 times in a row triggers a fail on the 10th time around
     */
};

#endif

