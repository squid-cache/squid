/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTEVENTLOOP_H
#define SQUID_SRC_TESTS_TESTEVENTLOOP_H

#include "compat/cppunit.h"

/*
 * test the EventLoop implementation
 */

class testEventLoop : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testEventLoop );
    CPPUNIT_TEST( testCreate );
    CPPUNIT_TEST( testRunOnce );
    CPPUNIT_TEST( testEngineTimeout );
    CPPUNIT_TEST( testEngineErrors );
    CPPUNIT_TEST( testSetTimeService );
    CPPUNIT_TEST( testSetPrimaryEngine );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testCreate();
    void testRunOnce();
    void testEngineTimeout();
    void testEngineErrors();
    void testSetTimeService();
    void testSetPrimaryEngine();
    /* TODO:
     * test that engine which errors a couple of times, then returns 0, then
     * errors 10 times in a row triggers a fail on the 10th time around
     */
};

#endif /* SQUID_SRC_TESTS_TESTEVENTLOOP_H */

