/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_TESTSBUF_H
#define SQUID_SRC_TEST_TESTSBUF_H

#include "compat/cppunit.h"

class TestSBufList: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestSBufList );
    CPPUNIT_TEST( testSBufListMembership );
    CPPUNIT_TEST( testSBufListJoin );
    CPPUNIT_TEST_SUITE_END();
protected:
    void testSBufListMembership();
    void testSBufListJoin();
};

#endif

