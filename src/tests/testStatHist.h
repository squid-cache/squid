/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * StatHist unit test
 */

#ifndef SQUID_SRC_TESTS_TESTSTATHIST_H
#define SQUID_SRC_TESTS_TESTSTATHIST_H

#include "compat/cppunit.h"

class testStatHist : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStatHist );
    CPPUNIT_TEST( testStatHistBaseEquality );
    CPPUNIT_TEST( testStatHistBaseAssignment );
    CPPUNIT_TEST( testStatHistLog );
    CPPUNIT_TEST( testStatHistSum );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testStatHistBaseEquality();
    void testStatHistBaseAssignment();
    void testStatHistLog();
    void testStatHistSum();
};

#endif /* SQUID_SRC_TESTS_TESTSTATHIST_H */

