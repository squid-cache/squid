/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTPACKABLESTREAM_H
#define SQUID_SRC_TESTS_TESTPACKABLESTREAM_H

#include "compat/cppunit.h"

/*
 * test PackableStream
 */

class testPackableStream : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testPackableStream );
    CPPUNIT_TEST( testGetStream );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testGetStream();
};

#endif /* SQUID_SRC_TESTS_TESTPACKABLESTREAM_H */

