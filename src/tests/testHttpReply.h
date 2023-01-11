/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_HTTP_REPLY_H
#define SQUID_SRC_TEST_HTTP_REPLY_H

#include "compat/cppunit.h"

/*
 * test HttpReply
 */

class testHttpReply : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttpReply );
    CPPUNIT_TEST( testSanityCheckFirstLine );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testSanityCheckFirstLine();
};

#endif

