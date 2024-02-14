/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTHTTPREQUEST_H
#define SQUID_SRC_TESTS_TESTHTTPREQUEST_H

#include "compat/cppunit.h"

/*
 * test HttpRequest
 */

class testHttpRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttpRequest );
    CPPUNIT_TEST( testCreateFromUrl );
    CPPUNIT_TEST( testIPv6HostColonBug );
    CPPUNIT_TEST( testSanityCheckStartLine );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    void testCreateFromUrl();
    void testIPv6HostColonBug();
    void testSanityCheckStartLine();
};

#endif /* SQUID_SRC_TESTS_TESTHTTPREQUEST_H */

