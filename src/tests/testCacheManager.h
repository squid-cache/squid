/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_CACHEMANAGER_H
#define SQUID_SRC_TEST_CACHEMANAGER_H

#include "compat/cppunit.h"

/*
 * test the CacheManager implementation
 */

class testCacheManager : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testCacheManager );
    CPPUNIT_TEST( testCreate );
    CPPUNIT_TEST( testRegister );
    CPPUNIT_TEST( testParseUrl );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCreate();
    void testRegister();
    void testParseUrl();
};

#endif

