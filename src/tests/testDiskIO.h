/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_DISKIO_H
#define SQUID_SRC_TEST_DISKIO_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the DiskIO framework
 */

class testDiskIO : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testDiskIO );
    CPPUNIT_TEST( testFindDefault );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testFindDefault();
};

#endif

