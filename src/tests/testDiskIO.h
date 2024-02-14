/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTDISKIO_H
#define SQUID_SRC_TESTS_TESTDISKIO_H

#include "compat/cppunit.h"

/*
 * test the DiskIO framework
 */

class testDiskIO : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testDiskIO );
    CPPUNIT_TEST( testFindDefault );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    void testFindDefault();
};

#endif /* SQUID_SRC_TESTS_TESTDISKIO_H */

