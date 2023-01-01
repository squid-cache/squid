/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_STORECONTROLLER_H
#define SQUID_SRC_TEST_STORECONTROLLER_H

#include "compat/cppunit.h"

/*
 * test the store framework
 */

class testUfs : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testUfs );
    CPPUNIT_TEST( testUfsSearch );
    CPPUNIT_TEST( testUfsDefaultEngine );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void commonInit();
    void testUfsSearch();
    void testUfsDefaultEngine();
};

#endif

