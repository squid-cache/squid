/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_BOILDERPLATE_H
#define SQUID_SRC_TEST_BOILDERPLATE_H

#include "compat/cppunit.h"

/*
 * demonstration test file, as new idioms are made they will
 * be shown in the testBoilerplate source.
 */

class testBoilerplate : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testBoilerplate );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testDemonstration );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testDemonstration();
};

#endif /* SQUID_SRC_TEST_BOILDERPLATE_H */

