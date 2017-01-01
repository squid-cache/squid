/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTYESNONONE_H
#define SQUID_SRC_TESTS_TESTYESNONONE_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * demonstration test file, as new idioms are made they will
 * be shown in the testYesNoNone source.
 */

class testYesNoNone : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testYesNoNone );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testBasics );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testBasics();
};

#endif /* SQUID_SRC_TESTS_TESTYESNONONE_H */

