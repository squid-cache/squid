/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

#include <stdexcept>

/*
 * This is a rough example of a typical unit test file.
 *
 * If the class declaration is used in more than one source file,
 * then place that declaration into a dedicated header file instead.
 */

class TestBoilerplate: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestBoilerplate );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testDemonstration );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testDemonstration();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestBoilerplate );

void
TestBoilerplate::testDemonstration()
{
    CPPUNIT_ASSERT_EQUAL(0, 0);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

