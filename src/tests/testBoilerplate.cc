/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "testBoilerplate.h"
#include "unitTestMain.h"

#include <stdexcept>

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

