/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/YesNoNone.h"
#include "tests/testYesNoNone.h"
#include "unitTestMain.h"

#include <stdexcept>

CPPUNIT_TEST_SUITE_REGISTRATION( testYesNoNone );

void
testYesNoNone::testBasics()
{
    // unconfigured, non-implicit
    {
        YesNoNone v;
        CPPUNIT_ASSERT_EQUAL(false, v.configured());
        // cannot test the value it is 'undefined' and will assert
    }
    // implicit dtor test

    // unconfigured, implicit true
    {
        YesNoNone v(true);
        CPPUNIT_ASSERT_EQUAL(false, v.configured());
        CPPUNIT_ASSERT(v);
        CPPUNIT_ASSERT_EQUAL(true, static_cast<bool>(v));

        // check explicit setter method
        v.configure(false);
        CPPUNIT_ASSERT_EQUAL(true, v.configured());
        CPPUNIT_ASSERT(!v);
        CPPUNIT_ASSERT_EQUAL(false, static_cast<bool>(v));
    }

    // unconfigured, implicit false
    {
        YesNoNone v(false);
        CPPUNIT_ASSERT_EQUAL(false, v.configured());
        CPPUNIT_ASSERT(!v);
        CPPUNIT_ASSERT_EQUAL(false, static_cast<bool>(v));

        // check assignment operator
        v = YesNoNone(true);
        CPPUNIT_ASSERT_EQUAL(false, v.configured());
        CPPUNIT_ASSERT(v);
        CPPUNIT_ASSERT_EQUAL(true, static_cast<bool>(v));
    }
}

