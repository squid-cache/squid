/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RandomUuid.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

class TestRandomUuid: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestRandomUuid );
    CPPUNIT_TEST( testSerialization );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testSerialization();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestRandomUuid );

void
TestRandomUuid::testSerialization()
{
    RandomUuid uuid1;
    auto serialized = uuid1.serialize();
    RandomUuid uuid2(uuid1.serialize());
    CPPUNIT_ASSERT_MESSAGE("Original and deserialized UUIDs are equal", uuid1 == uuid2);
}

