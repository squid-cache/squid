/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "hash.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

class TestHash : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestHash);
    CPPUNIT_TEST(testHashCase);
    CPPUNIT_TEST_SUITE_END();

public:
    void testHashCase();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestHash);

static const char * lowerCaseString[] = {
    "www.smallletters.com",
    "www.alphanumeric123.com",
};

static const char * mixCaseString[] = {
    "www.smallLetters.com",
    "www.alphaNUMeric123.com",
};
void
TestLookupTable::testLookupTableLookup()
{
   // Test thet hash4/casehash4 returns equal result for lower case string
    for(const char * domain : lowerCaseString)
        CPPUNIT_ASSERT_EQUAL(casehash4(domain), hash4(domain));
       
   // Test thet hash4/casehash4 returns  result mix case string
    for(const char * domain : lowerCaseString)
        CPPUNIT_ASSERT(casehash4(domain) != hash4(domain));
}

