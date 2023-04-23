/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/LookupTable.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

class TestLookupTable : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestLookupTable);
    CPPUNIT_TEST(testLookupTableLookup);
    CPPUNIT_TEST_SUITE_END();

public:
    void testLookupTableLookup();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestLookupTable);

enum EnumData {
    ENUM_1,
    ENUM_2,
    ENUM_3,
    ENUM_4,
    ENUM_5,
    ENUM_6,
    ENUM_7,
    ENUM_INVALID
};

static const LookupTable<EnumData>::Record tableData[] = {
    {"one", ENUM_1},
    {"two", ENUM_2},
    {"three", ENUM_3},
    {"four", ENUM_4},
    {"five", ENUM_5},
    {"six", ENUM_6},
    {"seven", ENUM_7},
    {nullptr, ENUM_INVALID}
};

void
TestLookupTable::testLookupTableLookup()
{
    LookupTable<EnumData> lt(ENUM_INVALID, tableData);
    // element found
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("one")), ENUM_1);
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("two")), ENUM_2);
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("three")), ENUM_3);
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("four")), ENUM_4);
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("five")), ENUM_5);
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("six")), ENUM_6);
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("seven")), ENUM_7);

    // element not found
    CPPUNIT_ASSERT_EQUAL(lt.lookup(SBuf("eleventy")), ENUM_INVALID);
}

