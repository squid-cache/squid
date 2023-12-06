/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/IoManip.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

#include <sstream>

class TestIoManip : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestIoManip);
    CPPUNIT_TEST(testAsHex);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testAsHex();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestIoManip );

/// resets the given stream, including any formatting
static void
resetStream(std::ostringstream &dirty)
{
    std::ostringstream clean;
    dirty.swap(clean);
}

void
TestIoManip::testAsHex()
{
    std::ostringstream ss;

    // assumption used by cases below: the stream defaults to lowercase
    ss << std::hex << 0xABC;
    CPPUNIT_ASSERT_EQUAL(std::string("abc"), ss.str());
    resetStream(ss);

    // assumption used by cases below: resetStream() resets formatting
    ss << std::uppercase << std::hex << 0xABC;
    CPPUNIT_ASSERT_EQUAL(std::string("ABC"), ss.str());
    resetStream(ss);
    ss << 0xABC;
    CPPUNIT_ASSERT_EQUAL(std::string("2748"), ss.str());
    resetStream(ss);

    // standard output
    ss << asHex(0xa0);
    CPPUNIT_ASSERT_EQUAL(std::string("a0"), ss.str());
    resetStream(ss);

    // zero-padded
    ss << asHex(0xa0).minDigits(4);
    CPPUNIT_ASSERT_EQUAL(std::string("00a0"), ss.str());
    resetStream(ss);

    // leading zeros
    ss << asHex(0x00004);
    CPPUNIT_ASSERT_EQUAL(std::string("4"), ss.str());
    resetStream(ss);

    // leading zeros
    ss << asHex(0x00004).minDigits(0);
    CPPUNIT_ASSERT_EQUAL(std::string("4"), ss.str());
    resetStream(ss);

    // exceed minDigits
    ss << asHex(0x12345).minDigits(2);
    CPPUNIT_ASSERT_EQUAL(std::string("12345"), ss.str());
    resetStream(ss);

    // honor uppercase flag
    ss << asHex(0xa0).upperCase();
    CPPUNIT_ASSERT_EQUAL(std::string("A0"), ss.str());
    resetStream(ss);

    // honored uppercase is cleared afterwords
    ss << asHex(0xa0).upperCase() << asHex(0xa0);
    CPPUNIT_ASSERT_EQUAL(std::string("A0a0"), ss.str());
    resetStream(ss);

    // original std::uppercase is honored
    ss << std::uppercase << std::hex << 0xA << asHex(0xB) << 0xC;
    CPPUNIT_ASSERT_EQUAL(std::string("ABC"), ss.str());
    resetStream(ss);

    // original std::uppercase is preserved
    ss << std::uppercase << std::hex << 0xA << asHex(0xB).upperCase(false) << 0xC;
    CPPUNIT_ASSERT_EQUAL(std::string("AbC"), ss.str());
    resetStream(ss);

    // original std::oct is preserved
    ss << std::oct << 9 << asHex(0xA) << 11;
    CPPUNIT_ASSERT_EQUAL(std::string("11a13"), ss.str());
    resetStream(ss);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

