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

#include <cstdint>
#include <limits>
#include <sstream>

class TestIoManip: public CPPUNIT_NS::TestFixture
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

/// returns the result of printing the given manipulator
template <typename Integer>
static std::string
toStdString(const AsHex<Integer> &manipulator)
{
    std::ostringstream os;
    os << manipulator;
    return os.str();
}

void
TestIoManip::testAsHex()
{
    // basic values
    CPPUNIT_ASSERT_EQUAL(std::string("0"), toStdString(asHex(0)));
    CPPUNIT_ASSERT_EQUAL(std::string("123abc"), toStdString(asHex(0x123abc)));

    // large values
    CPPUNIT_ASSERT_EQUAL(std::string("7fffffffffffffff"), toStdString(asHex(std::numeric_limits<int64_t>::max())));
    CPPUNIT_ASSERT_EQUAL(std::string("ffffffffffffffff"), toStdString(asHex(std::numeric_limits<uint64_t>::max())));

    // negative values
    // C++ defines printing with std::hex in terms of calling std::printf() with
    // %x (or %X) conversion specifier; printf(%x) interprets its value argument
    // as an unsigned integer, making it impossible for std::hex to print
    // negative values as negative hex integers. AsHex has the same limitation.
    CPPUNIT_ASSERT_EQUAL(std::string("80000000"), toStdString(asHex(std::numeric_limits<int32_t>::min())));

    // integer and integer-like types that std::ostream formats specially by default
    CPPUNIT_ASSERT_EQUAL(std::string("0"), toStdString(asHex(false)));
    CPPUNIT_ASSERT_EQUAL(std::string("1"), toStdString(asHex(true)));
    CPPUNIT_ASSERT_EQUAL(std::string("5a"), toStdString(asHex('Z')));
    CPPUNIT_ASSERT_EQUAL(std::string("77"), toStdString(asHex(int8_t(0x77))));
    CPPUNIT_ASSERT_EQUAL(std::string("ff"), toStdString(asHex(uint8_t(0xFF))));

    // other interesting integer-like types we may want to print
    enum { enumValue = 0xABCD };
    CPPUNIT_ASSERT_EQUAL(std::string("abcd"), toStdString(asHex(enumValue)));
    struct { uint8_t bitField:2; } s;
    s.bitField = 3; // TODO: Convert to default initializer after switching to C++20.
    CPPUNIT_ASSERT_EQUAL(std::string("3"), toStdString(asHex(s.bitField)));

    // padding with zeros works
    CPPUNIT_ASSERT_EQUAL(std::string("1"), toStdString(asHex(1).minDigits(1)));
    CPPUNIT_ASSERT_EQUAL(std::string("01"), toStdString(asHex(1).minDigits(2)));
    CPPUNIT_ASSERT_EQUAL(std::string("001"), toStdString(asHex(1).minDigits(3)));

    // padding with zeros works even for zero values
    CPPUNIT_ASSERT_EQUAL(std::string("0000"), toStdString(asHex(0).minDigits(4)));

    // minDigits() does not truncate
    CPPUNIT_ASSERT_EQUAL(std::string("1"), toStdString(asHex(0x1).minDigits(0)));
    CPPUNIT_ASSERT_EQUAL(std::string("12"), toStdString(asHex(0x12).minDigits(1)));
    CPPUNIT_ASSERT_EQUAL(std::string("123"), toStdString(asHex(0x123).minDigits(2)));

    // upperCase() forces uppercase
    CPPUNIT_ASSERT_EQUAL(std::string("A"), toStdString(asHex(0xA).upperCase()));
    CPPUNIT_ASSERT_EQUAL(std::string("1A2B"), toStdString(asHex(0x1a2b).upperCase(true)));

    std::ostringstream ss;

    // upperCase(false) forces lowercase
    ss << std::uppercase << asHex(0xABC).upperCase(false);
    CPPUNIT_ASSERT_EQUAL(std::string("abc"), ss.str());
    resetStream(ss);

    // a combination of formatting options
    CPPUNIT_ASSERT_EQUAL(std::string("01A"), toStdString(asHex(0x1A).upperCase().minDigits(3)));

    // Test the effects of stream formatting flags on AsHex printing and the
    // effects of AsHex printing on stream formatting flags.

    // upperCase() effects are not leaked into the stream
    ss << asHex(0xa0).upperCase() << asHex(0xa0);
    CPPUNIT_ASSERT_EQUAL(std::string("A0a0"), ss.str());
    resetStream(ss);

    // original std::showbase is honored
    ss << std::showbase << asHex(1);
    CPPUNIT_ASSERT_EQUAL(std::string("0x1"), ss.str());
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

    // original std::setw() is honored
    ss << std::setw(4) << asHex(0x1);
    CPPUNIT_ASSERT_EQUAL(std::string("   1"), ss.str());
    resetStream(ss);

    // original std::setw() is consumed (by the printed number)
    ss << std::setw(4) << asHex(0x1) << 2;
    CPPUNIT_ASSERT_EQUAL(std::string("   12"), ss.str());
    resetStream(ss);

    // original std::setfill() is honored
    ss << std::setfill('.') << std::setw(4) << asHex(0x2);
    CPPUNIT_ASSERT_EQUAL(std::string("...2"), ss.str());
    resetStream(ss);

    // original std::setfill() is preserved
    ss << std::setfill('.') << asHex(0x3).minDigits(2) << std::setw(4) << 4;
    CPPUNIT_ASSERT_EQUAL(std::string("03...4"), ss.str());
    resetStream(ss);
}
