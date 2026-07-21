/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Base64Encoder.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

class TestBase64Encode : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestBase64Encode);
    CPPUNIT_TEST(testBase64EncodeFunction);
    CPPUNIT_TEST(testBase64EncodeFunctionEmpty);
    CPPUNIT_TEST(testBase64EncodeFunctionLargeInput);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testBase64EncodeFunction();
    void testBase64EncodeFunctionEmpty();
    void testBase64EncodeFunctionLargeInput();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestBase64Encode );

void
TestBase64Encode::testBase64EncodeFunction()
{
    SBuf input("Hello");
    SBuf result = Base64Encode(input);
    CPPUNIT_ASSERT_EQUAL(SBuf("SGVsbG8="), result);
}

void
TestBase64Encode::testBase64EncodeFunctionEmpty()
{
    SBuf input("");
    SBuf result = Base64Encode(input);
    CPPUNIT_ASSERT_EQUAL(SBuf(""), result);
}

void
TestBase64Encode::testBase64EncodeFunctionLargeInput()
{
    std::string largeInput(5000, 'A');
    SBuf input(largeInput.c_str(), largeInput.size());
    SBuf result = Base64Encode(input);

    CPPUNIT_ASSERT_EQUAL(static_cast<SBuf::size_type>(6668), result.length());
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('Q'), result[0]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('U'), result[1]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('F'), result[2]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('B'), result[3]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('='), result[result.length() - 1]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('E'), result[result.length() - 2]);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}