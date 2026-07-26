/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Base64.h"
#include "compat/cppunit.h"
#include "sbuf/SBuf.h"
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

class TestBase64Decode : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestBase64Decode);
    CPPUNIT_TEST(testDecodeSimple);
    CPPUNIT_TEST(testDecodeEmpty);
    CPPUNIT_TEST(testDecodeEncodeRoundtrip);
    CPPUNIT_TEST(testEncodeDecodeRoundtrip);
    CPPUNIT_TEST(testDecodeInvalidChars);
    CPPUNIT_TEST(testDecodeInvalidPadding);
    CPPUNIT_TEST(testDecodeIncomplete);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testDecodeSimple();
    void testDecodeEmpty();
    void testDecodeEncodeRoundtrip();
    void testEncodeDecodeRoundtrip();
    void testDecodeInvalidChars();
    void testDecodeInvalidPadding();
    void testDecodeIncomplete();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestBase64Decode);

static const struct { const char *encoded; const char *decoded; size_t decodedLen; } knownVectors[] = {
    { "YQ==",         "a",       1 },
    { "YWI=",         "ab",      2 },
    { "YWJj",         "abc",     3 },
    { "YWJjZA==",     "abcd",    4 },
    { "SGVsbG8=",     "Hello",   5 },
    { "dGVzdA==",     "test",    4 },
    { "AQID",         "\x01\x02\x03", 3 },
};

void
TestBase64Decode::testDecodeSimple()
{
    for (const auto &v : knownVectors) {
        SBuf result = Base64Decode(v.encoded, strlen(v.encoded));
        CPPUNIT_ASSERT_EQUAL(SBuf(v.decoded, v.decodedLen), result);
    }
}

void
TestBase64Decode::testDecodeEmpty()
{
    const auto result = Base64Decode("", 0);
    CPPUNIT_ASSERT_EQUAL(SBuf(), result);
}

void
TestBase64Decode::testDecodeEncodeRoundtrip()
{
    // decode a known base64 string, then re-encode and compare to original
    for (const auto &v : knownVectors) {
        const auto decoded = Base64Decode(v.encoded, strlen(v.encoded));
        const auto reencoded = Base64Encode(decoded);
        CPPUNIT_ASSERT_EQUAL(SBuf(v.encoded), reencoded);
    }
}

void
TestBase64Decode::testEncodeDecodeRoundtrip()
{
    // encode a plaintext string, then decode and compare to original
    static const char * const plainTexts[] = {
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "\x00\x01\x02\x03\xff\xfe\xfd",
        "",
    };
    static const size_t plainLens[] = { 13, 43, 7, 0 };

    for (size_t i = 0; i < sizeof(plainTexts) / sizeof(*plainTexts); ++i) {
        SBuf original(plainTexts[i], plainLens[i]);
        const auto encoded = Base64Encode(original);
        const auto decoded = Base64Decode(encoded);
        CPPUNIT_ASSERT_EQUAL(original, decoded);
    }
}

void
TestBase64Decode::testDecodeInvalidChars()
{
    // characters outside the base64 alphabet
    CPPUNIT_ASSERT_THROW(Base64Decode("!!!!", 4), DecodeException);
    CPPUNIT_ASSERT_THROW(Base64Decode("SGVs!G8=", 8), DecodeException);
    CPPUNIT_ASSERT_THROW(Base64Decode("abc$", 4), DecodeException);
}

void
TestBase64Decode::testDecodeInvalidPadding()
{
    // padding in wrong position or wrong amount
    CPPUNIT_ASSERT_THROW(Base64Decode("=YWJj", 5), DecodeException);
    CPPUNIT_ASSERT_THROW(Base64Decode("YWJj====", 8), DecodeException);
}

void
TestBase64Decode::testDecodeIncomplete()
{
    // a single base64 character cannot represent a complete byte
    CPPUNIT_ASSERT_THROW(Base64Decode("A", 1), DecodeException);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}