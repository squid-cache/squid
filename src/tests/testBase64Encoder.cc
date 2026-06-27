/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "base64/Base64Encoder.h"
#include "compat/cppunit.h"
#include "event.h"
#include "MemObject.h"
#include "unitTestMain.h"

#include "sbuf/Stream.h"

/*
 * test the Base64Encoder functionalities
 */

class TestBase64Encoder : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestBase64Encoder);
    CPPUNIT_TEST(testBase64EncoderDefault);
    CPPUNIT_TEST(testBase64EncoderWithMaxSize);
    CPPUNIT_TEST(testBase64EncoderWithInput);
    CPPUNIT_TEST(testBase64EncoderStreaming);
    CPPUNIT_TEST(testBase64EncoderBufAndClear);
    CPPUNIT_TEST(testBase64EncoderPrint);
    CPPUNIT_TEST(testBase64EncoderToBase64);
    CPPUNIT_TEST(testBase64EncoderLargeInput);
    CPPUNIT_TEST(testBase64EncoderMaxSize);
    CPPUNIT_TEST(testBase64EncoderMaxSizeExceeded);
    CPPUNIT_TEST(testBase64EncoderMaxSizeSBuf);
    CPPUNIT_TEST(testBase64EncoderMaxSizeBoundary);
    CPPUNIT_TEST(testBase64EncoderMaxSizeClear);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testBase64EncoderDefault();
    void testBase64EncoderWithMaxSize();
    void testBase64EncoderWithInput();
    void testBase64EncoderStreaming();
    void testBase64EncoderBufAndClear();
    void testBase64EncoderPrint();
    void testBase64EncoderToBase64();
    void testBase64EncoderLargeInput();
    void testBase64EncoderMaxSize();
    void testBase64EncoderMaxSizeExceeded();
    void testBase64EncoderMaxSizeSBuf();
    void testBase64EncoderMaxSizeBoundary();
    void testBase64EncoderMaxSizeClear();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestBase64Encoder );

/* let this test link sanely */
void
eventAdd(const char *, EVH *, void *, double, int, bool)
{}
int64_t
MemObject::endOffset() const
{ return 0; }
/* end of stubs */

void
TestBase64Encoder::testBase64EncoderDefault()
{
    Base64Encoder encoder;
    encoder << "Hello";
    auto result = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("SGVsbG8="), result);
}

void
TestBase64Encoder::testBase64EncoderWithMaxSize()
{
    // Test encoder with max size limit that is not exceeded
    Base64Encoder encoder(100);
    encoder << "Test";
    auto result = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("VGVzdA=="), result);
}

void
TestBase64Encoder::testBase64EncoderWithInput()
{
    SBuf input("Direct input");
    Base64Encoder encoder(input);
    auto result = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("RGlyZWN0IGlucHV0"), result);
}

void
TestBase64Encoder::testBase64EncoderStreaming()
{
    Base64Encoder encoder;
    encoder << "Part1" << "Part2" << 123;
    auto result = encoder.buf();
    // "Part1Part2123" base64 encoded
    CPPUNIT_ASSERT_EQUAL(SBuf("UGFydDFQYXJ0MjEyMw=="), result);
}

void
TestBase64Encoder::testBase64EncoderBufAndClear()
{
    Base64Encoder encoder;
    encoder << "First";
    auto result1 = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("Rmlyc3Q="), result1);

    encoder.clearBuf();
    encoder << "Second";
    auto result2 = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("U2Vjb25k"), result2);

    CPPUNIT_ASSERT(result1 != result2);
}

void
TestBase64Encoder::testBase64EncoderPrint()
{
    Base64Encoder encoder;
    encoder << "Printable";
    SBufStream ssb;
    ssb << encoder;
    CPPUNIT_ASSERT_EQUAL(SBuf("UHJpbnRhYmxl"), ssb.buf());
}

void
TestBase64Encoder::testBase64EncoderToBase64()
{
    auto result = ToBase64("A", "B", "C");
    CPPUNIT_ASSERT_EQUAL(SBuf("QUJD"), result);
}

void
TestBase64Encoder::testBase64EncoderLargeInput()
{
    // Create a string larger than the internal 4KB buffer (4096 bytes)
    SBuf largeInput;
    std::string as(5000, 'A');
    largeInput.append(as.c_str(), as.length());

    Base64Encoder encoder;
    encoder << largeInput;
    auto result = encoder.buf();

    // 5000 'A' chars = 5000 bytes = base64 encoded = 6668 chars (with padding)
    CPPUNIT_ASSERT_EQUAL(static_cast<SBuf::size_type>(6668), result.length());

    // Verify known prefix: 5000 'A's encoded starts with "QUFBQUFB..." (AAA->QUFB repeated)
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('Q'), result[0]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('U'), result[1]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('F'), result[2]);
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('B'), result[3]);

    // Verify padding at the end (5000 % 3 = 2, so 1 padding char '=')
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('='), result[result.length() - 1]);
    // Second to last is 'E' (from 'AA' -> 'QUE')
    CPPUNIT_ASSERT_EQUAL(static_cast<char>('E'), result[result.length() - 2]);
}

void
TestBase64Encoder::testBase64EncoderMaxSize()
{
    // Test encoder with max size limit that is not exceeded
    Base64Encoder encoder(50);
    encoder << "Hello";  // "Hello" = 5 bytes -> base64 = 8 chars (with padding)
    auto result = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("SGVsbG8="), result);
}

void
TestBase64Encoder::testBase64EncoderMaxSizeExceeded()
{
    // Test that encoding over the limit throws TextException
    Base64Encoder encoder(10);  // Very small limit
    encoder.exceptions(std::ios::badbit);  // Enable exceptions on stream
    CPPUNIT_ASSERT_THROW(encoder << "This is a long string that exceeds the limit", TextException);
}

void
TestBase64Encoder::testBase64EncoderMaxSizeSBuf()
{
    // Test SBuf constructor with max size - input too large should throw
    SBuf input("Direct input");  // 12 bytes -> base64 = 16 chars
    bool threw = false;
    // cannot use CPPUNIT_ASSERT_THROW here because the exception is thrown in the constructor
    try {
        Base64Encoder encoder(input, 10);  // Limit too small - encoding happens in constructor
        encoder.exceptions(std::ios::badbit); // Enable exceptions to catch stream errors
        encoder.buf(); // This will throw if stream is in error state
    } catch (const TextException &e) {
        threw = true;
        CPPUNIT_ASSERT(std::string(e.what()).find("size limit exceeded") != std::string::npos);
    } catch (const std::ios::failure &e) {
        // Stream throws ios::failure when exceptions enabled and badbit set
        threw = true;
    }
    CPPUNIT_ASSERT(threw);
}

void
TestBase64Encoder::testBase64EncoderMaxSizeBoundary()
{
    // Test exact boundary: "AB" = 2 bytes -> base64 = 4 chars
    Base64Encoder encoder(4);
    encoder << "AB";
    auto result = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("QUI="), result);

    // One more byte should exceed (limit 3 is too small for "AB" which needs 4)
    Base64Encoder encoder2(3);
    encoder2.exceptions(std::ios::badbit);
    CPPUNIT_ASSERT_THROW(encoder2 << "AB", TextException);
}

void
TestBase64Encoder::testBase64EncoderMaxSizeClear()
{
    // Test that clearBuf preserves the max size limit
    Base64Encoder encoder(20);
    encoder << "First";
    auto result1 = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("Rmlyc3Q="), result1);

    encoder.clearBuf();
    // Should still enforce limit
    encoder.exceptions(std::ios::badbit);
    CPPUNIT_ASSERT_THROW(encoder << "This is a very long string that exceeds limit", TextException);
    // But encoding within limit should work after clear
    encoder.clearBuf();
    encoder << "Short";
    auto result2 = encoder.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf("U2hvcnQ="), result2);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}