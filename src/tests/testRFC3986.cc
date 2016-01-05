/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "rfc1738.h"
#include "SBuf.h"
#include "testRFC3986.h"
#include "unitTestMain.h"

#include <cassert>

/* Being a C library code it is best bodily included and tested with C++ type-safe techniques. */
#include "lib/rfc3986.cc"

CPPUNIT_TEST_SUITE_REGISTRATION( testRFC3986 );

static void
performDecodingTest(const std::string &encoded_str, const std::string &plaintext_str)
{
    std::string decoded_str = rfc3986_unescape(encoded_str);
    CPPUNIT_ASSERT_EQUAL(plaintext_str, decoded_str);

    SBuf encoded_sbuf(encoded_str);
    SBuf plaintext_sbuf(plaintext_str);
    SBuf decoded_sbuf = rfc3986_unescape(encoded_sbuf);
    CPPUNIT_ASSERT_EQUAL(plaintext_sbuf, decoded_sbuf);
}

/* Regular Format de-coding tests */
void testRFC3986::testUrlDecode()
{
    performDecodingTest("%2Fdata%2Fsource%2Fpath","/data/source/path");
    performDecodingTest("http://foo.invalid%2Fdata%2Fsource%2Fpath",
                        "http://foo.invalid/data/source/path");
    // TODO query string

    performDecodingTest("1 w%0Ard","1 w\nrd"); // Newline %0A encoded
    performDecodingTest("2 w%rd","2 w%rd"); // Un-encoded %
    performDecodingTest("3 w%%rd","3 w%rd"); // encoded %
    performDecodingTest("5 Bad String %1","5 Bad String %1"); // corrupt string
    performDecodingTest("6 Bad String %1A%3","6 Bad String \032%3"); //partly corrupt string
    performDecodingTest("7 Good String %1A","7 Good String \032"); // non corrupt string
    //test various endings
    performDecodingTest("8 word%","8 word%");
    performDecodingTest("9 word%z","9 word%z");
    performDecodingTest("10 word%1","10 word%1");
    performDecodingTest("11 word%1q","11 word%1q");
    performDecodingTest("12 word%1a","12 word\032");
}

// perform a test for std::string, SBuf and if rfc1738flag is != 0 compare
//  against rfc1738 implementation
static void
performEncodingTest(const char *plaintext_str, const char *encoded_str, int rfc1738flag, const CharacterSet  &rfc3986CSet)
{
    CPPUNIT_ASSERT_EQUAL(std::string(encoded_str), rfc3986_escape(std::string(plaintext_str), rfc3986CSet));
    CPPUNIT_ASSERT_EQUAL(SBuf(encoded_str), rfc3986_escape(SBuf(plaintext_str), rfc3986CSet));
    if (!rfc1738flag)
        return;
    char *result = rfc1738_do_escape(plaintext_str, rfc1738flag);
    CPPUNIT_ASSERT_EQUAL(std::string(encoded_str), std::string(result));
}
void testRFC3986::testUrlEncode()
{
    /* TEST: Escaping only unsafe characters */
    performEncodingTest("http://foo.invalid/data/source/path",
                        "http://foo.invalid/data/source/path",
                        RFC1738_ESCAPE_UNSAFE, RFC3986::Unsafe);

    /* regular URL (no encoding needed) */
    performEncodingTest("http://foo.invalid/data/source/path",
                        "http://foo.invalid/data/source/path",
                        RFC1738_ESCAPE_UNSAFE, RFC3986::Unsafe);

    /* long string of unsafe # characters */
    performEncodingTest("################ ################ ################ ################ ################ ################ ################ ################",
                        "%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23",
                        RFC1738_ESCAPE_UNSAFE, RFC3986::Unsafe);

    /* TEST: escaping only reserved characters */

    /* regular URL (full encoding requested) */
    performEncodingTest("http://foo.invalid/data/source/path",
                        "http%3A%2F%2Ffoo.invalid%2Fdata%2Fsource%2Fpath",
                        RFC1738_ESCAPE_RESERVED, RFC3986::Reserved);

    /* regular path (encoding wanted for ALL special chars) */
    performEncodingTest("/data/source/path",
                        "%2Fdata%2Fsource%2Fpath",
                        RFC1738_ESCAPE_RESERVED, RFC3986::Reserved);

    /* TEST: safety-escaping a string already partially escaped */

    /* escaping of dangerous characters in a partially escaped string */
    performEncodingTest("http://foo.invalid/data%2Fsource[]",
                        "http://foo.invalid/data%2Fsource%5B%5D",
                        RFC1738_ESCAPE_UNESCAPED, RFC3986::Unescaped);

    /* escaping of hexadecimal 0xFF characters in a partially escaped string */
    performEncodingTest("http://foo.invalid/data%2Fsource\xFF\xFF",
                        "http://foo.invalid/data%2Fsource%FF%FF",
                        RFC1738_ESCAPE_UNESCAPED, RFC3986::Unescaped);
}

/** SECURITY BUG TESTS: avoid null truncation attacks by skipping %00 bytes */
void testRFC3986::PercentZeroNullDecoding()
{
    /* Attack with %00 encoded NULL */
    performDecodingTest("w%00rd", "w%00rd");

    /* Attack with %0 encoded NULL */
    performDecodingTest("w%0rd", "w%0rd");

    /* Handle '0' bytes embeded in encoded % */
    performDecodingTest("w%%00%rd", "w%00%rd");

    /* Handle NULL bytes with encoded % */
    performDecodingTest("w%%%00%rd", "w%%00%rd");
}

void
testRFC3986::testPerformance()
{

}

