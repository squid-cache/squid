/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "testRFC1738.h"
#include "unitTestMain.h"

#include <cassert>

/* Being a C library code it is best bodily included and tested with C++ type-safe techniques. */
#include "lib/rfc1738.c"

CPPUNIT_TEST_SUITE_REGISTRATION( testRFC1738 );

#if _SQUID_OPENBSD_
// the quite old GCC on OpenBSD 5.4 needs this when linking to libmisc-util.la
time_t squid_curtime;
#endif

/* Regular Format de-coding tests */
void testRFC1738::testUrlDecode()
{
    char *unescaped_str;

    /* regular URL-path */
    unescaped_str = xstrdup("%2Fdata%2Fsource%2Fpath");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "/data/source/path",18)==0);
    xfree(unescaped_str);

    /* path in full URL */
    unescaped_str = xstrdup("http://foo.invalid%2Fdata%2Fsource%2Fpath");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "http://foo.invalid/data/source/path",36)==0);
    xfree(unescaped_str);

// TODO query string...

    /* Newline %0A encoded */
    unescaped_str = xstrdup("w%0Ard");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w\nrd",5)==0);
    xfree(unescaped_str);

    /* Handle Un-encoded % */
    unescaped_str = xstrdup("w%rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%rd",5)==0);
    xfree(unescaped_str);

    /* Handle encoded % */
    unescaped_str = xstrdup("w%%rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%rd",5)==0);
    xfree(unescaped_str);

    /* Handle mixed-encoded % */
    unescaped_str = xstrdup("w%%%rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%%rd",6)==0);
    xfree(unescaped_str);

    /* A corrupt string */
    unescaped_str = xstrdup("Bad String %1");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "Bad String %1",14)==0);
    xfree(unescaped_str);

    /* A partly corrupt string */
    unescaped_str = xstrdup("Bad String %1A%3");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "Bad String \032%3",15)==0);
    xfree(unescaped_str);

    /* A non corrupt string */
    unescaped_str = xstrdup("Good String %1A");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "Good String \032",14)==0);
    xfree(unescaped_str);
}

/**
 * Public API is formed of a triplet of encode functions mapping to the rfc1738_do_encode() engine.
 *
 * Flags:
 * rfc1738_escape == 0
 * rfc1738_escape_unescaped == -1
 * rfc1738_escape_part == 1
 */
void testRFC1738::testUrlEncode()
{
    char *result;

    /* TEST: Escaping only unsafe characters */

    /* regular URL (no encoding needed) */
    result = rfc1738_do_escape("http://foo.invalid/data/source/path", RFC1738_ESCAPE_UNSAFE);
    CPPUNIT_ASSERT(memcmp(result, "http://foo.invalid/data/source/path",36)==0);

    /* long string of unsafe # characters */
    result = rfc1738_do_escape("################ ################ ################ ################ ################ ################ ################ ################", RFC1738_ESCAPE_UNSAFE);
    CPPUNIT_ASSERT(memcmp(result, "%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%20%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23",406)==0);

    /* TEST: escaping only reserved characters */

    /* regular URL (full encoding requested) */
    result = rfc1738_do_escape("http://foo.invalid/data/source/path", RFC1738_ESCAPE_RESERVED);
    CPPUNIT_ASSERT(memcmp(result, "http%3A%2F%2Ffoo.invalid%2Fdata%2Fsource%2Fpath",48)==0);

    /* regular path (encoding wanted for ALL special chars) */
    result = rfc1738_do_escape("/data/source/path", RFC1738_ESCAPE_RESERVED);
    CPPUNIT_ASSERT(memcmp(result, "%2Fdata%2Fsource%2Fpath",24)==0);

    /* TEST: safety-escaping a string already partially escaped */

    /* escaping of dangerous characters in a partially escaped string */
    result = rfc1738_do_escape("http://foo.invalid/data%2Fsource[]", RFC1738_ESCAPE_UNESCAPED);
    CPPUNIT_ASSERT(memcmp(result, "http://foo.invalid/data%2Fsource%5B%5D",39)==0);

    /* escaping of hexadecimal 0xFF characters in a partially escaped string */
    result = rfc1738_do_escape("http://foo.invalid/data%2Fsource\xFF\xFF", RFC1738_ESCAPE_UNESCAPED);
    CPPUNIT_ASSERT(memcmp(result, "http://foo.invalid/data%2Fsource%FF%FF",39)==0);

}

/** SECURITY BUG TESTS: avoid null truncation attacks by skipping %00 bytes */
void testRFC1738::PercentZeroNullDecoding()
{
    char *unescaped_str;

    /* Attack with %00 encoded NULL */
    unescaped_str = xstrdup("w%00rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%00rd",7)==0);
    xfree(unescaped_str);

    /* Attack with %0 encoded NULL */
    unescaped_str = xstrdup("w%0rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%0rd",6)==0);
    xfree(unescaped_str);

    /* Handle '0' bytes embeded in encoded % */
    unescaped_str = xstrdup("w%%00%rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%00%rd",8)==0);
    xfree(unescaped_str);

    /* Handle NULL bytes with encoded % */
    unescaped_str = xstrdup("w%%%00%rd");
    rfc1738_unescape(unescaped_str);
    CPPUNIT_ASSERT(memcmp(unescaped_str, "w%%00%rd",9)==0);
    xfree(unescaped_str);
}

