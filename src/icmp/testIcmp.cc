#define SQUID_UNIT_TEST 1
#define SQUID_HELPER 1

#include "squid.h"

#include <cppunit/TestAssert.h>

#include "testIcmp.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testIcmp );

#if USE_ICMP

void
testIcmp::testChecksum()
{
    stubIcmp icmp;
    short unsigned int buf[10] = {1,2,3,4,5,6,7,8,9};

    // NULL data
    CPPUNIT_ASSERT_EQUAL(65535, icmp.testChecksum(NULL,0));

    // NULL data with length!!
    CPPUNIT_ASSERT_EQUAL(65535, icmp.testChecksum(NULL,1));

    // data with 0 length
    CPPUNIT_ASSERT_EQUAL(65535, icmp.testChecksum(buf,0));

    // data with invalid length (low)
    CPPUNIT_ASSERT_EQUAL(65534, icmp.testChecksum(buf,1));

    // data with invalid length (max-low)
    CPPUNIT_ASSERT_EQUAL(65520, icmp.testChecksum(buf,9));

    // data with accurate length
    CPPUNIT_ASSERT_EQUAL(65520, icmp.testChecksum(buf,10));

    // data with invalid length (overrun)
    CPPUNIT_ASSERT_EQUAL(65514, icmp.testChecksum(buf,11));
}

void
testIcmp::testHops()
{
    stubIcmp icmp;

    /* test invalid -(under values) */
    // negative     : n > 33
    CPPUNIT_ASSERT_EQUAL(34, icmp.testHops(-1));
    // zero
    CPPUNIT_ASSERT_EQUAL(33, icmp.testHops(0));

    /* test each valid case boundary */
    // n(1...32)    : 32 >= n >= 1
    CPPUNIT_ASSERT_EQUAL(32, icmp.testHops(1));
    CPPUNIT_ASSERT_EQUAL(1, icmp.testHops(32));

    // n(33...62)   : 30 >= n >= 1
    CPPUNIT_ASSERT_EQUAL(30, icmp.testHops(33));
    CPPUNIT_ASSERT_EQUAL(1, icmp.testHops(62));

    // n(63...64)  : 2 >= n >= 1
    CPPUNIT_ASSERT_EQUAL(2, icmp.testHops(63));
    CPPUNIT_ASSERT_EQUAL(1, icmp.testHops(64));

    // n(65...128)  : 64 >= n >= 1
    CPPUNIT_ASSERT_EQUAL(64, icmp.testHops(65));
    CPPUNIT_ASSERT_EQUAL(1, icmp.testHops(128));

    // n(129...192) : 64 >= n >= 1
    CPPUNIT_ASSERT_EQUAL(64, icmp.testHops(129));
    CPPUNIT_ASSERT_EQUAL(1, icmp.testHops(192));

    // n(193...)    : n < 63
    CPPUNIT_ASSERT_EQUAL(63, icmp.testHops(193));
    CPPUNIT_ASSERT_EQUAL(1, icmp.testHops(255));

    /* test invalid (over values) */
    // 256 - produces zero
    CPPUNIT_ASSERT_EQUAL(0, icmp.testHops(256));
    // 257 - produces negative hops
    CPPUNIT_ASSERT_EQUAL(-1, icmp.testHops(257));
}

#endif /* USE_ICMP */
