/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "dns/rfc1035.h"
#include "testRFC1035.h"
#include "unitTestMain.h"

#include <cassert>

CPPUNIT_TEST_SUITE_REGISTRATION( testRFC1035 );

// TODO Test each function in the Library independently
//  Just because we can for global functions.
//  It's good for the code too.

void testRFC1035::testHeaderUnpack()
{
    /* Setup a buffer with the known-content packet */
    const char *buf = "\x76\xb1\x81\x80\x00\x01\x00\x01\x00\x02\x00\x02\x03\x77\x77\x77\x07\x67\x61\x6d\x65\x64\x65\x76\x03\x6e\x65\x74\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\x00\x04\xd8\xb9\x60\xea\xc0\x10\x00\x02\x00\x01\x00\x00\x00\xef\x00\x0f\x03\x6e\x73\x32\x05\x7a\x77\x61\x76\x65\x03\x63\x6f\x6d\x00\xc0\x10\x00\x02\x00\x01\x00\x00\x00\xef\x00\x06\x03\x6e\x73\x31\xc0\x41\xc0\x3d\x00\x01\x00\x01\x00\x00\x29\x6b\x00\x04\xd8\xea\xee\x4a\xc0\x58\x00\x01\x00\x01\x00\x00\x29\x6b\x00\x04\xd8\xea\xee\x4b";
    size_t len = 126;
    rfc1035_message *msg = NULL;
    int res = 0;
    unsigned int off = 0;

    /* Test the HeaderUnpack function */
    msg = new rfc1035_message;
    res = rfc1035HeaderUnpack(buf, len, &off, msg);
    CPPUNIT_ASSERT(res == 0);
    CPPUNIT_ASSERT_EQUAL((short unsigned int)0x76b1, msg->id);
    CPPUNIT_ASSERT(msg->qr == 1);
    /* flags */
    CPPUNIT_ASSERT_EQUAL((unsigned int)0, msg->opcode);
    CPPUNIT_ASSERT_EQUAL((unsigned int)0, msg->aa);
    CPPUNIT_ASSERT_EQUAL((unsigned int)0, msg->tc);
    CPPUNIT_ASSERT_EQUAL((unsigned int)1, msg->rd);
    CPPUNIT_ASSERT_EQUAL((unsigned int)1, msg->ra);
    CPPUNIT_ASSERT_EQUAL((unsigned int)0, msg->rcode);
    /* RR counts */
    CPPUNIT_ASSERT_EQUAL((unsigned short)1, msg->qdcount);
    CPPUNIT_ASSERT_EQUAL((unsigned short)1, msg->ancount);
    CPPUNIT_ASSERT_EQUAL((unsigned short)2, msg->nscount);
    CPPUNIT_ASSERT_EQUAL((unsigned short)2, msg->arcount);

    /* cleanup */
    delete msg;
    msg = NULL;
}

void testRFC1035::testParseAPacket()
{
    /* Setup a buffer with the known-content packet */
    const char *buf = "\x76\xb1\x81\x80\x00\x01\x00\x01\x00\x02\x00\x02\x03\x77\x77\x77\x07\x67\x61\x6d\x65\x64\x65\x76\x03\x6e\x65\x74\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\x00\x04\xd8\xb9\x60\xea\xc0\x10\x00\x02\x00\x01\x00\x00\x00\xef\x00\x0f\x03\x6e\x73\x32\x05\x7a\x77\x61\x76\x65\x03\x63\x6f\x6d\x00\xc0\x10\x00\x02\x00\x01\x00\x00\x00\xef\x00\x06\x03\x6e\x73\x31\xc0\x41\xc0\x3d\x00\x01\x00\x01\x00\x00\x29\x6b\x00\x04\xd8\xea\xee\x4a\xc0\x58\x00\x01\x00\x01\x00\x00\x29\x6b\x00\x04\xd8\xea\xee\x4b";
    size_t len = 126;
    rfc1035_message *msg = NULL;
    int res = 0;

    /* Test the MessageUnpack function itself */
    res = rfc1035MessageUnpack(buf, len, &msg);

    CPPUNIT_ASSERT_EQUAL(1, res);
    CPPUNIT_ASSERT(msg != NULL);
    /* cleanup */
    rfc1035MessageDestroy(&msg);
    CPPUNIT_ASSERT(msg == NULL);
}

void testRFC1035::testBugPacketEndingOnCompressionPtr()
{
    /* Setup a buffer with the known-to-fail packet */
    const char *buf = "\xec\x7b\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05\x62\x75\x72\x73\x74\x02\x74\x65\x06\x74\x61\x63\x6f\x64\x61\x03\x6e\x65\x74\x00\x00\x1c\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x19\xe5\x00\x0a\x02\x74\x65\x04\x67\x73\x6c\x62\xc0\x15";
    size_t len = 59;
    rfc1035_message *msg = NULL;
    int res = 0;
    unsigned int off = 0;

    /* Test the HeaderUnpack function results */
    msg = new rfc1035_message;
    res = rfc1035HeaderUnpack(buf, len, &off, msg);
    CPPUNIT_ASSERT(0 == res);
    CPPUNIT_ASSERT(0xec7b == msg->id);
    CPPUNIT_ASSERT(1 == msg->qr);
    /* flags */
    CPPUNIT_ASSERT(0 == msg->opcode);
    CPPUNIT_ASSERT(0 == msg->aa);
    CPPUNIT_ASSERT(0 == msg->tc);
    CPPUNIT_ASSERT(1 == msg->rd);
    CPPUNIT_ASSERT(1 == msg->ra);
    CPPUNIT_ASSERT(0 == msg->rcode);
    /* RR counts */
    CPPUNIT_ASSERT(1 == msg->qdcount);
    CPPUNIT_ASSERT(1 == msg->ancount);
    CPPUNIT_ASSERT(0 == msg->nscount);
    CPPUNIT_ASSERT(0 == msg->arcount);
    CPPUNIT_ASSERT(12 == off);
    printf("\n  Header : OK");
    /* cleanup */
    delete msg;
    msg = NULL;

// TODO explicitly test RR and Name unpack functions for this packet.

    /* Test the MessageUnpack function itself */
    res = rfc1035MessageUnpack(buf, len, &msg);

    CPPUNIT_ASSERT_EQUAL(1, res);
    CPPUNIT_ASSERT(msg != NULL);
    rfc1035MessageDestroy(&msg);
}

void testRFC1035::testBugPacketHeadersOnly()
{
    /* Setup a buffer with the known-to-fail headers-only packet */
    const char *buf = "\xab\xcd\x81\x80\x00\x01\x00\x05\x00\x04\x00\x04";
    size_t len = 12;
    rfc1035_message *msg = NULL;
    int res = 0;
    unsigned int off = 0;

    /* Test the HeaderUnpack function results */
    msg = new rfc1035_message;
    res = rfc1035HeaderUnpack(buf, len, &off, msg);
    CPPUNIT_ASSERT(0 == res);
    /* cleanup */
    delete msg;
    msg = NULL;

    /* Test the MessageUnpack function itself */
    res = rfc1035MessageUnpack(buf, len, &msg);

    CPPUNIT_ASSERT(0 == memcmp("The DNS reply message is corrupt or could not be safely parsed.", rfc1035ErrorMessage(res), 63));
    CPPUNIT_ASSERT(res < 0);
    CPPUNIT_ASSERT(msg == NULL);
}

