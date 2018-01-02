/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_RFC1035_H
#define SQUID_SRC_TEST_RFC1035_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the DNS resolver RFC 1035 Engine
 */

class testRFC1035 : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testRFC1035 );
    CPPUNIT_TEST( testHeaderUnpack );
    CPPUNIT_TEST( testParseAPacket );

    CPPUNIT_TEST( testBugPacketHeadersOnly );
    CPPUNIT_TEST( testBugPacketEndingOnCompressionPtr );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testHeaderUnpack();
    void testParseAPacket();

    // bugs.
    void testBugPacketEndingOnCompressionPtr();
    void testBugPacketHeadersOnly();
};

#endif /* SQUID_SRC_TEST_IPADDRESS_H */

