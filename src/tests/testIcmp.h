/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTICMP_H
#define SQUID_SRC_TESTS_TESTICMP_H

#include <cppunit/extensions/HelperMacros.h>

#if USE_ICMP

#include "icmp/Icmp.h"

class stubIcmp : public Icmp
{
public:
    stubIcmp() {};
    virtual ~stubIcmp() {};
    virtual int Open() { return 0; };
    virtual void Close() {};

    /// Construct ECHO request
    virtual void SendEcho(Ip::Address &to, int opcode, const char *payload, int len) {};

    /// Handle ICMP responses.
    virtual void Recv(void) {};

    /* methods to relay test data from tester to private methods being tested */
    int testChecksum(unsigned short *ptr, int size) { return CheckSum(ptr,size); };
    int testHops(int ttl) { return ipHops(ttl); };
};
#endif

/**
 * test the ICMP base class.
 */
class testIcmp : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testIcmp );
    CPPUNIT_TEST( testChecksum );
    CPPUNIT_TEST( testHops );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testChecksum();
    void testHops();
};

#endif /* SQUID_SRC_TESTS_TESTICMP_H */

