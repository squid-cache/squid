/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "tests/testIpAddress.h"
#include "unitTestMain.h"

#include <cstring>
#include <stdexcept>
#include <string>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( testIpAddress );

/* so that we don't break POD dependency just for the test */
struct timeval current_time;
double current_dtime;
time_t squid_curtime = 0;
int shutting_down = 0;

void
testIpAddress::testDefaults()
{
    Ip::Address anIPA;

    /* test stored values */
    CPPUNIT_ASSERT( anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( !anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    CPPUNIT_ASSERT( anIPA.isIPv6() );
}

void
testIpAddress::testInAddrConstructor()
{
    struct in_addr inval;
    struct in_addr outval;

    inval.s_addr = htonl(0xC0A8640C);
    outval.s_addr = htonl(0x00000000);

    Ip::Address anIPA(inval);

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp(&inval, &outval, sizeof(struct in_addr)) == 0 );
}

void
testIpAddress::testInAddr6Constructor()
{
    struct in6_addr inval;
    struct in6_addr outval = IN6ADDR_ANY_INIT;

    inval.s6_addr32[0] = htonl(0xC0A8640C);
    inval.s6_addr32[1] = htonl(0xFFFFFFFF);
    inval.s6_addr32[2] = htonl(0xFFFFFFFF);
    inval.s6_addr32[3] = htonl(0xFFFFFFFF);

    Ip::Address anIPA(inval);

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( !anIPA.isIPv4() );
    CPPUNIT_ASSERT( anIPA.isIPv6() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &inval, &outval, sizeof(struct in6_addr)) == 0 );
}

void
testIpAddress::testSockAddrConstructor()
{
    struct sockaddr_in insock;
    struct sockaddr_in outsock;

    memset(&insock,  0, sizeof(struct sockaddr_in));
    memset(&outsock, 0, sizeof(struct sockaddr_in));

    insock.sin_family = AF_INET;
    insock.sin_port = htons(80);
    insock.sin_addr.s_addr = htonl(0xC0A8640C);
#if HAVE_SIN_LEN_IN_SAI
    insock.sin_len = sizeof(struct sockaddr_in);
#endif

    Ip::Address anIPA(insock);

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT( anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 80, anIPA.port() );
    anIPA.getSockAddr(outsock);
    CPPUNIT_ASSERT( memcmp( &insock, &outsock, sizeof(struct sockaddr_in)) == 0 );
}

void
testIpAddress::testSockAddr6Constructor()
{
    struct sockaddr_in6 insock;
    struct sockaddr_in6 outsock;

    memset(&insock, 0, sizeof(struct sockaddr_in6));
    memset(&outsock, 0, sizeof(struct sockaddr_in6));

    insock.sin6_family = AF_INET6;
    insock.sin6_port = htons(80);
    insock.sin6_addr.s6_addr32[0] = htonl(0xFFFFFFFF);
    insock.sin6_addr.s6_addr32[1] = htonl(0x00000000);
    insock.sin6_addr.s6_addr32[2] = htonl(0x0000FFFF);
    insock.sin6_addr.s6_addr32[3] = htonl(0xC0A8640C);
#if HAVE_SIN6_LEN_IN_SAI
    insock.sin6_len = sizeof(struct sockaddr_in6);
#endif

    Ip::Address anIPA((const struct sockaddr_in6)insock);

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( !anIPA.isIPv4() );
    CPPUNIT_ASSERT( anIPA.isIPv6() );
    CPPUNIT_ASSERT( anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 80, anIPA.port() );
    anIPA.getSockAddr(outsock);
    CPPUNIT_ASSERT( memcmp( &insock, &outsock, sizeof(struct sockaddr_in6)) == 0 );
}

void
testIpAddress::testCopyConstructor()
{
    struct sockaddr_in insock;
    struct sockaddr_in outsock;

    memset(&insock,  0, sizeof(struct sockaddr_in));
    memset(&outsock, 0, sizeof(struct sockaddr_in));

    insock.sin_family = AF_INET;
    insock.sin_port = htons(80);
    insock.sin_addr.s_addr = htonl(0xC0A8640C);
#if HAVE_SIN_LEN_IN_SAI
    insock.sin_len = sizeof(struct sockaddr_in);
#endif

    Ip::Address inIPA(insock);
    Ip::Address outIPA(inIPA);

    /* test stored values */
    CPPUNIT_ASSERT( !outIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !outIPA.isNoAddr() );
    CPPUNIT_ASSERT( outIPA.isIPv4() );
    CPPUNIT_ASSERT( !outIPA.isIPv6() );
    CPPUNIT_ASSERT( outIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 80, outIPA.port() );
    outIPA.getSockAddr(outsock);
    CPPUNIT_ASSERT( memcmp( &insock, &outsock, sizeof(struct sockaddr_in)) == 0 );
}

void
testIpAddress::testHostentConstructor()
{
    struct hostent *hp = NULL;
    struct in_addr outval;
    struct in_addr expectval;

    expectval.s_addr = htonl(0xC0A8640C);

    hp = gethostbyname("192.168.100.12");
    CPPUNIT_ASSERT( hp != NULL /* gethostbyname failure.*/ );

    Ip::Address anIPA(*hp);

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &expectval, &outval, sizeof(struct in_addr)) == 0 );
}

void
testIpAddress::testStringConstructor()
{
    struct in_addr outval;
    struct in_addr expectval;

    expectval.s_addr = htonl(0xC0A8640C);

    Ip::Address anIPA = "192.168.100.12";

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &expectval, &outval, sizeof(struct in_addr)) == 0 );

    struct in6_addr expectv6;
    struct in6_addr outval6;

    expectv6.s6_addr32[0] = htonl(0x20000800);
    expectv6.s6_addr32[1] = htonl(0x00000000);
    expectv6.s6_addr32[2] = htonl(0x00000000);
    expectv6.s6_addr32[3] = htonl(0x00000045);

    Ip::Address bnIPA = "2000:800::45";

//char test[256];
//bnIPA.toStr(test, 256);
//printf("bnIPA: %s\n", test);

    /* test stored values */
    CPPUNIT_ASSERT( !bnIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !bnIPA.isNoAddr() );
    CPPUNIT_ASSERT( !bnIPA.isIPv4() );
    CPPUNIT_ASSERT(  bnIPA.isIPv6() );
    CPPUNIT_ASSERT( !bnIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, bnIPA.port() );
    bnIPA.getInAddr(outval6);
    CPPUNIT_ASSERT( memcmp( &expectv6, &outval6, sizeof(struct in6_addr)) == 0 );

    /* test IPv6 as an old netmask format. This is invalid but sometimes use. */
    Ip::Address cnIPA = "ffff:ffff:fff0::";

    expectv6.s6_addr32[0] = htonl(0xFFFFFFFF);
    expectv6.s6_addr32[1] = htonl(0xFFF00000);
    expectv6.s6_addr32[2] = htonl(0x00000000);
    expectv6.s6_addr32[3] = htonl(0x00000000);

    /* test stored values */
    CPPUNIT_ASSERT( !cnIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !cnIPA.isNoAddr() );
    CPPUNIT_ASSERT( !cnIPA.isIPv4() );
    CPPUNIT_ASSERT( cnIPA.isIPv6() );
    CPPUNIT_ASSERT( !cnIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, cnIPA.port() );
    cnIPA.getInAddr(outval6);
    CPPUNIT_ASSERT( memcmp( &expectv6, &outval6, sizeof(struct in6_addr)) == 0 );
}

void
testIpAddress::testsetEmpty()
{
    Ip::Address anIPA;
    struct in_addr inval;

    inval.s_addr = htonl(0xC0A8640C);

    anIPA = inval;

    /* test stored values before empty */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );

    anIPA.setEmpty();

    /* test stored values after empty */
    CPPUNIT_ASSERT( anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( !anIPA.isIPv4() );
    CPPUNIT_ASSERT( anIPA.isIPv6() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
}

void
testIpAddress::testBooleans()
{
    Ip::Address lhsIPA;
    Ip::Address rhsIPA;
    struct in_addr valLow;
    struct in_addr valHigh;

    valLow.s_addr  = htonl(0xC0A8640C);
    valHigh.s_addr = htonl(0xC0A8640F);

    /* test equality */
    lhsIPA = valLow;
    rhsIPA = valLow;
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) == 0 );
    CPPUNIT_ASSERT(  ( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <  rhsIPA ) );

    /* test equality versus ANYADDR */
    lhsIPA.setAnyAddr();
    rhsIPA.setAnyAddr();
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) == 0 );
    CPPUNIT_ASSERT(  ( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <  rhsIPA ) );

    /* test equality versus NOADDR */
    lhsIPA.setNoAddr();
    rhsIPA.setNoAddr();
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) == 0 );
    CPPUNIT_ASSERT(  ( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <  rhsIPA ) );

    /* test inequality (less than) */
    lhsIPA = valLow;
    rhsIPA = valHigh;
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) < 0 );
    CPPUNIT_ASSERT( !( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <  rhsIPA ) );

    /* test inequality versus ANYADDR (less than) */
    lhsIPA.setAnyAddr();
    rhsIPA = valHigh;
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) < 0 );
    CPPUNIT_ASSERT( !( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <  rhsIPA ) );

    /* test inequality versus NOADDR (less than) */
    lhsIPA = valLow;
    rhsIPA.setNoAddr();
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) < 0 );
    CPPUNIT_ASSERT( !( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA <  rhsIPA ) );

    /* test inequality (greater than) */
    lhsIPA = valHigh;
    rhsIPA = valLow;
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) > 0 );
    CPPUNIT_ASSERT( !( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <  rhsIPA ) );

    /* test inequality (greater than) */
    lhsIPA = valHigh;
    rhsIPA.setAnyAddr();
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) > 0 );
    CPPUNIT_ASSERT( !( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <  rhsIPA ) );

    /* test inequality versus NOADDR (greater than) */
    lhsIPA.setNoAddr();
    rhsIPA = valLow;
    CPPUNIT_ASSERT( lhsIPA.matchIPAddr(rhsIPA) > 0 );
    CPPUNIT_ASSERT( !( lhsIPA == rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA != rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >= rhsIPA ) );
    CPPUNIT_ASSERT(  ( lhsIPA >  rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <= rhsIPA ) );
    CPPUNIT_ASSERT( !( lhsIPA <  rhsIPA ) );

}

void
testIpAddress::testtoStr()
{
    struct in_addr inval;
    char buf[MAX_IPSTRLEN];
    Ip::Address anIPA;

    anIPA.setAnyAddr();

    /* test AnyAddr display values */
    CPPUNIT_ASSERT( memcmp("::", anIPA.toStr(buf,MAX_IPSTRLEN), 2) == 0 );

    inval.s_addr = htonl(0xC0A8640C);
    anIPA = inval;

    /* test IP display */
    CPPUNIT_ASSERT( memcmp("192.168.100.12",anIPA.toStr(buf,MAX_IPSTRLEN), 14) == 0 );

    anIPA.setNoAddr();

    /* test NoAddr display values */
    CPPUNIT_ASSERT( memcmp("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",anIPA.toStr(buf,MAX_IPSTRLEN), 39) == 0 );
}

void
testIpAddress::testtoUrl_fromInAddr()
{
    char buf[MAX_IPSTRLEN];
    buf[0] = '\0';
    struct in_addr inval;

    inval.s_addr = htonl(0xC0A8640C);

    Ip::Address anIPA(inval);

    /* test values */
    anIPA.toUrl(buf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( memcmp("192.168.100.12", buf, 14) == 0 );

    /* test output when constructed from in6_addr with IPv6 */
    struct in6_addr ip6val;

    ip6val.s6_addr32[0] = htonl(0xC0A8640C);
    ip6val.s6_addr32[1] = htonl(0xFFFFFFFF);
    ip6val.s6_addr32[2] = htonl(0xFFFFFFFF);
    ip6val.s6_addr32[3] = htonl(0xFFFFFFFF);

    Ip::Address bnIPA(ip6val);

    bnIPA.toUrl(buf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( memcmp("[c0a8:640c:ffff:ffff:ffff:ffff:ffff:ffff]", buf, 41) == 0 );
}

void
testIpAddress::testtoUrl_fromSockAddr()
{
    struct sockaddr_in sock;
    sock.sin_addr.s_addr = htonl(0xC0A8640C);
    sock.sin_port = htons(80);
    sock.sin_family = AF_INET;
#if HAVE_SIN_LEN_IN_SAI
    sock.sin_len = sizeof(struct sockaddr_in);
#endif

    Ip::Address anIPA(sock);
    char buf[MAX_IPSTRLEN];

    /* test values */
    anIPA.toUrl(buf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( memcmp("192.168.100.12:80", buf, 17) == 0 );

    /* test output when constructed from in6_addr with IPv6 */
    struct sockaddr_in6 ip6val;

    ip6val.sin6_addr.s6_addr32[0] = htonl(0xC0A8640C);
    ip6val.sin6_addr.s6_addr32[1] = htonl(0xFFFFFFFF);
    ip6val.sin6_addr.s6_addr32[2] = htonl(0xFFFFFFFF);
    ip6val.sin6_addr.s6_addr32[3] = htonl(0xFFFFFFFF);
    ip6val.sin6_port = htons(80);
    ip6val.sin6_family = AF_INET6;
#if HAVE_SIN6_LEN_IN_SAI
    ip6val.sin6_len = sizeof(struct sockaddr_in6);
#endif

    Ip::Address bnIPA(ip6val);

    bnIPA.toUrl(buf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( memcmp("[c0a8:640c:ffff:ffff:ffff:ffff:ffff:ffff]:80", buf, 44) == 0 );
}

void
testIpAddress::testgetReverseString()
{
    char buf[MAX_IPSTRLEN];

    struct in_addr ipv4val;
    ipv4val.s_addr = htonl(0xC0A8640C);

    Ip::Address v4IPA(ipv4val);

    /* test IPv4 output */
    v4IPA.getReverseString(buf);
    CPPUNIT_ASSERT( memcmp("12.100.168.192.in-addr.arpa.",buf, 28) == 0 );

    v4IPA.getReverseString(buf,AF_INET);
    CPPUNIT_ASSERT( memcmp("12.100.168.192.in-addr.arpa.",buf, 28) == 0 );

    v4IPA.getReverseString(buf,AF_INET6);
    CPPUNIT_ASSERT( memcmp("",buf, 1) == 0 );

    struct in6_addr ip6val;

    ip6val.s6_addr32[0] = htonl(0xC0A8640C);
    ip6val.s6_addr32[1] = htonl(0xFFFFFFFF);
    ip6val.s6_addr32[2] = htonl(0xFFFFFFFF);
    ip6val.s6_addr32[3] = htonl(0xFFFFFFFF);

    Ip::Address v6IPA(ip6val);

    /* test IPv6 output */
    v6IPA.getReverseString(buf);
    CPPUNIT_ASSERT( memcmp("f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.c.0.4.6.8.a.0.c.ip6.arpa.",buf,73) == 0 );
}

void
testIpAddress::testMasking()
{
    char buf[MAX_IPSTRLEN];
    Ip::Address anIPA;
    Ip::Address maskIPA;

    /* Test Basic CIDR Routine */
    anIPA.setAnyAddr();
    CPPUNIT_ASSERT_EQUAL( 0,anIPA.cidr() );

    anIPA.setNoAddr();
    CPPUNIT_ASSERT_EQUAL( 128, anIPA.cidr() );

    /* Test Numeric ApplyCIDR */
    anIPA.setNoAddr();
    CPPUNIT_ASSERT( !anIPA.applyMask(129,AF_INET6) );
    CPPUNIT_ASSERT( !anIPA.applyMask(33,AF_INET) );

    anIPA.setNoAddr();
    CPPUNIT_ASSERT( anIPA.applyMask(31,AF_INET) );
    CPPUNIT_ASSERT_EQUAL( 127, anIPA.cidr() );

    anIPA.setNoAddr();
    CPPUNIT_ASSERT( anIPA.applyMask(127,AF_INET6) );
    CPPUNIT_ASSERT_EQUAL( 127, anIPA.cidr() );

    anIPA.setNoAddr();
    anIPA.applyMask(80,AF_INET6);
    CPPUNIT_ASSERT_EQUAL( 80, anIPA.cidr() );

    /* BUG Check: test values by display. */
    CPPUNIT_ASSERT( anIPA.toStr(buf,MAX_IPSTRLEN) != NULL );
    CPPUNIT_ASSERT( memcmp("ffff:ffff:ffff:ffff:ffff::", buf, 26) == 0 );

    /* Test Network Bitmask from Ip::Address */
    anIPA.setNoAddr();
    maskIPA = "255.255.240.0";
    CPPUNIT_ASSERT_EQUAL( 20, maskIPA.cidr() );
    anIPA.applyMask(maskIPA);
    CPPUNIT_ASSERT_EQUAL( 20, anIPA.cidr() );

    /* BUG Check: test values memory after masking. */
    struct in_addr btest;
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    anIPA.getInAddr(btest);
    CPPUNIT_ASSERT_EQUAL( (uint32_t)htonl(0xFFFFF000), btest.s_addr );

    /* BUG Check failing test. Masked values for display. */
    CPPUNIT_ASSERT( memcmp("255.255.240.0",anIPA.toStr(buf,MAX_IPSTRLEN), 13) == 0 );

    anIPA.setNoAddr();
    maskIPA.setNoAddr();

    /* IPv6 masks MUST be CIDR representations. */
    /* however as with IPv4 they can technically be represented as a bitmask */
    maskIPA = "ffff:ffff:fff0::";
    CPPUNIT_ASSERT( !maskIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !maskIPA.isNoAddr() );
    anIPA.applyMask(maskIPA);
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT_EQUAL( 44, anIPA.cidr() );

    anIPA.setNoAddr();
    maskIPA.setNoAddr();

    /* IPv4 masks represented in IPv6 as IPv4 bitmasks. */
    maskIPA = "::ffff:ffff:f000";
    CPPUNIT_ASSERT( !maskIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !maskIPA.isNoAddr() );
    CPPUNIT_ASSERT(  maskIPA.isIPv4() );
    CPPUNIT_ASSERT( !maskIPA.isIPv6() );
    anIPA.applyMask(maskIPA);
    CPPUNIT_ASSERT( !maskIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !maskIPA.isNoAddr() );
    CPPUNIT_ASSERT(  maskIPA.isIPv4() );
    CPPUNIT_ASSERT( !maskIPA.isIPv6() );
    CPPUNIT_ASSERT_EQUAL( 20, anIPA.cidr() );
}

void
testIpAddress::testAddrInfo()
{
    struct addrinfo *expect;
    struct addrinfo *ipval = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_NUMERICHOST;

    Ip::Address anIP = "127.0.0.1";

    /* assert this just to check that getaddrinfo is working properly */
    CPPUNIT_ASSERT( getaddrinfo("127.0.0.1", NULL, &hints, &expect ) == 0 );

    anIP.getAddrInfo(ipval);

#if 0
    /* display a byte-by-byte hex comparison of the addr cores */
    unsigned int *p;
    p = (unsigned int*)expect;
    printf("\nSYS-ADDRINFO: %2x %2x %2x %2x %2x %2x",
           p[0],p[1],p[2],p[3],p[4],p[5]);

    p = (unsigned int*)ipval;
    printf("\nSQD-ADDRINFO: %2x %2x %2x %2x %2x %2x",
           p[0],p[1],p[2],p[3],p[4],p[5] );
    printf("\n");
#endif /*0*/

    // check the addrinfo object core. (BUT not the two ptrs at the tail)
    // details
    CPPUNIT_ASSERT_EQUAL( expect->ai_flags, ipval->ai_flags );
    CPPUNIT_ASSERT_EQUAL( expect->ai_family, ipval->ai_family );
    // check the sockaddr it points to.
    CPPUNIT_ASSERT_EQUAL( expect->ai_addrlen, ipval->ai_addrlen );

#if 0
    printf("sizeof IN(%d), IN6(%d), STORAGE(%d), \n",
           sizeof(struct sockaddr_in), sizeof(struct sockaddr_in6), sizeof(struct sockaddr_storage));

    p = (unsigned int*)(expect->ai_addr);
    printf("\nSYS-ADDR: (%d) {%d} %x %x %x %x %x %x %x %x ...",
           expect->ai_addrlen, sizeof(*p),
           p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7] );

    p = (unsigned int*)(ipval->ai_addr);
    printf("\nSQD-ADDR: (%d) {%d} %x %x %x %x %x %x %x %x ...",
           ipval->ai_addrlen, sizeof(*p),
           p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7] );
    printf("\n");
#if HAVE_SS_LEN_IN_SS
    printf("\nSYS SS_LEN=%d\nSQD SS_LEN=%d\n",((struct sockaddr_storage*)expect->ai_addr)->ss_len,
           ((struct sockaddr_storage*)ipval->ai_addr)->ss_len );
#endif
#endif /*0*/

#if HAVE_SS_LEN_IN_SS
    CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_storage*)expect->ai_addr)->ss_len,
                          ((struct sockaddr_storage*)ipval->ai_addr)->ss_len );
    CPPUNIT_ASSERT_EQUAL( (socklen_t)((struct sockaddr_storage*)ipval->ai_addr)->ss_len, ipval->ai_addrlen );
#endif
#if HAVE_SIN6_LEN_IN_SAI
    CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_in6*)expect->ai_addr)->sin6_len,
                          ((struct sockaddr_in6*)ipval->ai_addr)->sin6_len );
    CPPUNIT_ASSERT_EQUAL( (socklen_t)((struct sockaddr_in6*)ipval->ai_addr)->sin6_len, ipval->ai_addrlen );
#endif
#if HAVE_SIN_LEN_IN_SAI
    CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_in*)expect->ai_addr)->sin_len,
                          ((struct sockaddr_in*)ipval->ai_addr)->sin_len );
    CPPUNIT_ASSERT_EQUAL( (socklen_t)((struct sockaddr_in*)ipval->ai_addr)->sin_len, ipval->ai_addrlen );
#endif

    if (expect->ai_addrlen == sizeof(struct sockaddr_in)) {
//printf("FAMILY %d %d\n", ((struct sockaddr_in*)expect->ai_addr)->sin_family, ((struct sockaddr_in*)ipval->ai_addr)->sin_family);
        CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_in*)expect->ai_addr)->sin_family,
                              ((struct sockaddr_in*)ipval->ai_addr)->sin_family );
//printf("PORT %d %d\n", ((struct sockaddr_in*)expect->ai_addr)->sin_port, ((struct sockaddr_in*)ipval->ai_addr)->sin_port);
        CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_in*)expect->ai_addr)->sin_port,
                              ((struct sockaddr_in*)ipval->ai_addr)->sin_port );
    }
    if (expect->ai_addrlen == sizeof(struct sockaddr_in6)) {
//printf("FAMILY %d %d\n", ((struct sockaddr_in6*)expect->ai_addr)->sin6_family, ((struct sockaddr_in6*)ipval->ai_addr)->sin6_family);
        CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_in6*)expect->ai_addr)->sin6_family,
                              ((struct sockaddr_in6*)ipval->ai_addr)->sin6_family );
//printf("PORT %d %d\n", ((struct sockaddr_in6*)expect->ai_addr)->sin6_port, ((struct sockaddr_in6*)ipval->ai_addr)->sin6_port);
        CPPUNIT_ASSERT_EQUAL( ((struct sockaddr_in6*)expect->ai_addr)->sin6_port,
                              ((struct sockaddr_in6*)ipval->ai_addr)->sin6_port );
    }

    CPPUNIT_ASSERT( memcmp( expect->ai_addr, ipval->ai_addr, expect->ai_addrlen ) == 0 );

    freeaddrinfo(expect);
    Ip::Address::FreeAddr(ipval);
}

void
testIpAddress::testBugNullingDisplay()
{
    // Weird Bug: address set to empty during string conversion somewhere.
    // initial string gets created and returned OK.
    // but at the end of the process m_SocketAddr is left NULL'ed

    char ntoabuf[MAX_IPSTRLEN];
    char hostbuf[MAX_IPSTRLEN];
    char urlbuf[MAX_IPSTRLEN];

    struct in_addr outval;
    struct in_addr expectval;

    expectval.s_addr = htonl(0xC0A8640C);

    Ip::Address anIPA = "192.168.100.12";

    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &expectval, &outval, sizeof(struct in_addr)) == 0 );

    /* POKE toStr display function to see what it is doing */
    anIPA.toStr(ntoabuf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &expectval, &outval, sizeof(struct in_addr)) == 0 );

    /* POKE toHostStr display function to see what it is doing */
    anIPA.toHostStr(hostbuf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &expectval, &outval, sizeof(struct in_addr)) == 0 );

    /* POKE toUrl display function to see what it is doing */
    anIPA.toUrl(urlbuf,MAX_IPSTRLEN);
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    /* test stored values */
    CPPUNIT_ASSERT( !anIPA.isAnyAddr() );
    CPPUNIT_ASSERT( !anIPA.isNoAddr() );
    CPPUNIT_ASSERT( anIPA.isIPv4() );
    CPPUNIT_ASSERT( !anIPA.isIPv6() );
    CPPUNIT_ASSERT_EQUAL( (unsigned short) 0, anIPA.port() );
    CPPUNIT_ASSERT( !anIPA.isSockAddr() );
    anIPA.getInAddr(outval);
    CPPUNIT_ASSERT( memcmp( &expectval, &outval, sizeof(struct in_addr)) == 0 );

}

