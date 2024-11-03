/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "anyp/UriScheme.h"
#include "compat/cppunit.h"

#include <cppunit/TestAssert.h>
#include <sstream>

/*
 * test UriScheme
 */

class TestUriScheme : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestUriScheme);
    CPPUNIT_TEST(testAssignFromprotocol_t);
    CPPUNIT_TEST(testCastToprotocol_t);
    CPPUNIT_TEST(testConstructprotocol_t);
    CPPUNIT_TEST(testDefaultConstructor);
    CPPUNIT_TEST(testEqualprotocol_t);
    CPPUNIT_TEST(testNotEqualprotocol_t);
    CPPUNIT_TEST(testC_str);
    CPPUNIT_TEST(testStream);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testAssignFromprotocol_t();
    void testCastToprotocol_t();
    void testConstructprotocol_t();
    void testC_str();
    void testDefaultConstructor();
    void testEqualprotocol_t();
    void testNotEqualprotocol_t();
    void testStream();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestUriScheme);

/*
 * we should be able to assign a protocol_t to a AnyP::UriScheme for ease
 * of code conversion
 */
void
TestUriScheme::testAssignFromprotocol_t()
{
    AnyP::UriScheme empty_scheme;
    AnyP::UriScheme scheme;
    scheme = AnyP::PROTO_NONE;
    CPPUNIT_ASSERT_EQUAL(empty_scheme, scheme);

    AnyP::UriScheme https_scheme(AnyP::PROTO_HTTPS);
    scheme = AnyP::PROTO_HTTPS;
    CPPUNIT_ASSERT_EQUAL(https_scheme, scheme);
}

/*
 * We should be able to get a protocol_t from a AnyP::UriScheme for ease
 * of migration
 */
void
TestUriScheme::testCastToprotocol_t()
{
    /* explicit cast */
    AnyP::ProtocolType protocol = static_cast<AnyP::ProtocolType>(AnyP::UriScheme());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_NONE, protocol);
    /* and implicit */
    protocol = AnyP::UriScheme(AnyP::PROTO_HTTP);
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, protocol);
}

/*
 * a default constructed AnyP::UriScheme is == AnyP::PROTO_NONE
 */
void
TestUriScheme::testDefaultConstructor()
{
    AnyP::UriScheme lhs;
    AnyP::UriScheme rhs(AnyP::PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * we should be able to construct a AnyP::UriScheme from the old 'protocol_t' enum.
 */
void
TestUriScheme::testConstructprotocol_t()
{
    AnyP::UriScheme lhs_none(AnyP::PROTO_NONE), rhs_none(AnyP::PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs_none, rhs_none);

    AnyP::UriScheme lhs_cacheobj(AnyP::PROTO_HTTP), rhs_cacheobj(AnyP::PROTO_HTTP);
    CPPUNIT_ASSERT_EQUAL(lhs_cacheobj, rhs_cacheobj);
    CPPUNIT_ASSERT(lhs_none != rhs_cacheobj);
}

/*
 * we should be able to get a char const * version of the method.
 */
void
TestUriScheme::testC_str()
{
    SBuf lhs("wais");
    AnyP::UriScheme wais(AnyP::PROTO_WAIS);
    SBuf rhs(wais.image());
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * a AnyP::UriScheme replaces protocol_t, so we should be able to test for equality on
 * either the left or right hand side seamlessly.
 */
void
TestUriScheme::testEqualprotocol_t()
{
    CPPUNIT_ASSERT(AnyP::UriScheme() == AnyP::PROTO_NONE);
    CPPUNIT_ASSERT(not (AnyP::UriScheme(AnyP::PROTO_WAIS) == AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(AnyP::PROTO_HTTP == AnyP::UriScheme(AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(not (AnyP::PROTO_HTTPS == AnyP::UriScheme(AnyP::PROTO_HTTP)));
}

/*
 * a AnyP::UriScheme should testable for inequality with a protocol_t.
 */
void
TestUriScheme::testNotEqualprotocol_t()
{
    CPPUNIT_ASSERT(AnyP::UriScheme(AnyP::PROTO_NONE) != AnyP::PROTO_HTTP);
    CPPUNIT_ASSERT(not (AnyP::UriScheme(AnyP::PROTO_HTTP) != AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(AnyP::PROTO_NONE != AnyP::UriScheme(AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(not (AnyP::PROTO_WAIS != AnyP::UriScheme(AnyP::PROTO_WAIS)));
}

/*
 * we should be able to send it to a stream and get the normalised version
 */
void
TestUriScheme::testStream()
{
    std::ostringstream buffer;
    buffer << AnyP::UriScheme(AnyP::PROTO_HTTP);
    SBuf http_str("http");
    SBuf from_buf(buffer.str());
    CPPUNIT_ASSERT_EQUAL(http_str, from_buf);
}

// This test uses main() from ./testURL.cc.

