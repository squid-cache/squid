#define SQUID_UNIT_TEST 1

#include "squid.h"

#include <cppunit/TestAssert.h>

#include "Mem.h"
#include "SquidString.h"
#include "testURLScheme.h"
#include "URLScheme.h"

#if HAVE_SSTREAM
#include <sstream>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( testURLScheme );

#if 0
/*
 * We should be able to make an HttpRequestMethod straight from a string.
 */
void
testHttpRequestMethod::testConstructCharStart()
{
    /* parse an empty string -> METHOD_NONE */
    CPPUNIT_ASSERT(METHOD_NONE == HttpRequestMethod(NULL));
    /* parsing a literal should work */
    CPPUNIT_ASSERT(METHOD_GET == HttpRequestMethod("GET", NULL));
}

/*
 * We can also parse precise ranges of characters
 */
void
testHttpRequestMethod::testConstructCharStartEnd()
{
    char const * buffer;
    /* parse an empty string -> METHOD_NONE */
    CPPUNIT_ASSERT(METHOD_NONE == HttpRequestMethod(NULL, NULL));
    /* parsing a literal should work */
    CPPUNIT_ASSERT(METHOD_GET == HttpRequestMethod("GET", NULL));
    /* parsing with an explicit end should work */
    buffer = "POSTPLUS";
    CPPUNIT_ASSERT(METHOD_POST == HttpRequestMethod(buffer, buffer + 4));
}

#endif

/*
 * we should be able to assign a protocol_t to a URLScheme for ease
 * of code conversion
 */
void
testURLScheme::testAssignFromprotocol_t()
{
    URLScheme empty_scheme;
    URLScheme scheme;
    scheme = AnyP::PROTO_NONE;
    CPPUNIT_ASSERT_EQUAL(empty_scheme, scheme);

    URLScheme https_scheme(AnyP::PROTO_HTTPS);
    scheme = AnyP::PROTO_HTTPS;
    CPPUNIT_ASSERT_EQUAL(https_scheme, scheme);
}

/*
 * We should be able to get a protocol_t from a URLScheme for ease
 * of migration
 */
void
testURLScheme::testCastToprotocol_t()
{
    /* explicit cast */
    AnyP::ProtocolType protocol = static_cast<AnyP::ProtocolType>(URLScheme());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_NONE, protocol);
    /* and implicit */
    protocol = URLScheme(AnyP::PROTO_HTTP);
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, protocol);
}

/*
 * a default constructed URLScheme is == AnyP::PROTO_NONE
 */
void
testURLScheme::testDefaultConstructor()
{
    URLScheme lhs;
    URLScheme rhs(AnyP::PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * we should be able to construct a URLScheme from the old 'protocol_t' enum.
 */
void
testURLScheme::testConstructprotocol_t()
{
    URLScheme lhs_none(AnyP::PROTO_NONE), rhs_none(AnyP::PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs_none, rhs_none);

    URLScheme lhs_cacheobj(AnyP::PROTO_CACHE_OBJECT), rhs_cacheobj(AnyP::PROTO_CACHE_OBJECT);
    CPPUNIT_ASSERT_EQUAL(lhs_cacheobj, rhs_cacheobj);
    CPPUNIT_ASSERT(lhs_none != rhs_cacheobj);
}

/*
 * we should be able to get a char const * version of the method.
 */
void
testURLScheme::testConst_str()
{
    String lhs("wais");
    URLScheme wais(AnyP::PROTO_WAIS);
    String rhs(wais.const_str());
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * a URLScheme replaces protocol_t, so we should be able to test for equality on
 * either the left or right hand side seamlessly.
 */
void
testURLScheme::testEqualprotocol_t()
{
    CPPUNIT_ASSERT(URLScheme() == AnyP::PROTO_NONE);
    CPPUNIT_ASSERT(not (URLScheme(AnyP::PROTO_WAIS) == AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(AnyP::PROTO_HTTP == URLScheme(AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(not (AnyP::PROTO_CACHE_OBJECT == URLScheme(AnyP::PROTO_HTTP)));
}

/*
 * a URLScheme should testable for inequality with a protocol_t.
 */
void
testURLScheme::testNotEqualprotocol_t()
{
    CPPUNIT_ASSERT(URLScheme(AnyP::PROTO_NONE) != AnyP::PROTO_HTTP);
    CPPUNIT_ASSERT(not (URLScheme(AnyP::PROTO_HTTP) != AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(AnyP::PROTO_NONE != URLScheme(AnyP::PROTO_HTTP));
    CPPUNIT_ASSERT(not (AnyP::PROTO_WAIS != URLScheme(AnyP::PROTO_WAIS)));
}

/*
 * we should be able to send it to a stream and get the normalised version
 */
void
testURLScheme::testStream()
{
    std::ostringstream buffer;
    buffer << URLScheme(AnyP::PROTO_HTTP);
    String http_str("http");
    String from_buf(buffer.str().c_str());
    CPPUNIT_ASSERT_EQUAL(http_str, from_buf);
}
