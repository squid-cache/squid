#define SQUID_UNIT_TEST 1

#include "squid.h"

#include <cppunit/TestAssert.h>

#include "Mem.h"
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
    scheme = PROTO_NONE;
    CPPUNIT_ASSERT_EQUAL(empty_scheme, scheme);

    URLScheme https_scheme(PROTO_HTTPS);
    scheme = PROTO_HTTPS;
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
    protocol_t protocol = (protocol_t) URLScheme();
    CPPUNIT_ASSERT_EQUAL(PROTO_NONE, protocol);
    /* and implicit */
    protocol = URLScheme(PROTO_HTTP);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, protocol);
}

/*
 * a default constructed URLScheme is == PROTO_NONE
 */
void
testURLScheme::testDefaultConstructor()
{
    URLScheme lhs;
    URLScheme rhs(PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * we should be able to construct a URLScheme from the old 'protocol_t' enum.
 */
void
testURLScheme::testConstructprotocol_t()
{
    URLScheme lhs_none(PROTO_NONE), rhs_none(PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs_none, rhs_none);

    URLScheme lhs_cacheobj(PROTO_CACHEOBJ), rhs_cacheobj(PROTO_CACHEOBJ);
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
    URLScheme wais(PROTO_WAIS);
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
    CPPUNIT_ASSERT(URLScheme() == PROTO_NONE);
    CPPUNIT_ASSERT(not (URLScheme(PROTO_WAIS) == PROTO_HTTP));
    CPPUNIT_ASSERT(PROTO_HTTP == URLScheme(PROTO_HTTP));
    CPPUNIT_ASSERT(not (PROTO_CACHEOBJ == URLScheme(PROTO_HTTP)));
}

/*
 * a URLScheme should testable for inequality with a protocol_t.
 */
void
testURLScheme::testNotEqualprotocol_t()
{
    CPPUNIT_ASSERT(URLScheme(PROTO_NONE) != PROTO_HTTP);
    CPPUNIT_ASSERT(not (URLScheme(PROTO_HTTP) != PROTO_HTTP));
    CPPUNIT_ASSERT(PROTO_NONE != URLScheme(PROTO_HTTP));
    CPPUNIT_ASSERT(not (PROTO_WAIS != URLScheme(PROTO_WAIS)));
}

/*
 * we should be able to send it to a stream and get the normalised version
 */
void
testURLScheme::testStream()
{
    std::ostringstream buffer;
    buffer << URLScheme(PROTO_HTTP);
    String http_str("http");
    String from_buf(buffer.str().c_str());
    CPPUNIT_ASSERT_EQUAL(http_str, from_buf);
}
