#define SQUID_UNIT_TEST 1

#include "squid.h"
#include <cppunit/TestAssert.h>

#include "Mem.h"
#include "testHttpRequestMethod.h"
#include "HttpRequestMethod.h"

#if HAVE_SSTREAM
#include <sstream>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( testHttpRequestMethod );


/*
 * We should be able to make an HttpRequestMethod straight from a string.
 */
void
testHttpRequestMethod::testConstructCharStart()
{
    /* parse an empty string -> METHOD_NONE */
    CPPUNIT_ASSERT(HttpRequestMethod(NULL,NULL) == METHOD_NONE);
    /* parsing a literal should work */
    CPPUNIT_ASSERT(HttpRequestMethod("GET", NULL) == METHOD_GET);
    CPPUNIT_ASSERT(HttpRequestMethod("QWERTY", NULL) == METHOD_OTHER);
}

/*
 * We can also parse precise ranges of characters
 */
void
testHttpRequestMethod::testConstructCharStartEnd()
{
    char const * buffer;
    /* parse an empty string -> METHOD_NONE */
    CPPUNIT_ASSERT(HttpRequestMethod(NULL, NULL) == METHOD_NONE);
    /* parsing a literal should work */
    CPPUNIT_ASSERT(HttpRequestMethod("GET", NULL) == METHOD_GET);
    /* parsing with an explicit end should work */
    buffer = "POSTPLUS";
    CPPUNIT_ASSERT(HttpRequestMethod(buffer, buffer + 4) == METHOD_POST);
}

/*
 * we should be able to assign a method_t to a HttpRequestMethod
 */
void
testHttpRequestMethod::testAssignFrommethod_t()
{
    HttpRequestMethod method;
    method = METHOD_NONE;
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(METHOD_NONE), method);
    method = METHOD_POST;
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(METHOD_POST), method);
}

/*
 * a default constructed HttpRequestMethod is == METHOD_NONE
 */
void
testHttpRequestMethod::testDefaultConstructor()
{
    HttpRequestMethod lhs;
    HttpRequestMethod rhs(METHOD_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * we should be able to construct a HttpRequestMethod from a method_t
 */
void
testHttpRequestMethod::testConstructmethod_t()
{
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(METHOD_NONE), HttpRequestMethod(METHOD_NONE));
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(METHOD_POST), HttpRequestMethod(METHOD_POST));
    CPPUNIT_ASSERT(HttpRequestMethod(METHOD_NONE) != HttpRequestMethod(METHOD_POST));
}

/*
 * we should be able to get a char const * version of the method.
 */
void
testHttpRequestMethod::testImage()
{
    CPPUNIT_ASSERT_EQUAL(String("POST"), String(HttpRequestMethod("post",NULL).image()));
}

/*
 * an HttpRequestMethod should be comparable to a method_t without false
 * matches
 */
void
testHttpRequestMethod::testEqualmethod_t()
{
    CPPUNIT_ASSERT(HttpRequestMethod(METHOD_NONE) == METHOD_NONE);
    CPPUNIT_ASSERT(not (HttpRequestMethod(METHOD_POST) == METHOD_GET));
    CPPUNIT_ASSERT(HttpRequestMethod(METHOD_GET) == METHOD_GET);
    CPPUNIT_ASSERT(not (HttpRequestMethod(METHOD_TRACE) == METHOD_SEARCH));
}

/*
 * an HttpRequestMethod should testable for inequality without fail maatches
 */
void
testHttpRequestMethod::testNotEqualmethod_t()
{
    CPPUNIT_ASSERT(HttpRequestMethod(METHOD_NONE) != METHOD_GET);
    CPPUNIT_ASSERT(not (HttpRequestMethod(METHOD_POST) != METHOD_POST));
    CPPUNIT_ASSERT(HttpRequestMethod(METHOD_GET) != METHOD_NONE);
    CPPUNIT_ASSERT(not (HttpRequestMethod(METHOD_SEARCH) != METHOD_SEARCH));
}

/*
 * we should be able to send it to a stream and get the normalised version
 */
void
testHttpRequestMethod::testStream()
{
    std::ostringstream buffer;
    buffer << HttpRequestMethod("get",NULL);
    CPPUNIT_ASSERT_EQUAL(String("GET"), String(buffer.str().c_str()));
}
