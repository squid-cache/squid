/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "http/RequestMethod.h"
#include "SquidConfig.h"

class TestHttpRequestMethod : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestHttpRequestMethod);
    CPPUNIT_TEST(testAssignFrommethod_t);
    CPPUNIT_TEST(testConstructmethod_t);
    CPPUNIT_TEST(testConstructCharStart);
    CPPUNIT_TEST(testConstructCharStartEnd);
    CPPUNIT_TEST(testDefaultConstructor);
    CPPUNIT_TEST(testEqualmethod_t);
    CPPUNIT_TEST(testNotEqualmethod_t);
    CPPUNIT_TEST(testImage);
    CPPUNIT_TEST(testStream);
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testAssignFrommethod_t();
    void testConstructmethod_t();
    void testConstructCharStart();
    void testConstructCharStartEnd();
    void testImage();
    void testDefaultConstructor();
    void testEqualmethod_t();
    void testNotEqualmethod_t();
    void testStream();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestHttpRequestMethod );

/*
 * We should be able to make an HttpRequestMethod straight from a string.
 */
void
TestHttpRequestMethod::testConstructCharStart()
{
    // string in SBuf

    /* parse an empty string -> Http::METHOD_NONE */
    CPPUNIT_ASSERT(HttpRequestMethod(SBuf()) == Http::METHOD_NONE);

    /* parsing a literal should work */
    CPPUNIT_ASSERT(HttpRequestMethod(SBuf("GET")) == Http::METHOD_GET);
    CPPUNIT_ASSERT(HttpRequestMethod(SBuf("QWERTY")) == Http::METHOD_OTHER);

    // string in char*

    /* parse an empty string -> Http::METHOD_NONE */
    HttpRequestMethod a;
    a.HttpRequestMethodXXX(nullptr);
    CPPUNIT_ASSERT(a == Http::METHOD_NONE);

    /* parsing a literal should work */
    HttpRequestMethod b;
    b.HttpRequestMethodXXX("GET");
    CPPUNIT_ASSERT(b == Http::METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(SBuf("GET"), b.image());
    HttpRequestMethod c;
    c.HttpRequestMethodXXX("QWERTY");
    CPPUNIT_ASSERT(c == Http::METHOD_OTHER);
    CPPUNIT_ASSERT_EQUAL(SBuf("QWERTY"), c.image());

    // parsing error should not leave stale results
    b.HttpRequestMethodXXX(nullptr);
    CPPUNIT_ASSERT(b == Http::METHOD_NONE);
    CPPUNIT_ASSERT_EQUAL(SBuf("NONE"), b.image());
}

/*
 * We can also parse precise ranges of characters with SBuf
 */
void
TestHttpRequestMethod::testConstructCharStartEnd()
{
    char const * buffer;
    /* parse an empty string -> Http::METHOD_NONE */
    CPPUNIT_ASSERT(HttpRequestMethod(SBuf()) == Http::METHOD_NONE);
    /* parsing a literal should work */
    CPPUNIT_ASSERT(HttpRequestMethod(SBuf("GET")) == Http::METHOD_GET);
    /* parsing with an explicit end should work */
    buffer = "POSTPLUS";
    CPPUNIT_ASSERT(HttpRequestMethod(SBuf(buffer, 4)) == Http::METHOD_POST);
}

/*
 * we should be able to assign a Http::MethodType to a HttpRequestMethod
 */
void
TestHttpRequestMethod::testAssignFrommethod_t()
{
    HttpRequestMethod method;
    method = Http::METHOD_NONE;
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_NONE), method);
    method = Http::METHOD_POST;
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_POST), method);
}

/*
 * a default constructed HttpRequestMethod is == Http::METHOD_NONE
 */
void
TestHttpRequestMethod::testDefaultConstructor()
{
    HttpRequestMethod lhs;
    HttpRequestMethod rhs(Http::METHOD_NONE);
    CPPUNIT_ASSERT_EQUAL(lhs, rhs);
}

/*
 * we should be able to construct a HttpRequestMethod from a Http::MethodType
 */
void
TestHttpRequestMethod::testConstructmethod_t()
{
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_NONE), HttpRequestMethod(Http::METHOD_NONE));
    CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_POST), HttpRequestMethod(Http::METHOD_POST));
    CPPUNIT_ASSERT(HttpRequestMethod(Http::METHOD_NONE) != HttpRequestMethod(Http::METHOD_POST));
}

/*
 * we should be able to get a char const * version of the method.
 */
void
TestHttpRequestMethod::testImage()
{
    // relaxed RFC-compliance parse HTTP methods are upgraded to correct case
    Config.onoff.relaxed_header_parser = 1;
    CPPUNIT_ASSERT_EQUAL(SBuf("POST"), HttpRequestMethod(SBuf("POST")).image());
    CPPUNIT_ASSERT_EQUAL(SBuf("POST"), HttpRequestMethod(SBuf("pOsT")).image());
    CPPUNIT_ASSERT_EQUAL(SBuf("POST"), HttpRequestMethod(SBuf("post")).image());

    // strict RFC-compliance parse HTTP methods are case sensitive
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(SBuf("POST"), HttpRequestMethod(SBuf("POST")).image());
    CPPUNIT_ASSERT_EQUAL(SBuf("pOsT"), HttpRequestMethod(SBuf("pOsT")).image());
    CPPUNIT_ASSERT_EQUAL(SBuf("post"), HttpRequestMethod(SBuf("post")).image());
}

/*
 * an HttpRequestMethod should be comparable to a Http::MethodType without false
 * matches
 */
void
TestHttpRequestMethod::testEqualmethod_t()
{
    CPPUNIT_ASSERT(HttpRequestMethod(Http::METHOD_NONE) == Http::METHOD_NONE);
    CPPUNIT_ASSERT(not (HttpRequestMethod(Http::METHOD_POST) == Http::METHOD_GET));
    CPPUNIT_ASSERT(HttpRequestMethod(Http::METHOD_GET) == Http::METHOD_GET);
    CPPUNIT_ASSERT(not (HttpRequestMethod(Http::METHOD_TRACE) == Http::METHOD_SEARCH));
}

/*
 * an HttpRequestMethod should testable for inequality without fail maatches
 */
void
TestHttpRequestMethod::testNotEqualmethod_t()
{
    CPPUNIT_ASSERT(HttpRequestMethod(Http::METHOD_NONE) != Http::METHOD_GET);
    CPPUNIT_ASSERT(not (HttpRequestMethod(Http::METHOD_POST) != Http::METHOD_POST));
    CPPUNIT_ASSERT(HttpRequestMethod(Http::METHOD_GET) != Http::METHOD_NONE);
    CPPUNIT_ASSERT(not (HttpRequestMethod(Http::METHOD_SEARCH) != Http::METHOD_SEARCH));
}

/*
 * we should be able to send it to a stream and get the normalised version
 */
void
TestHttpRequestMethod::testStream()
{
    // relaxed RFC-compliance parse HTTP methods are upgraded to correct case
    Config.onoff.relaxed_header_parser = 1;
    std::ostringstream buffer;
    buffer << HttpRequestMethod(SBuf("get"));
    CPPUNIT_ASSERT_EQUAL(String("GET"), String(buffer.str().c_str()));

    // strict RFC-compliance parse HTTP methods are case sensitive
    Config.onoff.relaxed_header_parser = 0;
    std::ostringstream buffer2;
    buffer2 << HttpRequestMethod(SBuf("get"));
    CPPUNIT_ASSERT_EQUAL(String("get"), String(buffer2.str().c_str()));
}

