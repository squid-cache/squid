#include "squid.h"
#include <cppunit/TestAssert.h>

#include "Mem.h"
#include "testHttpRequest.h"
#include "HttpRequest.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testHttpRequest );

/* stub functions to link successfully */
void
shut_down(int)
{}

/* end stubs */

/* init memory pools */

void
testHttpRequest::setUp()
{
    Mem::Init();
}

/*
 * Test creating an HttpRequest object from a Url and method
 */
void
testHttpRequest::testCreateFromUrlAndMethod()
{
    /* vanilla url */
    ushort expected_port;
    char * url = xstrdup("http://foo:90/bar");
    HttpRequest *aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_GET);
    expected_port = 90;
    HttpRequest *nullRequest = NULL;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT_EQUAL(METHOD_GET, aRequest->method);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->host));
    CPPUNIT_ASSERT_EQUAL(String("/bar"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://foo:90/bar"), String(url));
    xfree(url);
    /* vanilla url, different method */
    url = xstrdup("http://foo/bar");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_PUT);
    expected_port = 80;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT_EQUAL(METHOD_PUT, aRequest->method);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->host));
    CPPUNIT_ASSERT_EQUAL(String("/bar"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://foo/bar"), String(url));
    /* a connect url with non-CONNECT data */
    url = xstrdup(":foo/bar");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_CONNECT);
    xfree(url);
    CPPUNIT_ASSERT_EQUAL(nullRequest, aRequest);
    /* a CONNECT url with CONNECT data */
    url = xstrdup("foo:45");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_CONNECT);
    expected_port = 45;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT_EQUAL(METHOD_CONNECT, aRequest->method);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->host));
    CPPUNIT_ASSERT_EQUAL(String(""), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_NONE, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("foo:45"), String(url));
    xfree(url);
}

/*
 * Test creating an HttpRequest object from a Url alone.
 */
void
testHttpRequest::testCreateFromUrl()
{
    /* vanilla url */
    ushort expected_port;
    char * url = xstrdup("http://foo:90/bar");
    HttpRequest *aRequest = HttpRequest::CreateFromUrl(url);
    expected_port = 90;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT_EQUAL(METHOD_GET, aRequest->method);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->host));
    CPPUNIT_ASSERT_EQUAL(String("/bar"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://foo:90/bar"), String(url));
    xfree(url);
}
