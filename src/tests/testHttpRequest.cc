#include "config.h"

#include <cppunit/TestAssert.h>

#include "testHttpRequest.h"
#include "HttpRequest.h"
#include "Mem.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testHttpRequest );

/* stub functions to link successfully */
void
shut_down(int)
{}

void
reconfigure(int)
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
    CPPUNIT_ASSERT(aRequest->method == METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->GetHost()));
    CPPUNIT_ASSERT_EQUAL(String("/bar"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://foo:90/bar"), String(url));
    xfree(url);

    /* vanilla url, different method */
    url = xstrdup("http://foo/bar");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_PUT);
    expected_port = 80;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT(aRequest->method == METHOD_PUT);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->GetHost()));
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
    CPPUNIT_ASSERT(aRequest->method == METHOD_CONNECT);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->GetHost()));
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
    CPPUNIT_ASSERT(aRequest->method == METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->GetHost()));
    CPPUNIT_ASSERT_EQUAL(String("/bar"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://foo:90/bar"), String(url));
    xfree(url);
}

/*
 * Test BUG: URL '2000:800:45' opens host 2000 port 800 !!
 */
void
testHttpRequest::testIPv6HostColonBug()
{
    ushort expected_port;
    char * url = NULL;
    HttpRequest *aRequest = NULL;

    /* valid IPv6 address without port */
    url = xstrdup("http://[2000:800::45]/foo");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_GET);
    expected_port = 80;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT(aRequest->method == METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->GetHost()));
    CPPUNIT_ASSERT_EQUAL(String("/foo"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://[2000:800::45]/foo"), String(url));
    xfree(url);

    /* valid IPv6 address with port */
    url = xstrdup("http://[2000:800::45]:90/foo");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_GET);
    expected_port = 90;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT(aRequest->method == METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->GetHost()));
    CPPUNIT_ASSERT_EQUAL(String("/foo"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://[2000:800::45]:90/foo"), String(url));
    xfree(url);

    /* IPv6 address as invalid (bug trigger) */
    url = xstrdup("http://2000:800::45/foo");
    aRequest = HttpRequest::CreateFromUrlAndMethod(url, METHOD_GET);
    expected_port = 80;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->port);
    CPPUNIT_ASSERT(aRequest->method == METHOD_GET);
#if USE_IPV6
      /* We hasve fixed this in IPv6 build. */
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->GetHost()));
#else
      /* NO fix is possible in IPv4-pure build. */
    CPPUNIT_ASSERT_EQUAL(String("2000:800::45"), String(aRequest->GetHost()));
#endif
    CPPUNIT_ASSERT_EQUAL(String("/foo"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://2000:800::45/foo"), String(url));
    xfree(url);
}
