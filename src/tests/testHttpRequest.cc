#include "config.h"

#include <cppunit/TestAssert.h>

#include "testHttpRequest.h"
#include "HttpRequest.h"
#include "Mem.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testHttpRequest );

/** wrapper for testing HttpRequest object private and protected functions */
class PrivateHttpRequest : public HttpRequest
{
public:
    bool doSanityCheckStartLine(MemBuf *b, const size_t h, http_status *e) { return sanityCheckStartLine(b,h,e); };
};

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
    httpHeaderInitModule();
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
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->GetHost()));
    CPPUNIT_ASSERT_EQUAL(String("/foo"), aRequest->urlpath);
    CPPUNIT_ASSERT_EQUAL(PROTO_HTTP, aRequest->protocol);
    CPPUNIT_ASSERT_EQUAL(String("http://2000:800::45/foo"), String(url));
    xfree(url);
}

void
testHttpRequest::testSanityCheckStartLine()
{
    MemBuf input;
    PrivateHttpRequest engine;
    http_status error = HTTP_STATUS_NONE;
    size_t hdr_len;
    input.init();

    // a valid request line
    input.append("GET / HTTP/1.1\n\n", 16);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("GET  /  HTTP/1.1\n\n", 18);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

    // strange but valid methods
    input.append(". / HTTP/1.1\n\n", 14);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("OPTIONS * HTTP/1.1\n\n", 20);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

// TODO no method

// TODO binary code in method

// TODO no URL

// TODO no status (okay)

// TODO non-HTTP protocol

    input.append("      \n\n", 8);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(!engine.doSanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;
}
