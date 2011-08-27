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
    unsigned short expected_port;
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
    unsigned short expected_port;
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
    unsigned short expected_port;
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

void
testHttpRequest::testParseRequestLine()
{
    MemBuf input;
    HttpParser output;
    input.init();

    // TEST: Do we comply with RFC 1945 section 5.1 ?
    // TEST: Do we comply with RFC 2616 section 5.1 ?

    // RFC 1945 : HTTP/0.9 simple-request
    input.append("GET /\r\n", 7);
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET /\r\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start], (output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start], (output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.v_min);
    input.reset();

    // RFC 1945 and 2616 : HTTP/1.0 full-request
    input.append("GET / HTTP/1.0\r\n", 16);
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.0\r\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.0", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();


    // RFC 2616 : HTTP/1.1 full-request
    input.append("GET / HTTP/1.1\r\n", 16);
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\r\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // RFC 2616 : future version full-request
    input.append("GET / HTTP/10.12\r\n", 18);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/10.12\r\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(15, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/10.12", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(10, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(12, output.v_min);
    input.reset();

    // space padded URL
    input.append("GET  /     HTTP/1.1\r\n", 21);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET  /     HTTP/1.1\r\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(11, output.v_start);
    CPPUNIT_ASSERT_EQUAL(18, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // space padded version
    // RFC 1945 and 2616 specify version is followed by CRLF. No intermediary bytes.
    // NP: the terminal whitespace is a special case: invalid for even HTTP/0.9 with no version tag
    input.append("GET / HTTP/1.1 \n", 16);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1 \n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(13, output.u_end);
    CPPUNIT_ASSERT(memcmp("/ HTTP/1.1", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // whitespace inside URI. (nasty but happens)
    input.append("GET /fo o/ HTTP/1.1\n", 20);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET /fo o/ HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(9, output.u_end);
    CPPUNIT_ASSERT(memcmp("/fo o/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(11, output.v_start);
    CPPUNIT_ASSERT_EQUAL(18, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // additional data in buffer
    input.append("GET /     HTTP/1.1\nboo!", 23);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-5, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET /     HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end); // strangeness generated by following RFC
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(10, output.v_start);
    CPPUNIT_ASSERT_EQUAL(17, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // alternative EOL sequence: NL-only
    input.append("GET / HTTP/1.1\n", 15);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // alternative EOL sequence: double-NL-only
    input.append("GET / HTTP/1.1\n\n", 16);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-2, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // RELAXED alternative EOL sequence: multi-CR-NL
    input.append("GET / HTTP/1.1\r\r\r\n", 18);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    Config.onoff.relaxed_header_parser = 1;
    // Being tolerant we can ignore and elide these apparently benign CR
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\r\r\r\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // STRICT alternative EOL sequence: multi-CR-NL
    input.append("GET / HTTP/1.1\r\r\r\n", 18);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    // strict mode treats these as several bare-CR in the request line which is explicitly invalid.
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // RFC 2616 : . method
    input.append(". / HTTP/1.1\n", 13);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp(". / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(0, output.m_end);
    CPPUNIT_ASSERT(memcmp(".", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(2, output.u_start);
    CPPUNIT_ASSERT_EQUAL(2, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.v_start);
    CPPUNIT_ASSERT_EQUAL(11, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // OPTIONS with * URL
    input.append("OPTIONS * HTTP/1.1\n", 19);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("OPTIONS * HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(6, output.m_end);
    CPPUNIT_ASSERT(memcmp("OPTIONS", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(8, output.u_start);
    CPPUNIT_ASSERT_EQUAL(8, output.u_end);
    CPPUNIT_ASSERT(memcmp("*", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(10, output.v_start);
    CPPUNIT_ASSERT_EQUAL(17, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // unknown method
    input.append("HELLOWORLD / HTTP/1.1\n", 22);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("HELLOWORLD / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(9, output.m_end);
    CPPUNIT_ASSERT(memcmp("HELLOWORLD", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(11, output.u_start);
    CPPUNIT_ASSERT_EQUAL(11, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(13, output.v_start);
    CPPUNIT_ASSERT_EQUAL(20, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // This stage of the parser does not yet accept non-HTTP protocol names.
    // violations mode treats them as HTTP/0.9 requests!
    input.append("GET / FOO/1.0\n", 14);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
#if USE_HTTP_VIOLATIONS
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(12, output.u_end);
    CPPUNIT_ASSERT(memcmp("/ FOO/1.0", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.v_min);
#else
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
#endif
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / FOO/1.0\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.v_end);
    CPPUNIT_ASSERT(memcmp("FOO/1.0", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    input.reset();

    // RELAXED space padded method (in strict mode SP is reserved so invalid as a method byte)
    input.append(" GET / HTTP/1.1\n", 16);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    Config.onoff.relaxed_header_parser = 1;
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(1, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // STRICT space padded method (in strict mode SP is reserved so invalid as a method byte)
    input.append(" GET / HTTP/1.1\n", 16);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp(" GET / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // tab padded method (NP: tab is not SP so treated as any other binary)
    input.append("\tGET / HTTP/1.1\n", 16);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("\tGET / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.m_end);
    CPPUNIT_ASSERT(memcmp("\tGET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    input.append("GET", 3);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    input.append("GET ", 4);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    input.append("GET / HT", 8);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    input.append("GET / HTTP/1.1", 14);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // method-only
    input.append("A\n", 2);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("A\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // no method (but in a form which is ambiguous with HTTP/0.9 simple-request)
    input.append("/ HTTP/1.0\n", 11);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("/ HTTP/1.0\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(0, output.m_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(2, output.u_start);
    CPPUNIT_ASSERT_EQUAL(9, output.u_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.0", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.v_min);
    input.reset();

    // RELAXED no method (an invalid format)
    input.append(" / HTTP/1.0\n", 12);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    // When tolerantly ignoring SP prefix this case becomes ambiguous with HTTP/0.9 simple-request)
    Config.onoff.relaxed_header_parser = 1;
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(1, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("/ HTTP/1.0\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(1, output.m_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(3, output.u_start);
    CPPUNIT_ASSERT_EQUAL(10, output.u_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.0", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.v_min);
    input.reset();

    // STRICT no method (an invalid format)
    input.append(" / HTTP/1.0\n", 12);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    // When tolerantly ignoring SP prefix this case becomes ambiguous with HTTP/0.9 simple-request)
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp(" / HTTP/1.0\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // binary code in method (strange but ...)
    input.append("GET\x0B / HTTP/1.1\n", 16);
    //printf("TEST: %d-%d/%d '%.*s'\n", output.req_start, output.req_end, input.contentSize(), 16, input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET\x0B / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET\x0B", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // CR in method
    // RFC 2616 sec 5.1 prohibits CR other than in terminator.
    input.append("GET\r / HTTP/1.1\r\n", 16);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // binary code NUL! in method (strange but ...)
    input.append("GET\0 / HTTP/1.1\n", 16);
    //printf("TEST: %d-%d/%d '%.*s'\n", output.req_start, output.req_end, input.contentSize(), 16, input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET\0 / HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET\0", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.v_min);
    input.reset();

    // no URL (grammer otherwise correct)
    input.append("GET  HTTP/1.1\n", 14);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET  HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.u_start);
    CPPUNIT_ASSERT_EQUAL(12, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.v_min);
    input.reset();

    // no URL (grammer invalid, ambiguous with RFC 1945 HTTP/0.9 simple-request)
    input.append("GET HTTP/1.1\n", 13);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET HTTP/1.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(11, output.u_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.v_min);
    input.reset();

    // no version
    input.append("GET / HTTP/\n", 12);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(10, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // no major version
    input.append("GET / HTTP/.1\n", 14);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // no version dot
    input.append("GET / HTTP/11\n", 14);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/11\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/11", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // negative major version (bug 3062)
    input.append("GET / HTTP/-999999.1\n", 21);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/-999999.1\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(19, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/-999999.1", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // no minor version
    input.append("GET / HTTP/1.\n", 14);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // negative major version (bug 3062 corollary)
    input.append("GET / HTTP/1.-999999\n", 21);
    //printf("TEST: '%s'\n",input.content());
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.-999999\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.u_start],(output.u_end-output.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.v_start);
    CPPUNIT_ASSERT_EQUAL(19, output.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.-999999", &output.buf[output.v_start],(output.v_end-output.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // binary line
    input.append("\xB\xC\xE\xF\n", 5);
    //printf("TEST: binary-line\n");
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("\xB\xC\xE\xF\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // mixed whitespace line
    // We accept non-space binary bytes for method so first \t shows up as that
    // but remaining space and tabs are skipped searching for URI-start
    input.append("\t \t \t\n", 6);
    //printf("TEST: mixed whitespace\n");
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req_end);
    CPPUNIT_ASSERT(memcmp("\t \t \t\n", &output.buf[output.req_start],(output.req_end-output.req_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.m_start);
    CPPUNIT_ASSERT_EQUAL(0, output.m_end);
    CPPUNIT_ASSERT(memcmp("\t", &output.buf[output.m_start],(output.m_end-output.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();

    // mixed whitespace line with CR middle
    // CR aborts on sight, so even initial \t method is not marked as above
    // (not when parsing clean with whole line available anyway)
    input.append("\t  \r \n", 6);
    //printf("TEST: mixed whitespace with CR\n");
    HttpParserInit(&output, input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(0, output.req_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.v_min);
    input.reset();
}
