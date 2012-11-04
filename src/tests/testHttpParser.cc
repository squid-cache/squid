#define SQUID_UNIT_TEST 1
#include "squid.h"

#include <cppunit/TestAssert.h>

#include "testHttpParser.h"
#include "HttpParser.h"
#include "Mem.h"
#include "MemBuf.h"
#include "SquidConfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testHttpParser );

void
testHttpParser::globalSetup()
{
    static bool setup_done = false;
    if (setup_done)
        return;

    Mem::Init();
    setup_done = true;
}

void
testHttpParser::testParseRequestLineProtocols()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    HttpParser output;
    input.init();

    // TEST: Do we comply with RFC 1945 section 5.1 ?
    // TEST: Do we comply with RFC 2616 section 5.1 ?

    // RFC 1945 : HTTP/0.9 simple-request
    input.append("GET /\r\n", 7);
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET /\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start], (output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start], (output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
    input.reset();

    // RFC 1945 : invalid HTTP/0.9 simple-request (only GET is valid)
#if 0
    input.append("POST /\r\n", 7);
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET /\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start], (output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start], (output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
    input.reset();
#endif

    // RFC 1945 and 2616 : HTTP/1.0 request
    input.append("GET / HTTP/1.0\r\n", 16);
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.0\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.0", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // RFC 2616 : HTTP/1.1 request
    input.append("GET / HTTP/1.1\r\n", 16);
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // RFC 2616 : future version full-request
    input.append("GET / HTTP/1.2\r\n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.2\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.2", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(2, output.req.v_min);
    input.reset();

    // RFC 2616 : future version full-request
    // XXX: IETF HTTPbis WG has made this two-digits format invalid.
    input.append("GET / HTTP/10.12\r\n", 18);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/10.12\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(15, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/10.12", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(10, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(12, output.req.v_min);
    input.reset();

    // This stage of the parser does not yet accept non-HTTP protocol names.
    // violations mode treats them as HTTP/0.9 requests!
    input.append("GET / FOO/1.0\n", 14);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
#if USE_HTTP_VIOLATIONS
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(12, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/ FOO/1.0", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
#else
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
#endif
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / FOO/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("FOO/1.0", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    input.reset();

    // no version
    input.append("GET / HTTP/\n", 12);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(10, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // no major version
    input.append("GET / HTTP/.1\n", 14);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // no version dot
    input.append("GET / HTTP/11\n", 14);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/11\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/11", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // negative major version (bug 3062)
    input.append("GET / HTTP/-999999.1\n", 21);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/-999999.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(19, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/-999999.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // no minor version
    input.append("GET / HTTP/1.\n", 14);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // negative major version (bug 3062 corollary)
    input.append("GET / HTTP/1.-999999\n", 21);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_HTTP_VERSION_NOT_SUPPORTED, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.-999999\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(19, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.-999999", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();
}

void
testHttpParser::testParseRequestLineStrange()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    HttpParser output;
    input.init();

    // space padded URL
    input.append("GET  /     HTTP/1.1\r\n", 21);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET  /     HTTP/1.1\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(11, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(18, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // whitespace inside URI. (nasty but happens)
    input.append("GET /fo o/ HTTP/1.1\n", 20);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET /fo o/ HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(9, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/fo o/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(11, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(18, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // additional data in buffer
    input.append("GET /     HTTP/1.1\nboo!", 23);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-5, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET /     HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end); // strangeness generated by following RFC
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(10, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(17, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();
}

void
testHttpParser::testParseRequestLineTerminators()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    HttpParser output;
    input.init();

    // alternative EOL sequence: NL-only
    input.append("GET / HTTP/1.1\n", 15);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // alternative EOL sequence: double-NL-only
    input.append("GET / HTTP/1.1\n\n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-2, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // RELAXED alternative EOL sequence: multi-CR-NL
    input.append("GET / HTTP/1.1\r\r\r\n", 18);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    Config.onoff.relaxed_header_parser = 1;
    // Being tolerant we can ignore and elide these apparently benign CR
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\r\r\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // STRICT alternative EOL sequence: multi-CR-NL
    input.append("GET / HTTP/1.1\r\r\r\n", 18);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    // strict mode treats these as several bare-CR in the request line which is explicitly invalid.
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // space padded version
    // RFC 1945 and 2616 specify version is followed by CRLF. No intermediary bytes.
    // NP: the terminal whitespace is a special case: invalid for even HTTP/0.9 with no version tag
    input.append("GET / HTTP/1.1 \n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1 \n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(13, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/ HTTP/1.1", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // incomplete line at various positions

    input.append("GET", 3);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_STATUS_NONE, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    input.append("GET ", 4);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_STATUS_NONE, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    input.append("GET / HT", 8);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_STATUS_NONE, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    input.append("GET / HTTP/1.1", 14);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(0, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_STATUS_NONE, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();
}

void
testHttpParser::testParseRequestLineMethods()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    HttpParser output;
    input.init();

    // RFC 2616 : . method
    input.append(". / HTTP/1.1\n", 13);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp(". / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_end);
    CPPUNIT_ASSERT(memcmp(".", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(2, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(11, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // OPTIONS with * URL
    input.append("OPTIONS * HTTP/1.1\n", 19);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("OPTIONS * HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(6, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("OPTIONS", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(8, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(8, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("*", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(10, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(17, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // unknown method
    input.append("HELLOWORLD / HTTP/1.1\n", 22);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("HELLOWORLD / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(9, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("HELLOWORLD", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(11, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(11, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(13, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(20, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // method-only
    input.append("A\n", 2);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("A\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    input.append("GET\n", 4);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // RELAXED space padded method (in strict mode SP is reserved so invalid as a method byte)
    input.append(" GET / HTTP/1.1\n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    Config.onoff.relaxed_header_parser = 1;
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(1, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // STRICT space padded method (in strict mode SP is reserved so invalid as a method byte)
    input.append(" GET / HTTP/1.1\n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp(" GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // tab padded method (NP: tab is not SP so treated as any other binary)
    input.append("\tGET / HTTP/1.1\n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("\tGET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("\tGET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();
}

void
testHttpParser::testParseRequestLineInvalid()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    HttpParser output;
    input.init();

    // no method (but in a form which is ambiguous with HTTP/0.9 simple-request)
    // XXX: Bug: HTTP/0.9 requires method to be "GET"
    input.append("/ HTTP/1.0\n", 11);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("/ HTTP/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(2, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(9, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.0", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
    input.reset();

    // RELAXED no method (an invalid format)
    input.append(" / HTTP/1.0\n", 12);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    // When tolerantly ignoring SP prefix this case becomes ambiguous with HTTP/0.9 simple-request)
    Config.onoff.relaxed_header_parser = 1;
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(1, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("/ HTTP/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(1, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(3, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(10, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.0", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
    input.reset();

    // STRICT no method (an invalid format)
    input.append(" / HTTP/1.0\n", 12);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    // When tolerantly ignoring SP prefix this case becomes ambiguous with HTTP/0.9 simple-request)
    Config.onoff.relaxed_header_parser = 0;
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp(" / HTTP/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // binary code in method (strange but ...)
    input.append("GET\x0B / HTTP/1.1\n", 16);
    //printf("TEST: %d-%d/%d '%.*s'\n", output.req.start, output.req.end, input.contentSize(), 16, input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET\x0B / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET\x0B", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // CR in method
    // RFC 2616 sec 5.1 prohibits CR other than in terminator.
    input.append("GET\r / HTTP/1.1\r\n", 16);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // binary code NUL! in method (strange but ...)
    input.append("GET\0 / HTTP/1.1\n", 16);
    //printf("TEST: %d-%d/%d '%.*s'\n", output.req.start, output.req.end, input.contentSize(), 16, input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET\0 / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET\0", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(1, output.req.v_min);
    input.reset();

    // no URL (grammer otherwise correct)
    input.append("GET  HTTP/1.1\n", 14);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET  HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(12, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
    input.reset();

    // no URL (grammer invalid, ambiguous with RFC 1945 HTTP/0.9 simple-request)
    input.append("GET HTTP/1.1\n", 13);
    //printf("TEST: '%s'\n",input.content());
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_OK, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("GET HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(11, output.req.u_end);
    CPPUNIT_ASSERT(memcmp("HTTP/1.1", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(9, output.req.v_min);
    input.reset();

    // binary line
    input.append("\xB\xC\xE\xF\n", 5);
    //printf("TEST: binary-line\n");
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("\xB\xC\xE\xF\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // mixed whitespace line
    // We accept non-space binary bytes for method so first \t shows up as that
    // but remaining space and tabs are skipped searching for URI-start
    input.append("\t \t \t\n", 6);
    //printf("TEST: mixed whitespace\n");
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
    CPPUNIT_ASSERT(memcmp("\t \t \t\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(0, output.req.m_end);
    CPPUNIT_ASSERT(memcmp("\t", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)) == 0);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();

    // mixed whitespace line with CR middle
    // CR aborts on sight, so even initial \t method is not marked as above
    // (not when parsing clean with whole line available anyway)
    input.append("\t  \r \n", 6);
    //printf("TEST: mixed whitespace with CR\n");
    output.reset(input.content(), input.contentSize());
    CPPUNIT_ASSERT_EQUAL(-1, HttpParserParseReqLine(&output));
    CPPUNIT_ASSERT_EQUAL(HTTP_BAD_REQUEST, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(0, output.req.start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_maj);
    CPPUNIT_ASSERT_EQUAL(0, output.req.v_min);
    input.reset();
}
