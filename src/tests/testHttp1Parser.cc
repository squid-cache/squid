#define SQUID_UNIT_TEST 1
#include "squid.h"

#include <cppunit/TestAssert.h>

#define private public
#define protected public

#include "testHttp1Parser.h"
#include "http/Http1Parser.h"
#include "http/RequestMethod.h"
#include "Mem.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "testHttp1Parser.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testHttp1Parser );

void
testHttp1Parser::globalSetup()
{
    static bool setup_done = false;
    if (setup_done)
        return;

    Mem::Init();
    setup_done = true;

    // default to strict parser. set for loose parsing specifically where behaviour differs.
    Config.onoff.relaxed_header_parser = 0;

    Config.maxRequestHeaderSize = 1024; // XXX: unit test the RequestParser handling of this limit
}

void
testHttp1Parser::testParseRequestLineProtocols()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    Http1::RequestParser output;
    input.init();

    // TEST: Do we comply with RFC 1945 section 5.1 ?
    // TEST: Do we comply with RFC 2616 section 5.1 ?

    // RFC 1945 : HTTP/0.9 simple-request
    {
        input.append("GET /\r\n", 7);
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0,memcmp("GET /\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start], (output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start], (output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9), output.msgProtocol_);
        input.reset();
    }

    // RFC 1945 : invalid HTTP/0.9 simple-request (only GET is valid)
#if 0
    {
        input.append("POST /\r\n", 7);
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0,memcmp("POST /\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("POST", &output.buf[output.req.m_start], (output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_POST), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start], (output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }
#endif

    // RFC 1945 and 2616 : HTTP/1.0 request
    {
        input.append("GET / HTTP/1.0\r\n", 16);
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.0\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.0", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0), output.msgProtocol_);
        input.reset();
    }

    // RFC 2616 : HTTP/1.1 request
    {
        input.append("GET / HTTP/1.1\r\n", 16);
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.1\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // RFC 2616 : future version full-request
    {
        input.append("GET / HTTP/1.2\r\n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.2\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.2", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,2), output.msgProtocol_);
        input.reset();
    }

    // RFC 2616 : future version full-request
    {
        // IETF HTTPbis WG has made this two-digits format invalid.
        // it gets treated same as HTTP/0.9 for now
        input.append("GET / HTTP/10.12\r\n", 18);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/10.12\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(15, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/10.12", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,10,12), output.msgProtocol_);
        input.reset();
    }

    // This stage of the parser does not yet accept non-HTTP protocol names.
    {
        // violations mode treats them as HTTP/0.9 requests!
        input.append("GET / FOO/1.0\n", 14);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
#if USE_HTTP_VIOLATIONS
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(12, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/ FOO/1.0", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9), output.msgProtocol_);
#else
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
#endif
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / FOO/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("FOO/1.0", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        input.reset();
    }

    // no version
    {
        input.append("GET / HTTP/\n", 12);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(10, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0), output.msgProtocol_);
        input.reset();
    }

    // no major version
    {
        input.append("GET / HTTP/.1\n", 14);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0), output.msgProtocol_);
        input.reset();
    }

    // no version dot
    {
        input.append("GET / HTTP/11\n", 14);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/11\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/11", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0), output.msgProtocol_);
        input.reset();
    }

    // negative major version (bug 3062)
    {
        input.append("GET / HTTP/-999999.1\n", 21);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/-999999.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(19, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/-999999.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0), output.msgProtocol_);
        input.reset();
    }

    // no minor version
    {
        input.append("GET / HTTP/1.\n", 14);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(12, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0), output.msgProtocol_);
        input.reset();
    }

    // negative major version (bug 3062 corollary)
    {
        input.append("GET / HTTP/1.-999999\n", 21);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scHttpVersionNotSupported, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.-999999\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(19, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.-999999", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0), output.msgProtocol_);
        input.reset();
    }
}

void
testHttp1Parser::testParseRequestLineStrange()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    Http1::RequestParser output;
    input.init();

    // space padded URL
    {
        input.append("GET  /     HTTP/1.1\r\n", 21);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET  /     HTTP/1.1\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(11, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(18, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // whitespace inside URI. (nasty but happens)
    {
        input.append("GET /fo o/ HTTP/1.1\n", 20);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0,memcmp("GET /fo o/ HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(9, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/fo o/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(11, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(18, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // additional data in buffer
    {
        input.append("GET /     HTTP/1.1\nboo!", 23);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-5, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET /     HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end); // strangeness generated by following RFC
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(10, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(17, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }
}

void
testHttp1Parser::testParseRequestLineTerminators()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    Http1::RequestParser output;
    input.init();

    // alternative EOL sequence: NL-only
    {
        input.append("GET / HTTP/1.1\n", 15);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // alternative EOL sequence: double-NL-only
    {
        input.append("GET / HTTP/1.1\n\n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-2, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // RELAXED alternative EOL sequence: multi-CR-NL
    {
        input.append("GET / HTTP/1.1\r\r\r\n", 18);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        Config.onoff.relaxed_header_parser = 1;
        // Being tolerant we can ignore and elide these apparently benign CR
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.1\r\r\r\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(6, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
        Config.onoff.relaxed_header_parser = 0;
    }

    // STRICT alternative EOL sequence: multi-CR-NL
    {
        input.append("GET / HTTP/1.1\r\r\r\n", 18);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        // strict mode treats these as several bare-CR in the request line which is explicitly invalid.
        Config.onoff.relaxed_header_parser = 0;
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    // space padded version
    {
        // RFC 1945 and 2616 specify version is followed by CRLF. No intermediary bytes.
        // NP: the terminal whitespace is a special case: invalid for even HTTP/0.9 with no version tag
        input.append("GET / HTTP/1.1 \n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.1 \n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(13, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/ HTTP/1.1", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    // incomplete line at various positions
    {
        input.append("GET", 3);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_FIRST, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scNone, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();

        input.append("GET ", 4);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_FIRST, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scNone, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();

        input.append("GET / HT", 8);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_FIRST, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scNone, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();

        input.append("GET / HTTP/1.1", 14);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_FIRST, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scNone, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }
}

void
testHttp1Parser::testParseRequestLineMethods()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    Http1::RequestParser output;
    input.init();

    // RFC 2616 : . method
    {
        input.append(". / HTTP/1.1\n", 13);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp(". / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp(".", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(".", NULL), output.method_);
        CPPUNIT_ASSERT_EQUAL(2, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(4, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(11, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // OPTIONS with * URL
    {
        input.append("OPTIONS * HTTP/1.1\n", 19);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("OPTIONS * HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(6, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("OPTIONS", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_OPTIONS), output.method_);
        CPPUNIT_ASSERT_EQUAL(8, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(8, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("*", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(10, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(17, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // unknown method
    {
        input.append("HELLOWORLD / HTTP/1.1\n", 22);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HELLOWORLD / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(9, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HELLOWORLD", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod("HELLOWORLD",NULL), output.method_);
        CPPUNIT_ASSERT_EQUAL(11, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(11, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(13, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(20, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // method-only
    {
        input.append("A\n", 2);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("A\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    input.append("GET\n", 4);
    {
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    // RELAXED space padded method (in strict mode SP is reserved so invalid as a method byte)
    {
        input.append(" GET / HTTP/1.1\n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        Config.onoff.relaxed_header_parser = 1;
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(1, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
        Config.onoff.relaxed_header_parser = 0;
    }

    // STRICT space padded method (in strict mode SP is reserved so invalid as a method byte)
    {
        input.append(" GET / HTTP/1.1\n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        Config.onoff.relaxed_header_parser = 0;
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp(" GET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_NONE,0,0), output.msgProtocol_);
        input.reset();
    }

    // tab padded method (NP: tab is not SP so treated as any other binary)
    // XXX: binary codes are non-compliant
    {
        input.append("\tGET / HTTP/1.1\n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("\tGET / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("\tGET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(&output.buf[output.req.m_start],&output.buf[output.req.m_end+1]), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }
}

void
testHttp1Parser::testParseRequestLineInvalid()
{
    // ensure MemPools etc exist
    globalSetup();

    MemBuf input;
    Http1::RequestParser output;
    input.init();

    // no method (but in a form which is ambiguous with HTTP/0.9 simple-request)
    {
        // XXX: Bug: HTTP/0.9 requires method to be "GET"
        input.append("/ HTTP/1.0\n", 11);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/ HTTP/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod("/",NULL), output.method_);
        CPPUNIT_ASSERT_EQUAL(2, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(9, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.0", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9), output.msgProtocol_);
        input.reset();
    }

    // RELAXED no method (an invalid format)
    {
        input.append(" / HTTP/1.0\n", 12);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        // BUG: When tolerantly ignoring SP prefix this case becomes ambiguous with HTTP/0.9 simple-request)
        Config.onoff.relaxed_header_parser = 1;
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
//        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_DONE, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(1, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/ HTTP/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod("/",NULL), output.method_);
        CPPUNIT_ASSERT_EQUAL(3, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(10, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.0", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9), output.msgProtocol_);
        input.reset();
        Config.onoff.relaxed_header_parser = 0;
    }

    // STRICT no method (an invalid format)
    {
        input.append(" / HTTP/1.0\n", 12);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        // When tolerantly ignoring SP prefix this case becomes ambiguous with HTTP/0.9 simple-request)
        Config.onoff.relaxed_header_parser = 0;
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp(" / HTTP/1.0\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_NONE,0,0), output.msgProtocol_);
        input.reset();
    }

    // binary code in method (strange but ...)
    {
        input.append("GET\x0B / HTTP/1.1\n", 16);
        //printf("TEST: %d-%d/%d '%.*s'\n", output.req.start, output.req.end, input.contentSize(), 16, input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET\x0B / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET\x0B", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
//        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod("GET\0x0B",NULL), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // CR in method
    {
        // RFC 2616 sec 5.1 prohibits CR other than in terminator.
        input.append("GET\r / HTTP/1.1\r\n", 16);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    // binary code NUL! in method (strange but ...)
    {
        input.append("GET\0 / HTTP/1.1\n", 16);
        //printf("TEST: %d-%d/%d '%.*s'\n", output.req.start, output.req.end, input.contentSize(), 16, input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(false, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET\0 / HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(3, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET\0", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
//        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod("GET\0",NULL), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("/", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(7, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(14, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.v_start],(output.req.v_end-output.req.v_start+1)));
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1), output.msgProtocol_);
        input.reset();
    }

    // no URL (grammer otherwise correct)
    {
        input.append("GET  HTTP/1.1\n", 14);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET  HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(5, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(12, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9), output.msgProtocol_);
        input.reset();
    }

    // no URL (grammer invalid, ambiguous with RFC 1945 HTTP/0.9 simple-request)
    {
        input.append("GET HTTP/1.1\n", 13);
        //printf("TEST: '%s'\n",input.content());
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(true, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scOkay, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET HTTP/1.1\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(2, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("GET", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_GET), output.method_);
        CPPUNIT_ASSERT_EQUAL(4, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(11, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("HTTP/1.1", &output.buf[output.req.u_start],(output.req.u_end-output.req.u_start+1)));
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9), output.msgProtocol_);
        input.reset();
    }

    // binary line
    {
        input.append("\xB\xC\xE\xF\n", 5);
        //printf("TEST: binary-line\n");
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("\xB\xC\xE\xF\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    // mixed whitespace line
    {
        // We accept non-space binary bytes for method so first \t shows up as that
        // but remaining space and tabs are skipped searching for URI-start
        input.append("\t \t \t\n", 6);
        //printf("TEST: mixed whitespace\n");
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL((int)input.contentSize()-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("\t \t \t\n", &output.buf[output.req.start],(output.req.end-output.req.start+1)));
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(0, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(0, memcmp("\t", &output.buf[output.req.m_start],(output.req.m_end-output.req.m_start+1)));
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(&output.buf[output.req.m_start],&output.buf[output.req.m_end+1]), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }

    // mixed whitespace line with CR middle
    {
        // CR aborts on sight, so even initial \t method is not marked as above
        // (not when parsing clean with whole line available anyway)
        input.append("\t  \r \n", 6);
        //printf("TEST: mixed whitespace with CR\n");
        output.reset(input.content(), input.contentSize());
        CPPUNIT_ASSERT_EQUAL(false, output.parse());
        CPPUNIT_ASSERT_EQUAL(true, output.isDone());
        CPPUNIT_ASSERT_EQUAL(Http::scBadRequest, output.request_parse_status);
        CPPUNIT_ASSERT_EQUAL(0, output.req.start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.m_end);
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(), output.method_);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.u_end);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_start);
        CPPUNIT_ASSERT_EQUAL(-1, output.req.v_end);
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
        input.reset();
    }
}

void
testHttp1Parser::testDripFeed()
{
    // Simulate a client drip-feeding Squid a few bytes at a time.
    // extend the size of the buffer from 0 bytes to full request length
    // calling the parser repeatedly as visible data grows.

    MemBuf mb;
    mb.init(1024, 1024);
    mb.append("            ", 12);
    int garbageEnd = mb.contentSize();
    mb.append("GET http://example.com/ HTTP/1.1\r\n", 34);
    int reqLineEnd = mb.contentSize();
    mb.append("Host: example.com\r\n\r\n", 21);
    int mimeEnd = mb.contentSize();
    mb.append("...", 3); // trailer to catch mime EOS errors.

    Http1::RequestParser hp(mb.content(), 0);

    // only relaxed parser accepts the garbage whitespace
    Config.onoff.relaxed_header_parser = 1;

    for (; hp.bufsiz <= mb.contentSize(); ++hp.bufsiz) {
        bool parseResult = hp.parse();

#if WHEN_TEST_DEBUG_IS_NEEDED
        printf("%d/%d :: %d, %d, %d '%c'\n", hp.bufsiz, mb.contentSize(),
               garbageEnd, reqLineEnd, parseResult,
               mb.content()[hp.bufsiz]);
#endif

	// before end of garbage found its a moving offset.
	if (hp.bufsiz <= garbageEnd) {
            CPPUNIT_ASSERT_EQUAL(hp.bufsiz, (int)hp.parseOffset_);
            CPPUNIT_ASSERT_EQUAL(false, hp.isDone());
            CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_NEW, hp.parsingStage_);
            continue;
        }

	// before request line found, parse announces incomplete
        if (hp.bufsiz < reqLineEnd) {
            CPPUNIT_ASSERT_EQUAL(garbageEnd, (int)hp.parseOffset_);
            CPPUNIT_ASSERT_EQUAL(false, parseResult);
            CPPUNIT_ASSERT_EQUAL(false, hp.isDone());
            CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_FIRST, hp.parsingStage_);
            continue;
        }

	// before request headers entirely found, parse announces incomplete
        if (hp.bufsiz < mimeEnd) {
            CPPUNIT_ASSERT_EQUAL(reqLineEnd, (int)hp.parseOffset_);
            CPPUNIT_ASSERT_EQUAL(false, parseResult);
            CPPUNIT_ASSERT_EQUAL(false, hp.isDone());
            // TODO: add all the other usual tests for request-line details
            CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_MIME, hp.parsingStage_);
            continue;
        }

        // once request line is found (AND the following \n) current parser announces success
        CPPUNIT_ASSERT_EQUAL(mimeEnd, (int)hp.parseOffset_);
        CPPUNIT_ASSERT_EQUAL(true, parseResult);
        CPPUNIT_ASSERT_EQUAL(true, hp.isDone());
    }
}
