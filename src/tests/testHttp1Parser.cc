#define SQUID_UNIT_TEST 1
#include "squid.h"

#include <cppunit/TestAssert.h>

#define private public
#define protected public

#include "testHttp1Parser.h"
#include "http/one/RequestParser.h"
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

struct resultSet {
    bool parsed;
    bool needsMore;
    Http1::ParseState parserState;
    Http::StatusCode status;
    int msgStart;
    int msgEnd;
    SBuf::size_type suffixSz;
    int methodStart;
    int methodEnd;
    HttpRequestMethod method;
    int uriStart;
    int uriEnd;
    const char *uri;
    int versionStart;
    int versionEnd;
    AnyP::ProtocolVersion version;
};

static void
testResults(int line, const SBuf &input, Http1::RequestParser &output, struct resultSet &expect)
{
#if WHEN_TEST_DEBUG_IS_NEEDED
    printf("TEST @%d, in=%u: " SQUIDSBUFPH "\n", line, input.length(), SQUIDSBUFPRINT(input));
#endif

    CPPUNIT_ASSERT_EQUAL(expect.parsed, output.parse(input));
    CPPUNIT_ASSERT_EQUAL(expect.needsMore, output.needsMoreData());
    if (output.needsMoreData())
        CPPUNIT_ASSERT_EQUAL(expect.parserState, output.parsingStage_);
    CPPUNIT_ASSERT_EQUAL(expect.status, output.request_parse_status);
    CPPUNIT_ASSERT_EQUAL(expect.msgStart, output.req.start);
    CPPUNIT_ASSERT_EQUAL(expect.msgEnd, output.req.end);
    CPPUNIT_ASSERT_EQUAL(expect.suffixSz, output.buf.length());
    CPPUNIT_ASSERT_EQUAL(expect.methodStart, output.req.m_start);
    CPPUNIT_ASSERT_EQUAL(expect.methodEnd, output.req.m_end);
    CPPUNIT_ASSERT_EQUAL(expect.method, output.method_);
    CPPUNIT_ASSERT_EQUAL(expect.uriStart, output.req.u_start);
    CPPUNIT_ASSERT_EQUAL(expect.uriEnd, output.req.u_end);
    if (expect.uri != NULL)
        CPPUNIT_ASSERT_EQUAL(0, output.uri_.cmp(expect.uri));
    CPPUNIT_ASSERT_EQUAL(expect.versionStart, output.req.v_start);
    CPPUNIT_ASSERT_EQUAL(expect.versionEnd, output.req.v_end);
    CPPUNIT_ASSERT_EQUAL(expect.version, output.msgProtocol_);
}

void
testHttp1Parser::testParseRequestLineProtocols()
{
    // ensure MemPools etc exist
    globalSetup();

    SBuf input;
    Http1::RequestParser output;

    // TEST: Do we comply with RFC 1945 section 5.1 ?
    // TEST: Do we comply with RFC 2616 section 5.1 ?

    // RFC 1945 : HTTP/0.9 simple-request
    {
        input.append("GET /\r\n", 7);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 1945 : invalid HTTP/0.9 simple-request (only GET is valid)
#if WHEN_RFC_COMPLIANT
    {
        input.append("POST /\r\n", 7);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 3,
            .method = HttpRequestMethod(Http::METHOD_POST),
            .uriStart = 5,
            .uriEnd = 5,
            .uri = "/",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
#endif
    // RFC 1945 and 2616 : HTTP/1.0 request
    {
        input.append("GET / HTTP/1.0\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 2616 : HTTP/1.1 request
    {
        input.append("GET / HTTP/1.1\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 2616 : future version full-request
    {
        input.append("GET / HTTP/1.2\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,2)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 2616 : future version full-request
    {
        // IETF HTTPbis WG has made this two-digits format invalid.
        // it gets treated same as HTTP/0.9 for now
        input.append("GET / HTTP/10.12\r\n", 18);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 15,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,10,12)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // unknown non-HTTP protocol names
    {
        // XXX: violations mode treats them as HTTP/0.9 requests! which is wrong.
#if !USE_HTTP_VIOLATIONS
        input.append("GET / FOO/1.0\n", 14);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 12,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
#endif
    }

    // no version
    {
        input.append("GET / HTTP/\n", 12);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 10,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no major version
    {
        input.append("GET / HTTP/.1\n", 14);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 12,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no version dot
    {
        input.append("GET / HTTP/11\n", 14);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 12,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // negative major version (bug 3062)
    {
        input.append("GET / HTTP/-999999.1\n", 21);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 19,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no minor version
    {
        input.append("GET / HTTP/1.\n", 14);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 12,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // negative major version (bug 3062 corollary)
    {
        input.append("GET / HTTP/1.-999999\n", 21);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scHttpVersionNotSupported,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 19,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
}

void
testHttp1Parser::testParseRequestLineStrange()
{
    // ensure MemPools etc exist
    globalSetup();

    SBuf input;
    Http1::RequestParser output;

    // space padded URL
    {
        input.append("GET  /     HTTP/1.1\r\n", 21);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 5,
            .uriEnd = 5,
            .uri = "/",
            .versionStart = 11,
            .versionEnd = 18,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // whitespace inside URI. (nasty but happens)
    // XXX: depends on tolerant parser...
    {
        input.append("GET /fo o/ HTTP/1.1\n", 20);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 9,
            .uri = "/fo o/",
            .versionStart = 11,
            .versionEnd = 18,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // additional data in buffer
    {
        input.append("GET /     HTTP/1.1\nboo!", 23);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-5,
            .suffixSz = 4, // strlen("boo!")
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 10,
            .versionEnd = 17,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
}

void
testHttp1Parser::testParseRequestLineTerminators()
{
    // ensure MemPools etc exist
    globalSetup();

    SBuf input;
    Http1::RequestParser output;

    // alternative EOL sequence: NL-only
    {
        input.append("GET / HTTP/1.1\n", 15);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // alternative EOL sequence: double-NL-only
    {
        input.append("GET / HTTP/1.1\n\n", 16);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-2,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // alternative EOL sequence: multi-CR-NL
    {
        input.append("GET / HTTP/1.1\r\r\r\n", 18);
        // Being tolerant we can ignore and elide these apparently benign CR
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expectRelaxed = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expectRelaxed);

        // strict mode treats these as several bare-CR in the request line which is explicitly invalid.
        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = -1,
            .suffixSz = input.length(),
            .methodStart =-1,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // space padded version
    {
        // RFC 1945 and 2616 specify version is followed by CRLF. No intermediary bytes.
        // NP: the terminal whitespace is a special case: invalid for even HTTP/0.9 with no version tag
        input.append("GET / HTTP/1.1 \n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 13,
            .uri = "/ HTTP/1.1",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
}

void
testHttp1Parser::testParseRequestLineMethods()
{
    // ensure MemPools etc exist
    globalSetup();

    SBuf input;
    Http1::RequestParser output;

    // RFC 2616 : . method
    {
        input.append(". / HTTP/1.1\n", 13);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 0,
            .method = HttpRequestMethod("."),
            .uriStart = 2,
            .uriEnd = 2,
            .uri = "/",
            .versionStart = 4,
            .versionEnd = 11,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // OPTIONS with * URL
    {
        input.append("OPTIONS * HTTP/1.1\n", 19);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 6,
            .method = HttpRequestMethod(Http::METHOD_OPTIONS),
            .uriStart = 8,
            .uriEnd = 8,
            .uri = "*",
            .versionStart = 10,
            .versionEnd = 17,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // unknown method
    {
        input.append("HELLOWORLD / HTTP/1.1\n", 22);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 9,
            .method = HttpRequestMethod("HELLOWORLD"),
            .uriStart = 11,
            .uriEnd = 11,
            .uri = "/",
            .versionStart = 13,
            .versionEnd = 20,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // method-only
    {
        input.append("A\n", 2);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    {
        input.append("GET\n", 4);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // space padded method (in strict mode SP is reserved so invalid as a method byte)
    {
        input.append(" GET / HTTP/1.1\n", 16);
        // RELAXED mode Squid custom tolerance ignores SP
#if USE_HTTP_VIOLATIONS
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expectRelaxed = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0, // garbage collection consumes the SP
            .msgEnd = (int)input.length()-2,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expectRelaxed);
#endif

        // STRICT mode obeys RFC syntax
        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // RFC 2616 defined tolerance: ignore empty line(s) prefix on messages
#if WHEN_RFC_COMPLIANT
    {
        input.append("\r\n\r\n\nGET / HTTP/1.1\r\n", 21);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 5,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 5,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 4,
            .uri = "/",
            .versionStart = 6,
            .versionEnd = 13,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
#endif

    // tab padded method (NP: tab is not SP so treated as any other binary)
    {
        input.append("\tGET / HTTP/1.1\n", 16);
#if WHEN_RFC_COMPLIANT
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = -1,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
#else // XXX: currently broken
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0, // garbage collection consumes the SP
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 3,
            .method = HttpRequestMethod(SBuf("\tGET")),
            .uriStart = 5,
            .uriEnd = 5,
            .uri = "/",
            .versionStart = 7,
            .versionEnd = 14,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
#endif
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
}

void
testHttp1Parser::testParseRequestLineInvalid()
{
    // ensure MemPools etc exist
    globalSetup();

    SBuf input;
    Http1::RequestParser output;

    // no method (but in a form which is ambiguous with HTTP/0.9 simple-request)
    {
        // XXX: HTTP/0.9 requires method to be "GET"
        input.append("/ HTTP/1.0\n", 11);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 0,
            .method = HttpRequestMethod("/"),
            .uriStart = 2,
            .uriEnd = 9,
            .uri = "HTTP/1.0",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no method (an invalid format)
    {
        input.append(" / HTTP/1.0\n", 12);

        // XXX: squid custom tolerance consumes initial SP.
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expectRelaxed = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-2,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 0,
            .method = HttpRequestMethod("/"),
            .uriStart = 2,
            .uriEnd = 9,
            .uri = "HTTP/1.0",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expectRelaxed);

        // STRICT detect as invalid
        Config.onoff.relaxed_header_parser = 0;
#if WHEN_RFC_COMPLIANT
        // XXX: except Squid does not
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
#else
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
#endif
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // binary code in method (invalid)
    {
        input.append("GET\x0B / HTTP/1.1\n", 16);
#if WHEN_RFC_COMPLIANT
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = -1,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
#else
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0, // garbage collection consumes the SP
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 3,
            .method = HttpRequestMethod(SBuf("GET\x0B")),
            .uriStart = 5,
            .uriEnd = 5,
            .uri = "/",
            .versionStart = 7,
            .versionEnd = 14,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
#endif
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // CR in method
    {
        // RFC 2616 sec 5.1 prohibits CR other than in terminator.
        input.append("GET\r / HTTP/1.1\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = -1, // halt at the first \r
            .suffixSz = input.length(),
            .methodStart = -1,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // binary code NUL! in method (strange but ...)
    {
        input.append("GET\0 / HTTP/1.1\n", 16);
#if WHEN_RFC_COMPLIANT
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = -1, // halt at the \0
            .suffixSz = input.length(),
            .methodStart = -1,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
#else
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 3,
            .method = HttpRequestMethod(SBuf("GET\0",4)),
            .uriStart = 5,
            .uriEnd = 5,
            .uri = "/",
            .versionStart = 7,
            .versionEnd = 14,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
#endif
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no URL (grammer invalid, ambiguous with RFC 1945 HTTP/0.9 simple-request)
    {
        input.append("GET  HTTP/1.1\n", 14);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 5,
            .uriEnd = 12,
            .uri = "HTTP/1.1",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no URL (grammer invalid, ambiguous with RFC 1945 HTTP/0.9 simple-request)
    {
        input.append("GET HTTP/1.1\n", 13);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = 0,
            .methodStart = 0,
            .methodEnd = 2,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uriStart = 4,
            .uriEnd = 11,
            .uri = "HTTP/1.1",
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // binary line
    {
        input.append("\xB\xC\xE\xF\n", 5);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // mixed whitespace line
    {
        // We accept non-space binary bytes for method so first \t shows up as that
        // but remaining space and tabs are skipped searching for URI-start
        input.append("\t \t \t\n", 6);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = (int)input.length()-1,
            .suffixSz = input.length(),
            .methodStart = 0,
            .methodEnd = 0,
            .method = HttpRequestMethod(SBuf("\t")),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // mixed whitespace line with CR middle
    {
        // CR aborts on sight, so even initial \t method is not marked as above
        // (not when parsing clean with whole line available anyway)
        input.append("\t  \r \n", 6);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .msgStart = 0,
            .msgEnd = -1, // halt on the \r
            .suffixSz = input.length(),
            .methodStart = -1,
            .methodEnd = -1,
            .method = HttpRequestMethod(),
            .uriStart = -1,
            .uriEnd = -1,
            .uri = NULL,
            .versionStart = -1,
            .versionEnd = -1,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
}

void
testHttp1Parser::testDripFeed()
{
    // Simulate a client drip-feeding Squid a few bytes at a time.
    // extend the size of the buffer from 0 bytes to full request length
    // calling the parser repeatedly as visible data grows.

    SBuf data;
    data.append("            ", 12);
    SBuf::size_type garbageEnd = data.length();
    data.append("GET http://example.com/ HTTP/1.1\r\n", 34);
    SBuf::size_type reqLineEnd = data.length() - 1;
    data.append("Host: example.com\r\n\r\n", 21);
    SBuf::size_type mimeEnd = data.length() - 1;
    data.append("...", 3); // trailer to catch mime EOS errors.

    SBuf ioBuf; // begins empty
    Http1::RequestParser hp;

    // only relaxed parser accepts the garbage whitespace
    Config.onoff.relaxed_header_parser = 1;

    // state of things we expect right now
    struct resultSet expect = {
        .parsed = false,
        .needsMore = true,
        .parserState = Http1::HTTP_PARSE_NONE,
        .status = Http::scBadRequest,
        .msgStart = 0,
        .msgEnd = -1,
        .suffixSz = 0,
        .methodStart = -1,
        .methodEnd = -1,
        .method = HttpRequestMethod(),
        .uriStart = -1,
        .uriEnd = -1,
        .uri = NULL,
        .versionStart = -1,
        .versionEnd = -1,
        .version = AnyP::ProtocolVersion()
    };

    Config.maxRequestHeaderSize = 1024; // large enough to hold the test data.

    for (SBuf::size_type pos = 0; pos <= data.length(); ++pos) {

        // simulate reading one more byte
        ioBuf.append(data.substr(pos,1));

        // when the garbage is passed we expect to start seeing first-line bytes
        if (pos == garbageEnd) {
            expect.parserState = Http1::HTTP_PARSE_FIRST;
            expect.msgStart = 0;
        }

        // all points after garbage start to see accumulated bytes looking for end of current section
        if (pos >= garbageEnd)
            expect.suffixSz = ioBuf.length();

        // at end of request line expect to see method, URI, version details
        // and switch to seeking Mime header section
        if (pos == reqLineEnd) {
            expect.parserState = Http1::HTTP_PARSE_MIME;
            expect.suffixSz = 0;
            expect.msgEnd = reqLineEnd-garbageEnd;
            expect.status = Http::scOkay;
            expect.methodStart = 0;
            expect.methodEnd = 2;
            expect.method = HttpRequestMethod(Http::METHOD_GET);
            expect.uriStart = 4;
            expect.uriEnd = 22;
            expect.uri = "http://example.com/";
            expect.versionStart = 24;
            expect.versionEnd = 31;
            expect.version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1);
        }

        // one mime header is done we are expectign a new request
        // parse results say true and initial data is all gone from the buffer
        if (pos == mimeEnd) {
            expect.parsed = true;
            expect.needsMore = false;
            expect.suffixSz = 0;
        }

        testResults(__LINE__, ioBuf, hp, expect);

        // sync the buffers like Squid does
        ioBuf = hp.buf;

        // Squid stops using the parser once it has parsed the first message.
        if (!hp.needsMoreData())
            break;
    }
}
