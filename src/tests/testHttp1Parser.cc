/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include <cppunit/TestAssert.h>

#define private public
#define protected public

#include "Debug.h"
#include "http/one/RequestParser.h"
#include "http/RequestMethod.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "testHttp1Parser.h"
#include "unitTestMain.h"

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
    SBuf::size_type suffixSz;
    HttpRequestMethod method;
    const char *uri;
    AnyP::ProtocolVersion version;
};

// define SQUID_DEBUG_TESTS to see exactly which test sub-cases fail and where
#ifdef SQUID_DEBUG_TESTS
// not optimized for runtime use
static void
Replace(SBuf &where, const SBuf &what, const SBuf &with)
{
    // prevent infinite loops
    if (!what.length() || with.find(what) != SBuf::npos)
        return;

    SBuf::size_type pos = 0;
    while ((pos = where.find(what, pos)) != SBuf::npos) {
        SBuf buf = where.substr(0, pos);
        buf.append(with);
        buf.append(where.substr(pos+what.length()));
        where = buf;
        pos += with.length();
    }
}

static SBuf Pretty(SBuf raw)
{
    Replace(raw, SBuf("\r"), SBuf("\\r"));
    Replace(raw, SBuf("\n"), SBuf("\\n"));
    return raw;
}
#endif

static void
testResults(int line, const SBuf &input, Http1::RequestParser &output, struct resultSet &expect)
{
#ifdef SQUID_DEBUG_TESTS
    std::cerr << "TEST @" << line << ", in=" << Pretty(input) << "\n";
#endif

    const bool parsed = output.parse(input);

#ifdef SQUID_DEBUG_TESTS
    if (expect.parsed != parsed)
        std::cerr << "\tparse-FAILED: " << expect.parsed << "!=" << parsed << "\n";
    else if (parsed && expect.method != output.method_)
        std::cerr << "\tmethod-FAILED: " << expect.method << "!=" << output.method_ << "\n";
    if (expect.status != output.parseStatusCode)
        std::cerr << "\tscode-FAILED: " << expect.status << "!=" << output.parseStatusCode << "\n";
    if (expect.suffixSz != output.buf_.length())
        std::cerr << "\tsuffixSz-FAILED: " << expect.suffixSz << "!=" << output.buf_.length() << "\n";
#endif

    // runs the parse
    CPPUNIT_ASSERT_EQUAL(expect.parsed, parsed);

    // if parsing was successful, check easily visible field outputs
    if (parsed) {
        CPPUNIT_ASSERT_EQUAL(expect.method, output.method_);
        if (expect.uri != NULL)
            CPPUNIT_ASSERT_EQUAL(0, output.uri_.cmp(expect.uri));
        CPPUNIT_ASSERT_EQUAL(expect.version, output.msgProtocol_);
    }

    CPPUNIT_ASSERT_EQUAL(expect.status, output.parseStatusCode);

    // check more obscure states
    CPPUNIT_ASSERT_EQUAL(expect.needsMore, output.needsMoreData());
    if (output.needsMoreData())
        CPPUNIT_ASSERT_EQUAL(expect.parserState, output.parsingStage_);
    CPPUNIT_ASSERT_EQUAL(expect.suffixSz, output.buf_.length());
}

void
testHttp1Parser::testParserConstruct()
{
    // whether the constructor works
    {
        Http1::RequestParser output;
        CPPUNIT_ASSERT_EQUAL(true, output.needsMoreData());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_NONE, output.parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scNone, output.parseStatusCode); // XXX: clear() not being called.
        CPPUNIT_ASSERT(output.buf_.isEmpty());
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_NONE), output.method_);
        CPPUNIT_ASSERT(output.uri_.isEmpty());
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output.msgProtocol_);
    }

    // whether new() works
    {
        Http1::RequestParser *output = new Http1::RequestParser;
        CPPUNIT_ASSERT_EQUAL(true, output->needsMoreData());
        CPPUNIT_ASSERT_EQUAL(Http1::HTTP_PARSE_NONE, output->parsingStage_);
        CPPUNIT_ASSERT_EQUAL(Http::scNone, output->parseStatusCode);
        CPPUNIT_ASSERT(output->buf_.isEmpty());
        CPPUNIT_ASSERT_EQUAL(HttpRequestMethod(Http::METHOD_NONE), output->method_);
        CPPUNIT_ASSERT(output->uri_.isEmpty());
        CPPUNIT_ASSERT_EQUAL(AnyP::ProtocolVersion(), output->msgProtocol_);
        delete output;
    }
}

#if __cplusplus >= 201103L
void
testHttp1Parser::testParseRequestLineProtocols()
{
    // ensure MemPools etc exist
    globalSetup();

    SBuf input;
    Http1::RequestParser output;

    // TEST: Do we comply with RFC 1945 section 5.1 ?
    // TEST: Do we comply with RFC 7230 sections 2.6, 3.1.1 and 3.5 ?

    // RFC 1945 : HTTP/0.9 simple-request
    {
        input.append("GET /\r\n", 7);
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 1945 : invalid HTTP/0.9 simple-request (only GET is valid)
    {
        input.append("POST /\r\n", 8);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_POST),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 1945 and 7230 : HTTP/1.0 request
    {
        input.append("GET / HTTP/1.0\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 7230 : HTTP/1.1 request
    {
        input.append("GET / HTTP/1.1\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 7230 : future 1.x version full-request
    {
        input.append("GET / HTTP/1.2\r\n", 16);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,2)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 7230 : future versions do not use 1.x message syntax.
    // However, it is still valid syntax for the single-digit forms
    // to appear. The parser we are testing should accept them.
    {
        input.append("GET / HTTP/2.0\r\n", 16);
        struct resultSet expectA = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,2,0)
        };
        output.clear();
        testResults(__LINE__, input, output, expectA);
        input.clear();

        input.append("GET / HTTP/9.9\r\n", 16);
        struct resultSet expectB = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,9,9)
        };
        output.clear();
        testResults(__LINE__, input, output, expectB);
        input.clear();
    }

    // RFC 7230 : future versions >= 10.0 are invalid syntax
    {
        input.append("GET / HTTP/10.12\r\n", 18);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // unknown non-HTTP protocol names
    {
        input.append("GET / FOO/1.0\r\n", 15);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no version digits
    {
        input.append("GET / HTTP/\r\n", 13);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no major version
    {
        input.append("GET / HTTP/.1\r\n", 15);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no version dot
    {
        input.append("GET / HTTP/11\r\n", 15);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // negative major version (bug 3062)
    {
        input.append("GET / HTTP/-999999.1\r\n", 22);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no minor version
    {
        input.append("GET / HTTP/1.\r\n", 15);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // negative major version (bug 3062 corollary)
    {
        input.append("GET / HTTP/1.-999999\r\n", 22);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion()
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
        // when being tolerant extra (sequential) SP delimiters are acceptable
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // whitespace inside URI. (nasty but happens)
    {
        input.append("GET /fo o/ HTTP/1.1\r\n", 21);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/fo o/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // additional data in buffer
    {
        input.append("GET / HTTP/1.1\r\nboo!", 20);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 4, // strlen("boo!")
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
        Config.onoff.relaxed_header_parser = 0;
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
    // RFC 7230 tolerance permits omitted CR
    {
        input.append("GET / HTTP/1.1\n", 15);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // alternative EOL sequence: double-NL-only
    // RFC 7230 tolerance permits omitted CR
    // NP: represents a request with no mime headers
    {
        input.append("GET / HTTP/1.1\n\n", 16);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = true,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // space padded version
    {
        // RFC 7230 specifies version is followed by CRLF. No intermediary bytes.
        input.append("GET / HTTP/1.1 \r\n", 17);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
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

    // RFC 7230 : dot method
    {
        input.append(". / HTTP/1.1\r\n", 14);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(SBuf(".")),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 7230 : special TCHAR method chars
    {
        input.append("!#$%&'*+-.^_`|~ / HTTP/1.1\r\n", 28);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(SBuf("!#$%&'*+-.^_`|~")),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // OPTIONS with * URL
    {
        input.append("OPTIONS * HTTP/1.1\r\n", 20);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_OPTIONS),
            .uri = "*",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // unknown method
    {
        input.append("HELLOWORLD / HTTP/1.1\r\n", 23);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(SBuf("HELLOWORLD")),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

#if 0
    // too-long method (over 16 bytes)
    {
        input.append("HELLOSTRANGEWORLD / HTTP/1.1\r\n", 31);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scNotImplemented,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }
#endif

    // method-only
    {
        input.append("A\n", 2);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
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
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // space padded method (SP is reserved so invalid as a method byte)
    {
        input.append(" GET / HTTP/1.1\r\n", 17);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // RFC 7230 defined tolerance: ignore empty line(s) prefix on messages
    {
        input.append("\r\n\r\n\nGET / HTTP/1.1\r\n", 21);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // forbidden character in method
    {
        input.append("\tGET / HTTP/1.1\r\n", 17);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // CR in method delimiters
    {
        // RFC 7230 section 3.5 permits CR in whitespace but only for tolerant parsers
        input.append("GET\r / HTTP/1.1\r\n", 17);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // tolerant parser delimiters
    {
        // RFC 7230 section 3.5 permits certain binary characters as whitespace delimiters
        input.append("GET\r\t\x0B\x0C / HTTP/1.1\r\n", 20);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_MIME,
            .status = Http::scOkay,
            .suffixSz = 0,
            .method = HttpRequestMethod(Http::METHOD_GET),
            .uri = "/",
            .version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1)
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
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

    // no method (or method delimiter)
    {
        // HTTP/0.9 requires method to be "GET"
        input.append("/ HTTP/1.0\n", 11);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // no method (with method delimiter)
    {
        input.append(" / HTTP/1.0\n", 12);
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // binary code after method (invalid)
    {
        input.append("GET\x16 / HTTP/1.1\r\n", 17);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // binary code NUL! after method (always invalid)
    {
        input.append("GET\0 / HTTP/1.1\r\n", 17);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // Either an RFC 1945 HTTP/0.9 simple-request for an "HTTP/1.1" URI or
    // an invalid (no URI) HTTP/1.1 request. We treat this as latter, naturally.
    {
        input.append("GET  HTTP/1.1\r\n", 15);
        Config.onoff.relaxed_header_parser = 1;
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);

        Config.onoff.relaxed_header_parser = 0;
        struct resultSet expectStrict = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expectStrict);
        input.clear();
    }

    // Either an RFC 1945 HTTP/0.9 simple-request for an "HTTP/1.1" URI or
    // an invalid (no URI) HTTP/1.1 request. We treat this as latter, naturally.
    {
        input.append("GET HTTP/1.1\r\n", 14);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
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
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // mixed whitespace line
    {
        input.append("\t \t \t\n", 6);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };
        output.clear();
        testResults(__LINE__, input, output, expect);
        input.clear();
    }

    // mixed whitespace line with CR
    {
        input.append("\r  \t \n", 6);
        struct resultSet expect = {
            .parsed = false,
            .needsMore = false,
            .parserState = Http1::HTTP_PARSE_DONE,
            .status = Http::scBadRequest,
            .suffixSz = input.length(),
            .method = HttpRequestMethod(),
            .uri = NULL,
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
    data.append("\n\n\n\n\n\n\n\n\n\n\n\n", 12);
    SBuf::size_type garbageEnd = data.length();
    data.append("GET ", 4);
    data.append("http://example.com/ ", 20);
    data.append("HTTP/1.1\r\n", 10);
    SBuf::size_type reqLineEnd = data.length() - 1;
    data.append("Host: example.com\r\n\r\n", 21);
    SBuf::size_type mimeEnd = data.length() - 1;
    data.append("...", 3); // trailer to catch mime EOS errors.

    SBuf ioBuf;
    Http1::RequestParser hp;

    // start with strict and move on to relaxed
    Config.onoff.relaxed_header_parser = 2;

    Config.maxRequestHeaderSize = 1024; // large enough to hold the test data.

    do {

        // state of things we expect right now
        struct resultSet expect = {
            .parsed = false,
            .needsMore = true,
            .parserState = Http1::HTTP_PARSE_NONE,
            .status = Http::scNone,
            .suffixSz = 0,
            .method = HttpRequestMethod(),
            .uri = NULL,
            .version = AnyP::ProtocolVersion()
        };

        ioBuf.clear(); // begins empty for each parser type
        hp.clear();

        --Config.onoff.relaxed_header_parser;

        for (SBuf::size_type pos = 0; pos <= data.length(); ++pos) {

            // simulate reading one more byte
            ioBuf.append(data.substr(pos,1));

            // strict does not permit the garbage prefix
            if (pos < garbageEnd && !Config.onoff.relaxed_header_parser) {
                ioBuf.clear();
                continue;
            }

            // when the garbage is passed we expect to start seeing first-line bytes
            if (pos == garbageEnd)
                expect.parserState = Http1::HTTP_PARSE_FIRST;

            // all points after garbage start to see accumulated bytes looking for end of current section
            if (pos >= garbageEnd)
                expect.suffixSz = ioBuf.length();

            // at end of request line expect to see method, URI, version details
            // and switch to seeking Mime header section
            if (pos == reqLineEnd) {
                expect.parserState = Http1::HTTP_PARSE_MIME;
                expect.suffixSz = 0; // and a checkpoint buffer reset
                expect.status = Http::scOkay;
                expect.method = HttpRequestMethod(Http::METHOD_GET);
                expect.uri = "http://example.com/";
                expect.version = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1);
            }

            // one mime header is done we are expecting a new request
            // parse results say true and initial data is all gone from the buffer
            if (pos == mimeEnd) {
                expect.parsed = true;
                expect.needsMore = false;
                expect.suffixSz = 0; // and a checkpoint buffer reset
            }

            testResults(__LINE__, ioBuf, hp, expect);

            // sync the buffers like Squid does
            ioBuf = hp.remaining();

            // Squid stops using the parser once it has parsed the first message.
            if (!hp.needsMoreData())
                break;
        }

    } while (Config.onoff.relaxed_header_parser);

}
#endif /* __cplusplus >= 201103L */

