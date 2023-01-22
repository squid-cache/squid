/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include <cppunit/TestAssert.h>

#include "HttpHeader.h"
#include "HttpRequest.h"
#include "MasterXaction.h"
#include "mime_header.h"
#include "testHttpRequest.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testHttpRequest );

/** wrapper for testing HttpRequest object private and protected functions */
class PrivateHttpRequest : public HttpRequest
{
public:
    PrivateHttpRequest(const MasterXaction::Pointer &mx) : HttpRequest(mx) {}
    bool doSanityCheckStartLine(const char *b, const size_t h, Http::StatusCode *e) { return sanityCheckStartLine(b,h,e); };
};

/* init memory pools */

void
testHttpRequest::setUp()
{
    Mem::Init();
    AnyP::UriScheme::Init();
    httpHeaderInitModule();
}

/*
 * Test creating an HttpRequest object from a Url and method
 */
void
testHttpRequest::testCreateFromUrl()
{
    /* vanilla url, implicit method */
    unsigned short expected_port;
    SBuf url("http://foo:90/bar");
    const auto mx = MasterXaction::MakePortless<XactionInitiator::initHtcp>();
    HttpRequest *aRequest = HttpRequest::FromUrl(url, mx);
    expected_port = 90;
    CPPUNIT_ASSERT(aRequest != nullptr);
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf("/bar"), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));

    /* vanilla url */
    url = "http://foo:90/bar";
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_GET);
    expected_port = 90;
    CPPUNIT_ASSERT(aRequest != nullptr);
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf("/bar"), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));

    /* vanilla url, different method */
    url = "http://foo/bar";
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_PUT);
    expected_port = 80;
    CPPUNIT_ASSERT(aRequest != nullptr);
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_PUT);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf("/bar"), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));

    /* a connect url with non-CONNECT data */
    HttpRequest *nullRequest = nullptr;
    url = ":foo/bar";
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_CONNECT);
    CPPUNIT_ASSERT_EQUAL(nullRequest, aRequest);

    /* a CONNECT url with CONNECT data */
    url = "foo:45";
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_CONNECT);
    expected_port = 45;
    CPPUNIT_ASSERT(aRequest != nullptr);
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_CONNECT);
    CPPUNIT_ASSERT_EQUAL(String("foo"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf(), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_NONE, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));

    // XXX: check METHOD_NONE input handling
}

/*
 * Test BUG: URL '2000:800:45' opens host 2000 port 800 !!
 */
void
testHttpRequest::testIPv6HostColonBug()
{
    unsigned short expected_port;
    HttpRequest *aRequest = nullptr;

    /* valid IPv6 address without port */
    SBuf url("http://[2000:800::45]/foo");
    const auto mx = MasterXaction::MakePortless<XactionInitiator::initHtcp>();
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_GET);
    expected_port = 80;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf("/foo"), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));

    /* valid IPv6 address with port */
    url = "http://[2000:800::45]:90/foo";
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_GET);
    expected_port = 90;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf("/foo"), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));

    /* IPv6 address as invalid (bug trigger) */
    url = "http://2000:800::45/foo";
    aRequest = HttpRequest::FromUrl(url, mx, Http::METHOD_GET);
    expected_port = 80;
    CPPUNIT_ASSERT_EQUAL(expected_port, aRequest->url.port());
    CPPUNIT_ASSERT(aRequest->method == Http::METHOD_GET);
    CPPUNIT_ASSERT_EQUAL(String("[2000:800::45]"), String(aRequest->url.host()));
    CPPUNIT_ASSERT_EQUAL(SBuf("/foo"), aRequest->url.path());
    CPPUNIT_ASSERT_EQUAL(AnyP::PROTO_HTTP, static_cast<AnyP::ProtocolType>(aRequest->url.getScheme()));
}

void
testHttpRequest::testSanityCheckStartLine()
{
    MemBuf input;
    const auto mx = MasterXaction::MakePortless<XactionInitiator::initHtcp>();
    PrivateHttpRequest engine(mx);
    Http::StatusCode error = Http::scNone;
    size_t hdr_len;
    input.init();

    // a valid request line
    input.append("GET / HTTP/1.1\n\n", 16);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(input.content(), hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("GET  /  HTTP/1.1\n\n", 18);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(input.content(), hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    // strange but valid methods
    input.append(". / HTTP/1.1\n\n", 14);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(input.content(), hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("OPTIONS * HTTP/1.1\n\n", 20);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(engine.doSanityCheckStartLine(input.content(), hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

// TODO no method

// TODO binary code in method

// TODO no URL

// TODO no status (okay)

// TODO non-HTTP protocol

    input.append("      \n\n", 8);
    hdr_len = headersEnd(input.content(), input.contentSize());
    CPPUNIT_ASSERT(!engine.doSanityCheckStartLine(input.content(), hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;
}

