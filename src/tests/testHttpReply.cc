/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include <cppunit/TestAssert.h>

#include "HttpHeader.h"
#include "HttpReply.h"
#include "Mem.h"
#include "mime_header.h"
#include "SquidConfig.h"
#include "testHttpReply.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testHttpReply );

class SquidConfig Config;

/* stub functions to link successfully */

#include "MemObject.h"
int64_t
MemObject::endOffset() const
{
    return 0;
}

/* end */

void
testHttpReply::setUp()
{
    Mem::Init();
    httpHeaderInitModule();
}

void
testHttpReply::testSanityCheckFirstLine()
{
    MemBuf input;
    HttpReply engine;
    Http::StatusCode error = Http::scNone;
    size_t hdr_len;
    input.init();

    // a valid status line
    input.append("HTTP/1.1 200 Okay\n\n", 19);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 1 && engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1    200  Okay     \n\n", 28);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 2 && engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

#if TODO // these cases are only checked after parse...
    // invalid status line
    input.append("HTTP/1.1 999 Okay\n\n", 19);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 3 && !engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1    2000  Okay     \n\n", 29);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 4 && engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;
#endif

    // valid ICY protocol status line
    input.append("ICY 200 Okay\n\n", 14);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;
    /* NP: the engine saves details about the protocol. even when being reset :( */
    engine.protoPrefix="HTTP/";
    engine.reset();

    // empty status line
    input.append("\n\n", 2);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 5 && !engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    input.append("      \n\n", 8);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 6 && !engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    // status line with no message
    input.append("HTTP/1.1 200\n\n", 14); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1 200 \n\n", 15); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    // incomplete (short) status lines... not sane (yet), but no error either.
    input.append("H", 1);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/", 5);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1", 6);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1", 8);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1 ", 9); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1    20", 14);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scNone);
    input.reset();
    error = Http::scNone;

    // status line with no status
    input.append("HTTP/1.1 \n\n", 11);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1     \n\n", 15);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    input.append("HTTP/1.1  Okay\n\n", 16); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    // status line with nul-byte
    input.append("HTTP/1.1" "\0" "200 Okay\n\n", 19); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;

    // status line with negative status
    input.append("HTTP/1.1 -000\n\n", 15); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, Http::scInvalidHeader);
    input.reset();
    error = Http::scNone;
}

