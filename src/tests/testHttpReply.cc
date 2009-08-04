#include "config.h"
#include <cppunit/TestAssert.h>

#include "testHttpReply.h"
#include "HttpReply.h"
#include "Mem.h"

/* to avoid libsquid.la and its comm stuff */
#include "TextException.cc"

CPPUNIT_TEST_SUITE_REGISTRATION( testHttpReply );

struct SquidConfig Config;

/* stub functions to link successfully */

#include "Store.h"
void
StoreEntry::timestampsSet()
{
    fatal("StoreEntry::timestampsSet. Not implemented.");
}

void
StoreEntry::setPublicKey()
{
    fatal("StoreEntry::setPulicKey. Not implemented.");
}

#include "MemObject.h"
int64_t
MemObject::endOffset() const
{
    return 0;
}

#include "ConfigParser.h"
void
ConfigParser::destruct()
{
// CALLED as shutdown no-op
//    fatal("ConfigParser::destruct. Not implemented.");
}

void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{
// CALLED as setUp no-op
//    fatal("eventAdd. Not implemented.");
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
    http_status error = HTTP_STATUS_NONE;
    size_t hdr_len;
    input.init();

    // a valid status line
    input.append("HTTP/1.1 200 Okay\n\n", 19);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 1 && engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("HTTP/1.1    200  Okay     \n\n", 28);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 2 && engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

#if TODO // these cases are only checked after parse...
    // invalid status line
    input.append("HTTP/1.1 999 Okay\n\n", 19);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 3 && !engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("HTTP/1.1    2000  Okay     \n\n", 29);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 4 && engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;
#endif

    // empty status line
    input.append("\n\n", 2);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 5 && !engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("      \n\n", 8);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT( 6 && !engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    // status line with no message
    input.append("HTTP/1.1 200\n\n", 14); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("HTTP/1.1 200 \n\n", 15); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_STATUS_NONE);
    input.reset();
    error = HTTP_STATUS_NONE;

    // status line with no status
    input.append("HTTP/1.1 \n\n", 11);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("HTTP/1.1     \n\n", 15);
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    input.append("HTTP/1.1  Okay\n\n", 16); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    // status line with nul-byte
    input.append("HTTP/1.1\0200 Okay\n\n", 19); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    // status line with negative status
    input.append("HTTP/1.1 -000\n\n", 15); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;

    // status line with non-HTTP protocol
    input.append("ICY/1.1 200 Okay\n\n", 18); /* real case seen */
    hdr_len = headersEnd(input.content(),input.contentSize());
    /* NP: for nw ICY is handled as a pass-thru */
    /*     Squid-3 will ignore it (and mangle the headers as per HTTP). */
    CPPUNIT_ASSERT(!engine.sanityCheckStartLine(&input, hdr_len, &error) );
    CPPUNIT_ASSERT_EQUAL(error, HTTP_INVALID_HEADER);
    input.reset();
    error = HTTP_STATUS_NONE;
}
