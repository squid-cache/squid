#include "squid.h"
#include <sstream>
#include <cppunit/TestAssert.h>

#include "Mem.h"
#include "testURL.h"
#include "URL.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testURL );

/* stub functions to link successfully */
void
shut_down(int)
{}

/* end stubs */

/* init memory pools */

void
testURL::setUp()
{
    Mem::Init();
}

/*
 * we can construct a URL with a URLScheme.
 * This creates a URL for that scheme.
 */
void
testURL::testConstructScheme()
{
    URLScheme empty_scheme;
    URL protoless_url(PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(empty_scheme, protoless_url.getScheme());

    URLScheme ftp_scheme(PROTO_FTP);
    URL ftp_url(PROTO_FTP);
    CPPUNIT_ASSERT_EQUAL(ftp_scheme, ftp_url.getScheme());
}

/*
 * a default constructed URL has scheme "NONE".
 * Also, we should be able to use new and delete on
 * scheme instances.
 */
void
testURL::testDefaultConstructor()
{
    URLScheme aScheme;
    URL aUrl;
    CPPUNIT_ASSERT_EQUAL(aScheme, aUrl.getScheme());

    URL *urlPointer = new URL;
    CPPUNIT_ASSERT(urlPointer != NULL);
    delete urlPointer;
}
