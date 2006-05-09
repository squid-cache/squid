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

struct Initer
{
    Initer() {Mem::Init();}
};

static Initer ensure_mempools;

/*
 * we can construct a URL with a URLScheme.
 * This creates a URL for that scheme.
 */
void
testURL::testConstructScheme()
{
    CPPUNIT_ASSERT_EQUAL(URLScheme(), URL(PROTO_NONE).getScheme());
    CPPUNIT_ASSERT_EQUAL(URLScheme(PROTO_FTP), URL(PROTO_FTP).getScheme());
}

/*
 * a default constructed URL has scheme "NONE".
 * Also, we should be able to use new and delete on
 * scheme instances.
 */
void
testURL::testDefaultConstructor()
{
    URL aUrl;
    CPPUNIT_ASSERT_EQUAL(URLScheme(), aUrl.getScheme());

    URL *urlPointer = new URL;
    CPPUNIT_ASSERT(urlPointer != NULL);
    delete urlPointer;
}
