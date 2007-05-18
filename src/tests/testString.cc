#include "squid.h"
#include "event.h"
#include "Mem.h"
#include "SquidString.h"
#include "testString.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testString );

/* let this test link sanely */
void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{}

/* init memory pools */

struct Initer
{
    Initer() {Mem::Init();}
};

static Initer ensure_mempools;

void
testString::testDefaults()
{
    string aStr;

    /* check this reports as empty */
    CPPUNIT_ASSERT( aStr.empty() );
    CPPUNIT_ASSERT_EQUAL( (const char*)NULL, aStr.c_str() );
    CPPUNIT_ASSERT_EQUAL( 0, aStr.size() );

    string bStr("foo bar");

    /* check copy constructor */
    CPPUNIT_ASSERT( !bStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 7, bStr.size() );
    CPPUNIT_ASSERT( NULL != bStr.c_str() );
    CPPUNIT_ASSERT( memcmp(bStr.c_str(), "foo bar", 8) == 0 );
}

void
testString::testBooleans()
{
    const string smStr("bar");
    const string bgStr("foo");
    const string eqStr("foo");
    const string nqStr("food");

   /* mathematical boolean operators */
   CPPUNIT_ASSERT(!(bgStr == smStr ));
   CPPUNIT_ASSERT(  bgStr != smStr );
   CPPUNIT_ASSERT(  bgStr >  smStr );
   CPPUNIT_ASSERT(!(bgStr <  smStr ));
   CPPUNIT_ASSERT(  bgStr >= smStr );
   CPPUNIT_ASSERT(!(bgStr <= smStr ));

   /* reverse order to catch corners */
   CPPUNIT_ASSERT(!(smStr == bgStr ));
   CPPUNIT_ASSERT(  smStr != bgStr );
   CPPUNIT_ASSERT(!(smStr >  bgStr ));
   CPPUNIT_ASSERT(  smStr <  bgStr );
   CPPUNIT_ASSERT(!(smStr >= bgStr ));
   CPPUNIT_ASSERT(  smStr <= bgStr );

   /* check identical to catch corners */
   CPPUNIT_ASSERT(  bgStr == eqStr );
   CPPUNIT_ASSERT(!(bgStr != eqStr ));
   CPPUNIT_ASSERT(!(bgStr >  eqStr ));
   CPPUNIT_ASSERT(!(bgStr <  eqStr ));
   CPPUNIT_ASSERT(  bgStr >= eqStr );
   CPPUNIT_ASSERT(  bgStr <= eqStr );

   /* check _almost_ identical to catch corners */
   CPPUNIT_ASSERT(!(bgStr == nqStr ));
   CPPUNIT_ASSERT(  bgStr != nqStr );
   CPPUNIT_ASSERT(!(bgStr >  nqStr ));
   CPPUNIT_ASSERT(  bgStr <  nqStr );
   CPPUNIT_ASSERT(!(bgStr >= nqStr ));
   CPPUNIT_ASSERT(  bgStr <= nqStr );
}

void
testString::testAppend()
{
    // FIXME: make tests for this.
    string aStr("hello");

    aStr.append(" world");
    CPPUNIT_ASSERT_EQUAL( (string)"hello world", aStr );
    aStr.append(" howsit", 7);
    CPPUNIT_ASSERT_EQUAL( (string)"hello world howsit", aStr );

    string bStr;
    string cStr("hello");

    /* corner cases */
    bStr.append(NULL, 2);
    CPPUNIT_ASSERT( bStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 0, bStr.size() );
    CPPUNIT_ASSERT_EQUAL( (string)"", bStr );

    bStr.append("hello", 5);
    CPPUNIT_ASSERT( !bStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 5, bStr.size() );
    CPPUNIT_ASSERT_EQUAL( (string)"hello", bStr );

    bStr.append(NULL, 2);
    CPPUNIT_ASSERT( !bStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 5, bStr.size() );
    CPPUNIT_ASSERT_EQUAL( (string)"hello", bStr );

    bStr.append(" world untroubled by things such as null termination", 6);
    CPPUNIT_ASSERT( !bStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 11, bStr.size() );
    CPPUNIT_ASSERT_EQUAL( (string)"hello world", bStr );

    cStr.append(" wo");
    CPPUNIT_ASSERT( !cStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 8, cStr.size() );
    CPPUNIT_ASSERT_EQUAL( (string)"hello wo", cStr );

    cStr.append("rld\0 untroubled by things such as null termination", 10);
    CPPUNIT_ASSERT( !cStr.empty() );
    CPPUNIT_ASSERT_EQUAL( 18, cStr.size() );
    CPPUNIT_ASSERT_EQUAL( (string)"hello world\0 untr", cStr );
}

void
testString::testAssignments()
{
    // FIXME: make tests for this.
}

void
testString::testCstrMethods()
{
    // FIXME: make tests for this.
    // strcmp, strncmp, etc....
}

void
testString::testSearch()
{
    // FIXME: make tests for this.

// pos, rpos, find, rfind, etc...
}

void
testString::testCmpDefault()
{
    string left, right;
    /* two default strings are equal */
    CPPUNIT_ASSERT(!left.compare(right));
    CPPUNIT_ASSERT(!left.compare(NULL));
    CPPUNIT_ASSERT(!left.compare(NULL, 1));
}

void
testString::testCmpEmptyString()
{
    string left("");
    string right;
    /* an empty string ("") is equal to a default string */
    CPPUNIT_ASSERT(!left.compare(right));
    CPPUNIT_ASSERT(!left.compare(NULL));
    CPPUNIT_ASSERT(!left.compare(NULL, 1));
    /* reverse the order to catch corners */
    CPPUNIT_ASSERT(!right.compare(left));
    CPPUNIT_ASSERT(!right.compare(""));
    CPPUNIT_ASSERT(!right.compare("", 1));
}

void
testString::testCmpNotEmptyDefault()
{
    string left("foo");
    string right;
    /* empty string sorts before everything */
    CPPUNIT_ASSERT(left.compare(right) > 0);
    CPPUNIT_ASSERT(left.compare(NULL) > 0);
    CPPUNIT_ASSERT(left.compare(NULL, 1) > 0);
    /* reverse for symmetry tests */
    CPPUNIT_ASSERT(right.compare(left) < 0);
    CPPUNIT_ASSERT(right.compare("foo") < 0);
    CPPUNIT_ASSERT(right.compare("foo", 1) < 0);
}
