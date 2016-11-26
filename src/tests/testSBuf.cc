/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "sbuf/Algorithms.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"
#include "tests/SBufFindTest.h"
#include "tests/testSBuf.h"
#include "unitTestMain.h"

#include <iostream>
#include <stdexcept>
#include <unordered_map>

CPPUNIT_TEST_SUITE_REGISTRATION( testSBuf );

/* let this test link sanely */
#include "event.h"
#include "MemObject.h"
void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{}
int64_t
MemObject::endOffset() const
{ return 0; }
/* end of stubs */

// test string
static char fox[]="The quick brown fox jumped over the lazy dog";
static char fox1[]="The quick brown fox ";
static char fox2[]="jumped over the lazy dog";

// TEST: globals variables (default/empty and with contents) are
//  created outside and before any unit tests and memory subsystem
//  initialization. Check for correct constructor operation.
SBuf empty_sbuf;
SBuf literal("The quick brown fox jumped over the lazy dog");

void
testSBuf::testSBufConstructDestruct()
{
    /* NOTE: Do not initialize memory here because we need
     * to test correct operation before and after Mem::Init
     */

    // XXX: partial demo below of how to do constructor unit-test. use scope to ensure each test
    // is working on local-scope variables constructed fresh for the test, and destructed when
    // scope exists. use nested scopes to test destructor affects on copied data (MemBlob etc)

    // TEST: default constructor (implicit destructor non-crash test)
    //  test accessors on empty SBuf.
    {
        SBuf s1;
        CPPUNIT_ASSERT_EQUAL(0U,s1.length());
        CPPUNIT_ASSERT_EQUAL(SBuf(""),s1);
        CPPUNIT_ASSERT_EQUAL(empty_sbuf,s1);
        CPPUNIT_ASSERT_EQUAL(0,strcmp("",s1.c_str()));
    }

    // TEST: copy-construct NULL string (implicit destructor non-crash test)
    {
        SBuf s1(NULL);
        CPPUNIT_ASSERT_EQUAL(0U,s1.length());
        CPPUNIT_ASSERT_EQUAL(SBuf(""),s1);
        CPPUNIT_ASSERT_EQUAL(empty_sbuf,s1);
        CPPUNIT_ASSERT_EQUAL(0,strcmp("",s1.c_str()));
    }

    // TEST: copy-construct empty string (implicit destructor non-crash test)
    {
        SBuf s1("");
        CPPUNIT_ASSERT_EQUAL(0U,s1.length());
        CPPUNIT_ASSERT_EQUAL(SBuf(""),s1);
        CPPUNIT_ASSERT_EQUAL(empty_sbuf,s1);
        CPPUNIT_ASSERT_EQUAL(0,strcmp("",s1.c_str()));
    }

    // TEST: copy-construct from a SBuf
    {
        SBuf s1(empty_sbuf);
        CPPUNIT_ASSERT_EQUAL(0U,s1.length());
        CPPUNIT_ASSERT_EQUAL(SBuf(""),s1);
        CPPUNIT_ASSERT_EQUAL(empty_sbuf,s1);
        CPPUNIT_ASSERT_EQUAL(0,strcmp("",s1.c_str()));

        SBuf s5(literal);
        CPPUNIT_ASSERT_EQUAL(literal,s5);
        SBuf s6(fox);
        CPPUNIT_ASSERT_EQUAL(literal,s6);
        // XXX: other state checks. expected result of calling any state accessor on s4 ?
    }

    // TEST: check that COW doesn't happen upon copy-construction
    {
        SBuf s1(empty_sbuf), s2(s1);
        CPPUNIT_ASSERT_EQUAL(s1.rawContent(), s2.rawContent());
        SBuf s3(literal), s4(literal);
        CPPUNIT_ASSERT_EQUAL(s3.rawContent(), s4.rawContent());
    }

    // TEST: sub-string copy
    {
        SBuf s1=SBuf(fox+4), s2(fox);
        SBuf s3=s2.substr(4,s2.length()); //n is out-of-bounds
        CPPUNIT_ASSERT_EQUAL(s1,s3);
        SBuf s4=SBuf(fox,4);
        s3=s2.substr(0,4);
        CPPUNIT_ASSERT_EQUAL(s4,s3);
    }

    // TEST: go via std::string adapter.
    {
        std::string str(fox);
        SBuf s1(str);
        CPPUNIT_ASSERT_EQUAL(literal,s1);
    }
}

void
testSBuf::testSBufConstructDestructAfterMemInit()
{
    Mem::Init();
    testSBufConstructDestruct();
}

void
testSBuf::testEqualityTest()
{
    SBuf s1(fox),s2(fox);
    CPPUNIT_ASSERT_EQUAL(s1,s1); //self-equality
    CPPUNIT_ASSERT_EQUAL(s1,s2); //same contents
    s2.assign("The quick brown fox jumped over the lazy doe");
    CPPUNIT_ASSERT(!(s1 == s2)); //same length, different contents
    s2.assign("foo");
    CPPUNIT_ASSERT(!(s1 == s2)); //different length and contents
    CPPUNIT_ASSERT(s1 != s2);    //while we're ready, let's test inequality
    s2.clear();
    CPPUNIT_ASSERT(!(s1 == s2)); //null and not-null
    CPPUNIT_ASSERT(s1 != s2);    //while we're ready, let's test inequality
    s1.clear();
    CPPUNIT_ASSERT_EQUAL(s1,s2); //null and null
}

void
testSBuf::testAppendSBuf()
{
    const SBuf appendix(fox1);
    const char * const rawAppendix = appendix.rawContent();

    // check whether the optimization that prevents copying when append()ing to
    // default-constructed SBuf actually works
    SBuf s0;
    s0.append(appendix);
    CPPUNIT_ASSERT_EQUAL(s0.rawContent(), appendix.rawContent());
    CPPUNIT_ASSERT_EQUAL(s0, appendix);

    // paranoid: check that the above code can actually detect copies
    SBuf s1(fox1);
    s1.append(appendix);
    CPPUNIT_ASSERT(s1.rawContent() != appendix.rawContent());
    CPPUNIT_ASSERT(s1 != appendix);
    CPPUNIT_ASSERT_EQUAL(rawAppendix, appendix.rawContent());
}

void
testSBuf::testPrintf()
{
    SBuf s1,s2;
    s1.Printf("%s:%d:%03.3f","fox",10,12345.67);
    s2.assign("fox:10:12345.670");
    CPPUNIT_ASSERT_EQUAL(s1,s2);
}

void
testSBuf::testAppendCString()
{
    SBuf s1(fox1);
    s1.append(fox2);
    CPPUNIT_ASSERT_EQUAL(s1,literal);
}

void
testSBuf::testAppendStdString()
{
    const char *alphabet="abcdefghijklmnopqrstuvwxyz";
    {
        SBuf alpha(alphabet), s;
        s.append(alphabet,5).append(alphabet+5);
        CPPUNIT_ASSERT_EQUAL(alpha,s);
    }
    {
        SBuf s;
        std::string control;
        s.append(alphabet,5).append("\0",1).append(alphabet+6,SBuf::npos);
        control.append(alphabet,5).append(1,'\0').append(alphabet,6,std::string::npos);
        SBuf scontrol(control); // we need this to test the equality. sigh.
        CPPUNIT_ASSERT_EQUAL(scontrol,s);
    }
    {
        const char *alphazero="abcdefghijk\0mnopqrstuvwxyz";
        SBuf s(alphazero,26);
        std::string str(alphazero,26);
        CPPUNIT_ASSERT_EQUAL(0,memcmp(str.data(),s.rawContent(),26));
    }
}

void
testSBuf::testAppendf()
{
    SBuf s1,s2;
    s1.appendf("%s:%d:%03.2f",fox,1234,1234.56);
    s2.assign("The quick brown fox jumped over the lazy dog:1234:1234.56");
    CPPUNIT_ASSERT_EQUAL(s2,s1);
}

void
testSBuf::testDumpStats()
{
    SBuf::GetStats().dump(std::cout);
    MemBlob::GetStats().dump(std::cout);
    std::cout << "sizeof(SBuf): " << sizeof(SBuf) << std::endl;
    std::cout << "sizeof(MemBlob): " << sizeof(MemBlob) << std::endl;
}

void
testSBuf::testSubscriptOp()
{
    SBuf chg(literal);
    CPPUNIT_ASSERT_EQUAL(chg[5],'u');
    chg.setAt(5,'e');
    CPPUNIT_ASSERT_EQUAL(literal[5],'u');
    CPPUNIT_ASSERT_EQUAL(chg[5],'e');
}

// note: can't use cppunit's CPPUNIT_TEST_EXCEPTION because TextException asserts, and
// so the test can't be properly completed.
void
testSBuf::testSubscriptOpFail()
{
    char c;
    c=literal.at(literal.length()); //out of bounds by 1
    //notreached
    std::cout << c << std::endl;
}

static int sign(int v)
{
    if (v < 0)
        return -1;
    if (v>0)
        return 1;
    return 0;
}

static void
testComparisonStdFull(const char *left, const char *right)
{
    if (sign(strcmp(left, right)) != sign(SBuf(left).cmp(SBuf(right))))
        std::cerr << std::endl << " cmp(SBuf) npos " << left << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strcmp(left, right)), sign(SBuf(left).cmp(SBuf(right))));

    if (sign(strcmp(left, right)) != sign(SBuf(left).cmp(right)))
        std::cerr << std::endl << " cmp(char*) npos " << left << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strcmp(left, right)), sign(SBuf(left).cmp(right)));

    if (sign(strcasecmp(left, right)) != sign(SBuf(left).caseCmp(SBuf(right))))
        std::cerr << std::endl << " caseCmp(SBuf) npos " << left << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strcasecmp(left, right)), sign(SBuf(left).caseCmp(SBuf(right))));

    if (sign(strcasecmp(left, right)) != sign(SBuf(left).caseCmp(right)))
        std::cerr << std::endl << " caseCmp(char*) npos " << left << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strcasecmp(left, right)), sign(SBuf(left).caseCmp(right)));
}

static void
testComparisonStdN(const char *left, const char *right, const size_t n)
{
    if (sign(strncmp(left, right, n)) != sign(SBuf(left).cmp(SBuf(right), n)))
        std::cerr << std::endl << " cmp(SBuf) " << n << ' ' << left << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strncmp(left, right, n)), sign(SBuf(left).cmp(SBuf(right), n)));

    if (sign(strncmp(left, right, n)) != sign(SBuf(left).cmp(right, n)))
        std::cerr << std::endl << " cmp(char*) " << n << ' ' << SBuf(left) << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strncmp(left, right, n)), sign(SBuf(left).cmp(right, n)));

    if (sign(strncasecmp(left, right, n)) != sign(SBuf(left).caseCmp(SBuf(right), n)))
        std::cerr << std::endl << " caseCmp(SBuf) " << n << ' ' << left << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strncasecmp(left, right, n)), sign(SBuf(left).caseCmp(SBuf(right), n)));

    if (sign(strncasecmp(left, right, n)) != sign(SBuf(left).caseCmp(right, n)))
        std::cerr << std::endl << " caseCmp(char*) " << n << ' ' << SBuf(left) << " ?= " << right << std::endl;
    CPPUNIT_ASSERT_EQUAL(sign(strncasecmp(left, right, n)), sign(SBuf(left).caseCmp(right, n)));
}

static void
testComparisonStdOneWay(const char *left, const char *right)
{
    testComparisonStdFull(left, right);
    const size_t maxN = 2 + min(strlen(left), strlen(right));
    for (size_t n = 0; n <= maxN; ++n) {
        testComparisonStdN(left, right, n);
    }
}

static void
testComparisonStd(const char *s1, const char *s2)
{
    testComparisonStdOneWay(s1, s2);
    testComparisonStdOneWay(s2, s1);
}

void
testSBuf::testComparisons()
{
    //same length
    SBuf s1("foo"),s2("foe");
    CPPUNIT_ASSERT(s1.cmp(s2)>0);
    CPPUNIT_ASSERT(s1.caseCmp(s2)>0);
    CPPUNIT_ASSERT(s2.cmp(s1)<0);
    CPPUNIT_ASSERT_EQUAL(0,s1.cmp(s2,2));
    CPPUNIT_ASSERT_EQUAL(0,s1.caseCmp(s2,2));
    CPPUNIT_ASSERT(s1 > s2);
    CPPUNIT_ASSERT(s2 < s1);
    CPPUNIT_ASSERT_EQUAL(sign(s1.cmp(s2)),sign(strcmp(s1.c_str(),s2.c_str())));
    //different lengths
    s1.assign("foo");
    s2.assign("foof");
    CPPUNIT_ASSERT(s1.cmp(s2)<0);
    CPPUNIT_ASSERT_EQUAL(sign(s1.cmp(s2)),sign(strcmp(s1.c_str(),s2.c_str())));
    CPPUNIT_ASSERT(s1 < s2);
    // specifying the max-length and overhanging size
    CPPUNIT_ASSERT_EQUAL(1,SBuf("foolong").caseCmp(SBuf("foo"), 5));
    // case-insensive comaprison
    s1 = "foo";
    s2 = "fOo";
    CPPUNIT_ASSERT_EQUAL(0,s1.caseCmp(s2));
    CPPUNIT_ASSERT_EQUAL(0,s1.caseCmp(s2,2));
    // \0-clenliness test
    s1.assign("f\0oo",4);
    s2.assign("f\0Oo",4);
    CPPUNIT_ASSERT(s1.cmp(s2) > 0);
    CPPUNIT_ASSERT_EQUAL(0,s1.caseCmp(s2));
    CPPUNIT_ASSERT_EQUAL(0,s1.caseCmp(s2,3));
    CPPUNIT_ASSERT_EQUAL(0,s1.caseCmp(s2,2));
    CPPUNIT_ASSERT_EQUAL(0,s1.cmp(s2,2));

    testComparisonStd("foo", "fooz");
    testComparisonStd("foo", "foo");
    testComparisonStd("foo", "f");
    testComparisonStd("foo", "bar");

    testComparisonStd("foo", "FOOZ");
    testComparisonStd("foo", "FOO");
    testComparisonStd("foo", "F");

    testComparisonStdOneWay("", "");

    // rare case C-string input matching SBuf with N>strlen(s)
    {
        char *right = xstrdup("foo34567890123456789012345678");
        SBuf left("fooZYXWVUTSRQPONMLKJIHGFEDCBA");
        // is 3 bytes in length. NEVER more.
        right[3] = '\0';
        left.setAt(3, '\0');

        // pick another spot to truncate at if something goes horribly wrong.
        right[14] = '\0';
        left.setAt(14, '\0');

        const SBuf::size_type maxN = 20 + min(left.length(), static_cast<SBuf::size_type>(strlen(right)));
        for (SBuf::size_type n = 0; n <= maxN; ++n) {
            if (sign(strncmp(left.rawContent(), right, n)) != sign(left.cmp(right, n)) )
                std::cerr << std::endl << " cmp(char*) " << n << ' ' << left << " ?= " << right;
            CPPUNIT_ASSERT_EQUAL(sign(strncmp(left.rawContent(), right, n)), sign(left.cmp(right, n)));
            if (sign(strncasecmp(left.rawContent(), right, n)) != sign(left.caseCmp(right, n)))
                std::cerr << std::endl << " caseCmp(char*) " << n << ' ' << left << " ?= " << right;
            CPPUNIT_ASSERT_EQUAL(sign(strncasecmp(left.rawContent(), right, n)), sign(left.caseCmp(right, n)));
        }
        xfree(right);
    }
}

void
testSBuf::testConsume()
{
    SBuf s1(literal),s2,s3;
    s2=s1.consume(4);
    s3.assign("The ");
    CPPUNIT_ASSERT_EQUAL(s2,s3);
    s3.assign("quick brown fox jumped over the lazy dog");
    CPPUNIT_ASSERT_EQUAL(s1,s3);
    s1.consume(40);
    CPPUNIT_ASSERT_EQUAL(s1,SBuf());
}

void
testSBuf::testRawContent()
{
    SBuf s1(literal);
    SBuf s2(s1);
    s2.append("foo");
    const char *foo;
    foo = s1.rawContent();
    CPPUNIT_ASSERT_EQUAL(0,strncmp(fox,foo,s1.length()));
    foo = s1.c_str();
    CPPUNIT_ASSERT(!strcmp(fox,foo));
}

void
testSBuf::testRawSpace()
{
    SBuf s1(literal);
    SBuf s2(fox1);
    SBuf::size_type sz=s2.length();
    char *rb=s2.rawSpace(strlen(fox2)+1);
    strcpy(rb,fox2);
    s2.forceSize(sz+strlen(fox2));
    CPPUNIT_ASSERT_EQUAL(s1,s2);
}

void
testSBuf::testChop()
{
    SBuf s1(literal),s2;
    s1.chop(4,5);
    s2.assign("quick");
    CPPUNIT_ASSERT_EQUAL(s1,s2);
    s1=literal;
    s2.clear();
    s1.chop(5,0);
    CPPUNIT_ASSERT_EQUAL(s1,s2);
    const char *alphabet="abcdefghijklmnopqrstuvwxyz";
    SBuf a(alphabet);
    std::string s(alphabet); // TODO
    {   //regular chopping
        SBuf b(a);
        b.chop(3,3);
        SBuf ref("def");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // chop at end
        SBuf b(a);
        b.chop(b.length()-3);
        SBuf ref("xyz");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // chop at beginning
        SBuf b(a);
        b.chop(0,3);
        SBuf ref("abc");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // chop to zero length
        SBuf b(a);
        b.chop(5,0);
        SBuf ref("");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // chop beyond end (at npos)
        SBuf b(a);
        b.chop(SBuf::npos,4);
        SBuf ref("");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // chop beyond end
        SBuf b(a);
        b.chop(b.length()+2,4);
        SBuf ref("");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // null-chop
        SBuf b(a);
        b.chop(0,b.length());
        SBuf ref(a);
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
    {   // overflow chopped area
        SBuf b(a);
        b.chop(b.length()-3,b.length());
        SBuf ref("xyz");
        CPPUNIT_ASSERT_EQUAL(ref,b);
    }
}

void
testSBuf::testChomp()
{
    SBuf s1("complete string");
    SBuf s2(s1);
    s2.trim(SBuf(" ,"));
    CPPUNIT_ASSERT_EQUAL(s1,s2);
    s2.assign(" complete string ,");
    s2.trim(SBuf(" ,"));
    CPPUNIT_ASSERT_EQUAL(s1,s2);
    s1.assign(", complete string ,");
    s2=s1;
    s2.trim(SBuf(" "));
    CPPUNIT_ASSERT_EQUAL(s1,s2);
}

// inspired by SBufFindTest; to be expanded.
class SBufSubstrAutoTest
{
    SBuf fullString, sb;
    std::string fullReference, str;
public:
    void performEqualityTest() {
        SBuf ref(str);
        CPPUNIT_ASSERT_EQUAL(ref,sb);
    }
    SBufSubstrAutoTest() : fullString(fox), fullReference(fox) {
        for (int offset=fullString.length()-1; offset >= 0; --offset ) {
            for (int length=fullString.length()-1-offset; length >= 0; --length) {
                sb=fullString.substr(offset,length);
                str=fullReference.substr(offset,length);
                performEqualityTest();
            }
        }
    }
};

void
testSBuf::testSubstr()
{
    SBuf s1(literal),s2,s3;
    s2=s1.substr(4,5);
    s3.assign("quick");
    CPPUNIT_ASSERT_EQUAL(s2,s3);
    s1.chop(4,5);
    CPPUNIT_ASSERT_EQUAL(s1,s2);
    SBufSubstrAutoTest sat; // work done in the constructor
}

void
testSBuf::testFindChar()
{
    const char *alphabet="abcdefghijklmnopqrstuvwxyz";
    SBuf s1(alphabet);
    SBuf::size_type idx;
    SBuf::size_type nposResult=SBuf::npos;

    // FORWARD SEARCH
    // needle in haystack
    idx=s1.find('d');
    CPPUNIT_ASSERT_EQUAL(3U,idx);
    CPPUNIT_ASSERT_EQUAL('d',s1[idx]);

    // needle not present in haystack
    idx=s1.find(' '); //fails
    CPPUNIT_ASSERT_EQUAL(nposResult,idx);

    // search in portion
    idx=s1.find('e',3U);
    CPPUNIT_ASSERT_EQUAL(4U,idx);

    // char not in searched portion
    idx=s1.find('e',5U);
    CPPUNIT_ASSERT_EQUAL(nposResult,idx);

    // invalid start position
    idx=s1.find('d',SBuf::npos);
    CPPUNIT_ASSERT_EQUAL(nposResult,idx);

    // search outside of haystack
    idx=s1.find('d',s1.length()+1);
    CPPUNIT_ASSERT_EQUAL(nposResult,idx);

    // REVERSE SEARCH
    // needle in haystack
    idx=s1.rfind('d');
    CPPUNIT_ASSERT_EQUAL(3U, idx);
    CPPUNIT_ASSERT_EQUAL('d', s1[idx]);

    // needle not present in haystack
    idx=s1.rfind(' '); //fails
    CPPUNIT_ASSERT_EQUAL(nposResult,idx);

    // search in portion
    idx=s1.rfind('e',5);
    CPPUNIT_ASSERT_EQUAL(4U,idx);

    // char not in searched portion
    idx=s1.rfind('e',3);
    CPPUNIT_ASSERT_EQUAL(nposResult,idx);

    // overlong haystack specification
    idx=s1.rfind('d',s1.length()+1);
    CPPUNIT_ASSERT_EQUAL(3U,idx);
}

void
testSBuf::testFindSBuf()
{
    const char *alphabet="abcdefghijklmnopqrstuvwxyz";
    SBuf haystack(alphabet);
    SBuf::size_type idx;
    SBuf::size_type nposResult=SBuf::npos;

    // FORWARD search
    // needle in haystack
    idx = haystack.find(SBuf("def"));
    CPPUNIT_ASSERT_EQUAL(3U,idx);

    idx = haystack.find(SBuf("xyz"));
    CPPUNIT_ASSERT_EQUAL(23U,idx);

    // needle not in haystack, no initial char match
    idx = haystack.find(SBuf(" eq"));
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // needle not in haystack, initial sequence match
    idx = haystack.find(SBuf("deg"));
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // needle past end of haystack
    idx = haystack.find(SBuf("xyz1"));
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // search in portion: needle not in searched part
    idx = haystack.find(SBuf("def"),7);
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // search in portion: overhang
    idx = haystack.find(SBuf("def"),4);
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // invalid start position
    idx = haystack.find(SBuf("def"),SBuf::npos);
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // needle bigger than haystack
    idx = SBuf("def").find(haystack);
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // search in a double-matching haystack
    {
        SBuf h2=haystack;
        h2.append(haystack);

        idx = h2.find(SBuf("def"));
        CPPUNIT_ASSERT_EQUAL(3U,idx);

        idx = h2.find(SBuf("xyzab"));
        CPPUNIT_ASSERT_EQUAL(23U,idx);
    }

    // REVERSE search
    // needle in haystack
    idx = haystack.rfind(SBuf("def"));
    CPPUNIT_ASSERT_EQUAL(3U,idx);

    idx = haystack.rfind(SBuf("xyz"));
    CPPUNIT_ASSERT_EQUAL(23U,idx);

    // needle not in haystack, no initial char match
    idx = haystack.rfind(SBuf(" eq"));
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // needle not in haystack, initial sequence match
    idx = haystack.rfind(SBuf("deg"));
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // needle past end of haystack
    idx = haystack.rfind(SBuf("xyz1"));
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // search in portion: needle in searched part
    idx = haystack.rfind(SBuf("def"),7);
    CPPUNIT_ASSERT_EQUAL(3U, idx);

    // search in portion: needle not in searched part
    idx = haystack.rfind(SBuf("mno"),3);
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // search in portion: overhang
    idx = haystack.rfind(SBuf("def"),4);
    CPPUNIT_ASSERT_EQUAL(3U, idx);

    // npos start position
    idx = haystack.rfind(SBuf("def"),SBuf::npos);
    CPPUNIT_ASSERT_EQUAL(3U, idx);

    // needle bigger than haystack
    idx = SBuf("def").rfind(haystack);
    CPPUNIT_ASSERT_EQUAL(nposResult, idx);

    // search in a double-matching haystack
    {
        SBuf h2=haystack;
        h2.append(haystack);

        idx = h2.rfind(SBuf("def"));
        CPPUNIT_ASSERT_EQUAL(29U,idx);

        idx = h2.find(SBuf("xyzab"));
        CPPUNIT_ASSERT_EQUAL(23U,idx);
    }
}

void
testSBuf::testRFindChar()
{
    SBuf s1(literal);
    SBuf::size_type idx;
    idx=s1.rfind(' ');
    CPPUNIT_ASSERT_EQUAL(40U,idx);
    CPPUNIT_ASSERT_EQUAL(' ',s1[idx]);
}

void
testSBuf::testRFindSBuf()
{
    SBuf haystack(literal),afox("fox");
    SBuf goobar("goobar");
    SBuf::size_type idx;

    // corner case: search for a zero-length SBuf
    idx=haystack.rfind(SBuf(""));
    CPPUNIT_ASSERT_EQUAL(haystack.length(),idx);

    // corner case: search for a needle longer than the haystack
    idx=afox.rfind(SBuf("     "));
    CPPUNIT_ASSERT_EQUAL(SBuf::npos,idx);

    idx=haystack.rfind(SBuf("fox"));
    CPPUNIT_ASSERT_EQUAL(16U,idx);

    // needle not found, no match for first char
    idx=goobar.rfind(SBuf("foo"));
    CPPUNIT_ASSERT_EQUAL(SBuf::npos,idx);

    // needle not found, match for first char but no match for SBuf
    idx=haystack.rfind(SBuf("foe"));
    CPPUNIT_ASSERT_EQUAL(SBuf::npos,idx);

    SBuf g("g"); //match at the last char
    idx=haystack.rfind(g);
    CPPUNIT_ASSERT_EQUAL(43U,idx);
    CPPUNIT_ASSERT_EQUAL('g',haystack[idx]);

    idx=haystack.rfind(SBuf("The"));
    CPPUNIT_ASSERT_EQUAL(0U,idx);

    haystack.append("The");
    idx=haystack.rfind(SBuf("The"));
    CPPUNIT_ASSERT_EQUAL(44U,idx);

    //partial match
    haystack="The quick brown fox";
    SBuf needle("foxy lady");
    idx=haystack.rfind(needle);
    CPPUNIT_ASSERT_EQUAL(SBuf::npos,idx);
}

void
testSBuf::testSBufLength()
{
    SBuf s(fox);
    CPPUNIT_ASSERT_EQUAL(strlen(fox),(size_t)s.length());
}

void
testSBuf::testCopy()
{
    char buf[40]; //shorter than literal()
    SBuf s(fox1),s2;
    CPPUNIT_ASSERT_EQUAL(s.length(),s.copy(buf,40));
    CPPUNIT_ASSERT_EQUAL(0,strncmp(s.rawContent(),buf,s.length()));
    s=literal;
    CPPUNIT_ASSERT_EQUAL(40U,s.copy(buf,40));
    s2.assign(buf,40);
    s.chop(0,40);
    CPPUNIT_ASSERT_EQUAL(s2,s);
}

void
testSBuf::testStringOps()
{
    SBuf sng(ToLower(literal)),
         ref("the quick brown fox jumped over the lazy dog");
    CPPUNIT_ASSERT_EQUAL(ref,sng);
    sng=literal;
    CPPUNIT_ASSERT_EQUAL(0,sng.compare(ref,caseInsensitive));
    // max-size comparison
    CPPUNIT_ASSERT_EQUAL(0,ref.compare(SBuf("THE"),caseInsensitive,3));
    CPPUNIT_ASSERT_EQUAL(1,ref.compare(SBuf("THE"),caseInsensitive,6));
    CPPUNIT_ASSERT_EQUAL(0,SBuf("the").compare(SBuf("THE"),caseInsensitive,6));
}

void
testSBuf::testGrow()
{
    SBuf t;
    t.assign("foo");
    const char *ref=t.rawContent();
    t.reserveCapacity(10240);
    const char *match=t.rawContent();
    CPPUNIT_ASSERT(match!=ref);
    ref=match;
    t.append(literal).append(literal).append(literal).append(literal).append(literal);
    t.append(t).append(t).append(t).append(t).append(t);
    CPPUNIT_ASSERT_EQUAL(ref,match);
}

void
testSBuf::testReserve()
{
    SBufReservationRequirements requirements;
    // use unusual numbers to ensure we dont hit a lucky boundary situation
    requirements.minSpace = 10;
    requirements.idealSpace = 82;
    requirements.maxCapacity = 259;
    requirements.allowShared = true;

    // for each possible starting buffer length within the capacity
    for (SBuf::size_type startLength = 0; startLength <= requirements.maxCapacity; ++startLength) {
        std::cerr << ".";
        SBuf b;
        b.reserveCapacity(startLength);
        CPPUNIT_ASSERT_EQUAL(b.length(), static_cast<unsigned int>(0));
        CPPUNIT_ASSERT_EQUAL(b.spaceSize(), startLength);

        // check that it never grows outside capacity.
        // do 5 excess cycles to check that.
        for (SBuf::size_type filled = 0; filled < requirements.maxCapacity +5; ++filled) {
            CPPUNIT_ASSERT_EQUAL(b.length(), min(filled, requirements.maxCapacity));
            auto x = b.reserve(requirements);
            // the amount of space advertized must not cause users to exceed capacity
            CPPUNIT_ASSERT(x <= requirements.maxCapacity - filled);
            CPPUNIT_ASSERT(b.spaceSize() <= requirements.maxCapacity - filled);
            // the total size of buffer must not cause users to exceed capacity
            CPPUNIT_ASSERT(b.length() + b.spaceSize() <= requirements.maxCapacity);
            if (x > 0)
                b.append('X');
        }
    }

    // the minimal space requirement should overwrite idealSpace preferences
    requirements.minSpace = 10;
    for (const int delta: {-1,0,+1}) {
        requirements.idealSpace = requirements.minSpace + delta;
        SBuf buffer;
        buffer.reserve(requirements);
        CPPUNIT_ASSERT(buffer.spaceSize() >= requirements.minSpace);
    }
}

void
testSBuf::testStartsWith()
{
    static SBuf casebuf("THE QUICK");
    CPPUNIT_ASSERT(literal.startsWith(SBuf(fox1)));
    CPPUNIT_ASSERT(!SBuf("The quick brown").startsWith(SBuf(fox1))); //too short
    CPPUNIT_ASSERT(!literal.startsWith(SBuf(fox2))); //different contents

    // case-insensitive checks
    CPPUNIT_ASSERT(literal.startsWith(casebuf,caseInsensitive));
    casebuf=ToUpper(SBuf(fox1));
    CPPUNIT_ASSERT(literal.startsWith(casebuf,caseInsensitive));
    CPPUNIT_ASSERT(literal.startsWith(SBuf(fox1),caseInsensitive));
    casebuf = "tha quick";
    CPPUNIT_ASSERT_EQUAL(false,literal.startsWith(casebuf,caseInsensitive));
}

void
testSBuf::testSBufStream()
{
    SBuf b("const.string, int 10 and a float 10.5");
    SBufStream ss;
    ss << "const.string, int " << 10 << " and a float " << 10.5;
    SBuf o=ss.buf();
    CPPUNIT_ASSERT_EQUAL(b,o);
    ss.clearBuf();
    o=ss.buf();
    CPPUNIT_ASSERT_EQUAL(SBuf(),o);
    SBuf f1(fox1);
    SBufStream ss2(f1);
    ss2 << fox2;
    CPPUNIT_ASSERT_EQUAL(ss2.buf(),literal);
    CPPUNIT_ASSERT_EQUAL(f1,SBuf(fox1));
}

void
testSBuf::testFindFirstOf()
{
    SBuf haystack(literal);
    SBuf::size_type idx;

    // not found
    idx=haystack.findFirstOf(CharacterSet("t1","ADHRWYP"));
    CPPUNIT_ASSERT_EQUAL(SBuf::npos,idx);

    // found at beginning
    idx=haystack.findFirstOf(CharacterSet("t2","THANDF"));
    CPPUNIT_ASSERT_EQUAL(0U,idx);

    //found at end of haystack
    idx=haystack.findFirstOf(CharacterSet("t3","QWERYVg"));
    CPPUNIT_ASSERT_EQUAL(haystack.length()-1,idx);

    //found in the middle of haystack
    idx=haystack.findFirstOf(CharacterSet("t4","QWERqYV"));
    CPPUNIT_ASSERT_EQUAL(4U,idx);
}

void
testSBuf::testFindFirstNotOf()
{
    SBuf haystack(literal);
    SBuf::size_type idx;

    // all chars from the set
    idx=haystack.findFirstNotOf(CharacterSet("t1",literal.c_str()));
    CPPUNIT_ASSERT_EQUAL(SBuf::npos,idx);

    // found at beginning
    idx=haystack.findFirstNotOf(CharacterSet("t2","a"));
    CPPUNIT_ASSERT_EQUAL(0U,idx);

    //found at end of haystack
    idx=haystack.findFirstNotOf(CharacterSet("t3",literal.substr(0,literal.length()-1).c_str()));
    CPPUNIT_ASSERT_EQUAL(haystack.length()-1,idx);

    //found in the middle of haystack
    idx=haystack.findFirstNotOf(CharacterSet("t4","The"));
    CPPUNIT_ASSERT_EQUAL(3U,idx);
}

void
testSBuf::testAutoFind()
{
    SBufFindTest test;
    test.run();
}

void
testSBuf::testStdStringOps()
{
    const char *alphabet="abcdefghijklmnopqrstuvwxyz";
    std::string astr(alphabet);
    SBuf sb(alphabet);
    CPPUNIT_ASSERT_EQUAL(astr,sb.toStdString());
}

void
testSBuf::testIterators()
{
    SBuf text("foo"), text2("foo");
    CPPUNIT_ASSERT(text.begin() == text.begin());
    CPPUNIT_ASSERT(text.begin() != text.end());
    CPPUNIT_ASSERT(text.begin() != text2.begin());
    {
        auto i = text.begin();
        auto e = text.end();
        CPPUNIT_ASSERT_EQUAL('f', *i);
        CPPUNIT_ASSERT(i != e);
        ++i;
        CPPUNIT_ASSERT_EQUAL('o', *i);
        CPPUNIT_ASSERT(i != e);
        ++i;
        CPPUNIT_ASSERT_EQUAL('o', *i);
        CPPUNIT_ASSERT(i != e);
        ++i;
        CPPUNIT_ASSERT(i == e);
    }
    {
        auto i = text.rbegin();
        auto e = text.rend();
        CPPUNIT_ASSERT_EQUAL('o', *i);
        CPPUNIT_ASSERT(i != e);
        ++i;
        CPPUNIT_ASSERT_EQUAL('o', *i);
        CPPUNIT_ASSERT(i != e);
        ++i;
        CPPUNIT_ASSERT_EQUAL('f', *i);
        CPPUNIT_ASSERT(i != e);
        ++i;
        CPPUNIT_ASSERT(i == e);
    }
}

void
testSBuf::testSBufHash()
{
    // same SBuf must have same hash
    auto hasher=std::hash<SBuf>();
    CPPUNIT_ASSERT_EQUAL(hasher(literal),hasher(literal));

    // same content must have same hash
    CPPUNIT_ASSERT_EQUAL(hasher(literal),hasher(SBuf(fox)));
    CPPUNIT_ASSERT_EQUAL(hasher(SBuf(fox)),hasher(SBuf(fox)));

    //differen content should have different hash
    CPPUNIT_ASSERT(hasher(SBuf(fox)) != hasher(SBuf(fox1)));

    {
        std::unordered_map<SBuf, int> um;
        um[SBuf("one")] = 1;
        um[SBuf("two")] = 2;

        auto i = um.find(SBuf("one"));
        CPPUNIT_ASSERT(i != um.end());
        CPPUNIT_ASSERT(i->second == 1);

        i = um.find(SBuf("eleventy"));
        CPPUNIT_ASSERT(i == um.end());
    }
}

