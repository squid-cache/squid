#include "squid.h"
#include "base/CharacterSet.h"
#include "parser/Tokenizer.h"
#include "testTokenizer.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testTokenizer );

SBuf text("GET http://resource.com/path HTTP/1.1\r\n"
    "Host: resource.com\r\n"
    "Cookie: laijkpk3422r j1noin \r\n"
    "\r\n");
const CharacterSet alpha("alpha","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
const CharacterSet whitespace("whitespace"," \r\n");
const CharacterSet crlf("crlf","\r\n");
const CharacterSet tab("tab","\t");
const CharacterSet numbers("numbers","0123456789");

void
testTokenizer::testTokenizerPrefix()
{
    Parser::Tokenizer t(text);
    SBuf s;

    // successful prefix tokenization
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("GET"),s);
    CPPUNIT_ASSERT(t.prefix(s,whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf(" "),s);

    //no match (first char is not in the prefix set)
    CPPUNIT_ASSERT(!t.prefix(s,whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf(" "),s);

    // one more match to set S to something meaningful
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("http"),s);

    //no match (no characters from the character set in the prefix)
    CPPUNIT_ASSERT(!t.prefix(s,tab));
    CPPUNIT_ASSERT_EQUAL(SBuf("http"),s); //output SBuf left untouched

    // match until the end of the sample
    CharacterSet all(whitespace);
    all += alpha;
    all += crlf;
    all += numbers;
    all.add(':').add('.').add('/');
    CPPUNIT_ASSERT(t.prefix(s,all));
    CPPUNIT_ASSERT_EQUAL(SBuf(),t.remaining());
}

void
testTokenizer::testTokenizerSkip()
{
    Parser::Tokenizer t(text);
    SBuf s;

    // first scenario: patterns match
    // prep for test
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("GET"),s);

    // test skip testing character set
    CPPUNIT_ASSERT(t.skip(whitespace));
    // check that skip was right
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("http"),s);

    //check skip prefix
    CPPUNIT_ASSERT(t.skip(SBuf("://")));
    // verify
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("resource"),s);

    // no skip
    CPPUNIT_ASSERT(!t.skip(alpha));
    CPPUNIT_ASSERT(!t.skip(SBuf("://")));
    CPPUNIT_ASSERT(!t.skip('a'));

}

void
testTokenizer::testTokenizerToken()
{
    Parser::Tokenizer t(text);
    SBuf s;

    // first scenario: patterns match
    CPPUNIT_ASSERT(t.token(s,whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf("GET"),s);
    CPPUNIT_ASSERT(t.token(s,whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf("http://resource.com/path"),s);
    CPPUNIT_ASSERT(t.token(s,whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf("HTTP/1.1"),s);
    CPPUNIT_ASSERT(t.token(s,whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf("Host:"),s);

    SBuf s2(s);
    //no separator found
    CPPUNIT_ASSERT(!t.token(s,tab));
    CPPUNIT_ASSERT_EQUAL(s2,s); // check that the output parameter was untouched
}

void
testTokenizer::testCharacterSet()
{

}
