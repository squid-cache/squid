#include "squid.h"

#include "testTokenizer.h"
#include "CharacterSet.h"
#include "Tokenizer.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testTokenizer );

SBuf text("GET http://resource.com/path HTTP/1.1\r\n"
    "Host: resource.com\r\n"
    "Cookie: laijkpk3422r j1noin \r\n"
    "\r\n");
const Parser::CharacterSet alpha("alpha","abcdefghijklmnopqrstuvwxzABCDEFGHIJKLMNOPQRSTUVWXYZ");
const Parser::CharacterSet whitespace("whitespace"," ");
const Parser::CharacterSet crlf("crlf","\r\n");
const Parser::CharacterSet tab("tab","\t");

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
    Parser::CharacterSet all(alpha);
    // TODO: finish from here. But += is buggy
//    all += whitespace;
//    all += crlf;

}

void
testTokenizer::testTokenizerSkip()
{

}

void
testTokenizer::testTokenizerToken()
{

}

void
testTokenizer::testCharacterSet()
{

}
