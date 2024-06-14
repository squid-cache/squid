/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "compat/cppunit.h"
#include "parser/Tokenizer.h"
#include "unitTestMain.h"

class TestTokenizer : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestTokenizer);
    CPPUNIT_TEST(testTokenizerPrefix);
    CPPUNIT_TEST(testTokenizerSuffix);
    CPPUNIT_TEST(testTokenizerSkip);
    CPPUNIT_TEST(testTokenizerToken);
    CPPUNIT_TEST(testTokenizerInt64);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testTokenizerPrefix();
    void testTokenizerSuffix();
    void testTokenizerSkip();
    void testTokenizerToken();
    void testTokenizerInt64();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestTokenizer);

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
TestTokenizer::testTokenizerPrefix()
{
    const SBuf canary("This text should not be changed.");

    Parser::Tokenizer t(text);
    SBuf s;

    CharacterSet all(whitespace);
    all += alpha;
    all += crlf;
    all += numbers;
    all.add(':').add('.').add('/');

    // an empty prefix should return false (the full output buffer case)
    s = canary;
    const SBuf before = t.remaining();
    CPPUNIT_ASSERT(!t.prefix(s, all, 0));
    // ... and a false return value means no parameter changes
    CPPUNIT_ASSERT_EQUAL(canary, s);
    // ... and a false return value means no input buffer changes
    CPPUNIT_ASSERT_EQUAL(before, t.remaining());

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
    CPPUNIT_ASSERT(t.prefix(s,all));
    CPPUNIT_ASSERT_EQUAL(SBuf(),t.remaining());

    // empty prefix should return false (the empty input buffer case)
    s = canary;
    CPPUNIT_ASSERT(!t.prefix(s, all));
    // ... and a false return value means no parameter changes
    CPPUNIT_ASSERT_EQUAL(canary, s);
}

void
TestTokenizer::testTokenizerSkip()
{
    Parser::Tokenizer t(text);
    SBuf s;

    // first scenario: patterns match
    // prep for test
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("GET"),s);

    // test skipping one character from a character set
    CPPUNIT_ASSERT(t.skipOne(whitespace));
    // check that skip was right
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("http"),s);

    //check skip prefix
    CPPUNIT_ASSERT(t.skip(SBuf("://")));
    // verify
    CPPUNIT_ASSERT(t.prefix(s,alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("resource"),s);

    // no skip
    CPPUNIT_ASSERT(!t.skipOne(alpha));
    CPPUNIT_ASSERT(!t.skip(SBuf("://")));
    CPPUNIT_ASSERT(!t.skip('a'));

    // test skipping all characters from a character set while looking at .com
    CPPUNIT_ASSERT(t.skip('.'));
    CPPUNIT_ASSERT_EQUAL(static_cast<SBuf::size_type>(3), t.skipAll(alpha));
    CPPUNIT_ASSERT(t.remaining().startsWith(SBuf("/path")));
}

void
TestTokenizer::testTokenizerToken()
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

}

void
TestTokenizer::testTokenizerSuffix()
{
    const SBuf canary("This text should not be changed.");

    Parser::Tokenizer t(text);
    SBuf s;

    CharacterSet all(whitespace);
    all += alpha;
    all += crlf;
    all += numbers;
    all.add(':').add('.').add('/');

    // an empty suffix should return false (the full output buffer case)
    s = canary;
    const SBuf before = t.remaining();
    CPPUNIT_ASSERT(!t.suffix(s, all, 0));
    // ... and a false return value means no parameter changes
    CPPUNIT_ASSERT_EQUAL(canary, s);
    // ... and a false return value means no input buffer changes
    CPPUNIT_ASSERT_EQUAL(before, t.remaining());

    // consume suffix until the last CRLF, including that last CRLF
    SBuf::size_type remaining = t.remaining().length();
    while (t.remaining().findLastOf(crlf) != SBuf::npos) {
        CPPUNIT_ASSERT(t.remaining().length() > 0);
        CPPUNIT_ASSERT(t.skipOneTrailing(all));
        // ensure steady progress
        CPPUNIT_ASSERT_EQUAL(remaining, t.remaining().length() + 1);
        --remaining;
    }

    // no match (last char is not in the suffix set)
    CPPUNIT_ASSERT(!t.suffix(s, crlf));
    CPPUNIT_ASSERT(!t.suffix(s, whitespace));

    // successful suffix tokenization
    CPPUNIT_ASSERT(t.suffix(s, numbers));
    CPPUNIT_ASSERT_EQUAL(SBuf("1"), s);
    CPPUNIT_ASSERT(t.skipSuffix(SBuf("1.")));
    CPPUNIT_ASSERT(t.skipSuffix(SBuf("/")));
    CPPUNIT_ASSERT(t.suffix(s, alpha));
    CPPUNIT_ASSERT_EQUAL(SBuf("HTTP"), s);
    CPPUNIT_ASSERT(t.suffix(s, whitespace));
    CPPUNIT_ASSERT_EQUAL(SBuf(" "), s);

    // match until the end of the sample
    CPPUNIT_ASSERT(t.suffix(s, all));
    CPPUNIT_ASSERT_EQUAL(SBuf(), t.remaining());

    // an empty buffer does not end with a token
    s = canary;
    CPPUNIT_ASSERT(!t.suffix(s, all));
    CPPUNIT_ASSERT_EQUAL(canary, s); // no parameter changes

    // we cannot skip an empty suffix, even in an empty buffer
    CPPUNIT_ASSERT(!t.skipSuffix(SBuf()));
}

void
TestTokenizer::testTokenizerInt64()
{
    // successful parse in base 10
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("1234"));
        const int64_t benchmark = 1234;
        CPPUNIT_ASSERT(t.int64(rv, 10));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // successful parse, autodetect base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("1234"));
        const int64_t benchmark = 1234;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // successful parse, autodetect base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("01234"));
        const int64_t benchmark = 01234;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // successful parse, autodetect base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0x12f4"));
        const int64_t benchmark = 0x12f4;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // autodetect octal base in shortest valid input
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0"));
        const int64_t benchmark = 0;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // autodetect decimal base in shortest valid input
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("1"));
        const int64_t benchmark = 1;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // autodetect hex base in shortest valid input
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0X1"));
        const int64_t benchmark = 0X1;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // invalid (when autodetecting base) input matching hex base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0x"));
        CPPUNIT_ASSERT(!t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(SBuf("0x"), t.buf());
    }

    // invalid (when forcing hex base) input matching hex base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0x"));
        CPPUNIT_ASSERT(!t.int64(rv, 16));
        CPPUNIT_ASSERT_EQUAL(SBuf("0x"), t.buf());
    }

    // invalid (when autodetecting base and limiting) input matching hex base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0x2"));
        CPPUNIT_ASSERT(!t.int64(rv, 0, true, 2));
        CPPUNIT_ASSERT_EQUAL(SBuf("0x2"), t.buf());
    }

    // invalid (when forcing hex base and limiting) input matching hex base
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0x3"));
        CPPUNIT_ASSERT(!t.int64(rv, 16, false, 2));
        CPPUNIT_ASSERT_EQUAL(SBuf("0x3"), t.buf());
    }

    // API mismatch: don't eat leading space
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf(" 1234"));
        CPPUNIT_ASSERT(!t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(SBuf(" 1234"), t.buf());
    }

    // API mismatch: don't eat multiple leading spaces
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("  1234"));
        CPPUNIT_ASSERT(!t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(SBuf("  1234"), t.buf());
    }

    // trailing spaces
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("1234  foo"));
        const int64_t benchmark = 1234;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT_EQUAL(SBuf("  foo"), t.buf());
    }

    // trailing nonspaces
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("1234foo"));
        const int64_t benchmark = 1234;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT_EQUAL(SBuf("foo"), t.buf());
    }

    // trailing nonspaces
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("0x1234foo"));
        const int64_t benchmark = 0x1234f;
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT_EQUAL(SBuf("oo"), t.buf());
    }

    // overflow
    {
        int64_t rv;
        Parser::Tokenizer t(SBuf("1029397752385698678762234"));
        CPPUNIT_ASSERT(!t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(SBuf("1029397752385698678762234"), t.buf());
    }

    // buffered sub-string parsing
    {
        int64_t rv;
        SBuf base("1029397752385698678762234");
        const int64_t benchmark = 22;
        Parser::Tokenizer t(base.substr(base.length()-4,2));
        CPPUNIT_ASSERT_EQUAL(SBuf("22"),t.buf());
        CPPUNIT_ASSERT(t.int64(rv));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT(t.buf().isEmpty());
    }

    // base-16, prefix
    {
        int64_t rv;
        SBuf base("deadbeefrow");
        const int64_t benchmark=0xdeadbeef;
        Parser::Tokenizer t(base);
        CPPUNIT_ASSERT(t.int64(rv,16));
        CPPUNIT_ASSERT_EQUAL(benchmark,rv);
        CPPUNIT_ASSERT_EQUAL(SBuf("row"),t.buf());

    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

