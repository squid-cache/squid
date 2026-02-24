/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

#include "clients/FtpClient.h"
#include "sbuf/SBuf.h"

class TestFtpEpsv : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestFtpEpsv);
    CPPUNIT_TEST(testValidTupleParses);
    CPPUNIT_TEST(testRejectDigitDelimiter);
    CPPUNIT_TEST(testPortRange);
    CPPUNIT_TEST(testTrailingGarbage);
    CPPUNIT_TEST(testOptionalWsAllowed);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testValidTupleParses();
    void testRejectDigitDelimiter();
    void testPortRange();
    void testTrailingGarbage();
    void testOptionalWsAllowed();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestFtpEpsv);

void
TestFtpEpsv::testValidTupleParses()
{
    uint16_t port = 0;
    Parser::Tokenizer tok(SBuf("(|||12345|)"));
    Parser::Tokenizer tok2(SBuf("(***21*)"));

    // Classic '|' delimiter
    CPPUNIT_ASSERT(Ftp::parseEPSV(tok, port));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(12345), port);

    // Arbitrary non-digit delimiter
    CPPUNIT_ASSERT(Ftp::parseEPSV(tok2, port));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(21), port);
}

void
TestFtpEpsv::testRejectDigitDelimiter()
{
    uint16_t port = 0;
    Parser::Tokenizer tok(SBuf("(111123451)"));
    // EPSV delimiter must be a non-digit
    CPPUNIT_ASSERT(!Ftp::parseEPSV(tok, port));
}

void
TestFtpEpsv::testPortRange()
{
    uint16_t port = 0;
    Parser::Tokenizer tok(SBuf("(|||0|)"));
    Parser::Tokenizer tok2(SBuf("(|||70000|)"));
    // Port must be 1..65535
    CPPUNIT_ASSERT(!Ftp::parseEPSV(tok, port));
    CPPUNIT_ASSERT(!Ftp::parseEPSV(tok2, port));
}

void
TestFtpEpsv::testTrailingGarbage()
{
    uint16_t port = 0;
    Parser::Tokenizer tok(SBuf("(|||123|)xyz"));
    // No extra junk after the closing delimiter
    CPPUNIT_ASSERT(!Ftp::parseEPSV(tok, port));
}

void
TestFtpEpsv::testOptionalWsAllowed()
{
    uint16_t port = 0;
    Parser::Tokenizer tok(SBuf("(|||8080|)\r\n"));

    // Allow network EOL after the tuple
    CPPUNIT_ASSERT(Ftp::parseEPSV(tok, port));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(8080), port);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
