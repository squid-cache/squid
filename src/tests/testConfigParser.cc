/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "ConfigParser.h"
#include "SquidString.h"
#include "unitTestMain.h"

/*
 * test the ConfigParser framework
 */

class TestConfigParser : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestConfigParser);
    CPPUNIT_TEST(testParseQuoted);
    CPPUNIT_TEST_SUITE_END();

protected:
    bool doParseQuotedTest(const char *, const char *);
    void testParseQuoted();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestConfigParser );

int shutting_down = 0;

bool TestConfigParser::doParseQuotedTest(const char *s, const char *expectInterp)
{
    char cfgline[2048];
    char cfgparam[2048];
    snprintf(cfgline, 2048, "%s", s);

    // Keep the initial value on cfgparam. The ConfigParser  methods will write on cfgline
    strncpy(cfgparam, cfgline, sizeof(cfgparam)-1);
    cfgparam[sizeof(cfgparam)-1] = '\0';

    // Initialize parser to point to the start of quoted string
    ConfigParser::SetCfgLine(cfgline);
    String unEscaped = ConfigParser::NextToken();

    const bool interpOk = (unEscaped.cmp(expectInterp) == 0);
    if (!interpOk) {
        printf("%25s: %s\n%25s: %s\n%25s: %s\n",
               "Raw configuration", cfgparam,
               "Expected interpretation", expectInterp,
               "Actual interpretation", unEscaped.termedBuf());
    }

    const char *quoted = ConfigParser::QuoteString(unEscaped);
    bool quotedOk = (strcmp(cfgparam, quoted)==0);
    if (!quotedOk) {
        printf("%25s: %s\n%25s: %s\n%25s: %s\n",
               "Raw configuration", cfgparam,
               "Parsed and quoted", quoted,
               "parsed value was", unEscaped.termedBuf());
    }

    return quotedOk && interpOk ;
}

void TestConfigParser::testParseQuoted()
{
    // SingleToken
    CPPUNIT_ASSERT_EQUAL(true, doParseQuotedTest("SingleToken", "SingleToken"));

    // This is a quoted "string" by me
    CPPUNIT_ASSERT_EQUAL(true, doParseQuotedTest("\"This is a quoted \\\"string\\\" by me\"",
                         "This is a quoted \"string\" by me"));

    // escape sequence test: \\"\"\\"
    CPPUNIT_ASSERT_EQUAL(true, doParseQuotedTest("\"escape sequence test: \\\\\\\\\\\"\\\\\\\"\\\\\\\\\\\"\"",
                         "escape sequence test: \\\\\"\\\"\\\\\""));

    // \beginning and end test"
    CPPUNIT_ASSERT_EQUAL(true, doParseQuotedTest("\"\\\\beginning and end test\\\"\"",
                         "\\beginning and end test\""));

    // "
    CPPUNIT_ASSERT_EQUAL(true, doParseQuotedTest("\"\\\"\"", "\""));

    /* \ */
    CPPUNIT_ASSERT_EQUAL(true, doParseQuotedTest("\"\\\\\"", "\\"));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

