/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ConfigParser.h"
#include "event.h"
#include "Mem.h"
#include "SquidString.h"
#include "testConfigParser.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testConfigParser);

/* let this test link sanely */
void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{}

void testConfigParser::setUp()
{
}

bool testConfigParser::doParseQuotedTest(const char *s, const char *expectInterp)
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

void testConfigParser::testParseQuoted()
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

