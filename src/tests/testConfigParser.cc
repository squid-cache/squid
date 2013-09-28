#define SQUID_UNIT_TEST 1
#include "squid.h"
#include "testConfigParser.h"
#include "SquidString.h"
#include "Mem.h"
#include "event.h"
#include "ConfigParser.h"

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
    snprintf(cfgline, 2048, "Config %s", s);

    // Points to the start of quoted string
    const char *tmp = strchr(cfgline, ' ');

    if (tmp == NULL) {
        fprintf(stderr, "Invalid config line: %s\n", s);
        return false;
    }

    // Keep the initial value on cfgparam. The ConfigParser  methods will write on cfgline
    strncpy(cfgparam, tmp+1, sizeof(cfgparam)-1);
    cfgparam[sizeof(cfgparam)-1] = '\0';

    // Initialize parser to point to the start of quoted string
    strtok(cfgline, w_space);
    String unEscaped;
    ConfigParser::ParseQuotedString(&unEscaped);

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
    CPPUNIT_ASSERT(doParseQuotedTest("SingleToken", "SingleToken"));

    // This is a quoted "string" by me
    CPPUNIT_ASSERT(doParseQuotedTest("\"This is a quoted \\\"string\\\" by me\"",
                                     "This is a quoted \"string\" by me"));

    // escape sequence test: \\"\"\\"
    CPPUNIT_ASSERT(doParseQuotedTest("\"escape sequence test: \\\\\\\\\\\"\\\\\\\"\\\\\\\\\\\"\"",
                                     "escape sequence test: \\\\\"\\\"\\\\\""));

    // \beginning and end test"
    CPPUNIT_ASSERT(doParseQuotedTest("\"\\\\beginning and end test\\\"\"",
                                     "\\beginning and end test\""));

    // "
    CPPUNIT_ASSERT(doParseQuotedTest("\"\\\"\"", "\""));

    /* \ */
    CPPUNIT_ASSERT(doParseQuotedTest("\"\\\\\"", "\\"));
}

