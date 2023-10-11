/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "html_quote.h"
#include "unitTestMain.h"

#include <cstring>

class testHtmlQuote: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(testHtmlQuote);
    CPPUNIT_TEST(test_html_quote_cstr);
    CPPUNIT_TEST_SUITE_END();

    protected:
    void test_html_quote_cstr();
};

CPPUNIT_TEST_SUITE_REGISTRATION( testHtmlQuote );

void
testHtmlQuote::test_html_quote_cstr()
{
    CPPUNIT_ASSERT_EQUAL(0, strcmp(html_quote(""),""));
    CPPUNIT_ASSERT_EQUAL(0, strcmp(html_quote("bar"),"bar"));
    CPPUNIT_ASSERT_EQUAL(0, strcmp(html_quote("foo<bar>gazonk"), "foo&lt;bar&gt;gazonk"));
    CPPUNIT_ASSERT_EQUAL(0, strcmp(html_quote("foo&bar"), "foo&amp;bar"));
    CPPUNIT_ASSERT_EQUAL(0, strcmp(html_quote("\'"), "&#39;"));
}

int main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
