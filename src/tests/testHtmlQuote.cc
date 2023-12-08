/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "html/Quoting.h"
#include "unitTestMain.h"

#include <cstring>
#include <iostream>

class TestHtmlQuote: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestHtmlQuote);
    CPPUNIT_TEST(test_html_quote_cstr);
    CPPUNIT_TEST_SUITE_END();

protected:
    void test_html_quote_cstr();
    void testPerformance();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestHtmlQuote );

void
TestHtmlQuote::test_html_quote_cstr()
{
    CPPUNIT_ASSERT_EQUAL(std::string(""), std::string(html_quote("")));
    CPPUNIT_ASSERT_EQUAL(std::string("bar"), std::string(html_quote("bar")));
    CPPUNIT_ASSERT_EQUAL(std::string("foo&lt;bar&gt;gazonk"), std::string(html_quote("foo<bar>gazonk")));
    CPPUNIT_ASSERT_EQUAL(std::string("foo&amp;bar"), std::string(html_quote("foo&bar")));
    CPPUNIT_ASSERT_EQUAL(std::string("some&apos;thing"), std::string(html_quote("some'thing")));
    CPPUNIT_ASSERT_EQUAL(std::string("some&quot;thing"), std::string(html_quote("some\"thing")));
    CPPUNIT_ASSERT_EQUAL(std::string("&lt;&gt;&quot;&amp;&apos;"), std::string(html_quote("<>\"&'")));
    CPPUNIT_ASSERT_EQUAL(std::string("&gt;"), std::string(html_quote(">")));
    CPPUNIT_ASSERT_EQUAL(std::string("&#163;"), std::string(html_quote("\xa3")));

    for (unsigned char ch = 1; ch < 0xff; ++ch) {
        unsigned char buf[2] = {ch, '\0'};
        auto quoted = html_quote(reinterpret_cast<char *>(buf));

        if (strlen(quoted) == 1) {
            CPPUNIT_ASSERT_EQUAL(static_cast<int>(ch), static_cast<int>(quoted[0]));
        } else {
            CPPUNIT_ASSERT(strlen(quoted) >= 3);
            CPPUNIT_ASSERT_EQUAL('&', quoted[0]);
            CPPUNIT_ASSERT_EQUAL(';', quoted[strlen(quoted)-1]);
            if (quoted[1] == '#') {
                CPPUNIT_ASSERT(strlen(quoted) > 3);
                CPPUNIT_ASSERT(strlen(quoted) <= 6);
            }
        }
    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
