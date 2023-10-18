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

class testHtmlQuote: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(testHtmlQuote);
    CPPUNIT_TEST(test_html_quote_cstr);
    // CPPUNIT_TEST(testPerformance);
    CPPUNIT_TEST_SUITE_END();

    protected:
    void test_html_quote_cstr();
    void testPerformance();
};

CPPUNIT_TEST_SUITE_REGISTRATION( testHtmlQuote );

void
testHtmlQuote::test_html_quote_cstr()
{
    CPPUNIT_ASSERT_EQUAL(std::string(""), std::string(html_quote("")));
    CPPUNIT_ASSERT_EQUAL(std::string("bar"), std::string(html_quote("bar")));
    CPPUNIT_ASSERT_EQUAL(std::string("foo&lt;bar&gt;gazonk"), std::string(html_quote("foo<bar>gazonk")));
    CPPUNIT_ASSERT_EQUAL(std::string("foo&amp;bar"), std::string(html_quote("foo&bar")));
    CPPUNIT_ASSERT_EQUAL(std::string("some&#39;thing"), std::string(html_quote("some'thing")));
    CPPUNIT_ASSERT_EQUAL(std::string("some&quot;thing"), std::string(html_quote("some\"thing")));
    CPPUNIT_ASSERT_EQUAL(std::string("&#31;"), std::string(html_quote("\x1f")));
}

void testHtmlQuote::testPerformance()
{
    const char *input = "<script>alert('Hello, world!');</script>";
    const char *expected_output = "&lt;script&gt;alert(&#39;Hello, world!&#39;);&lt;/script&gt;";
    const int num_iterations = 10000000;
    const char *output = html_quote(input);

    // Measure the time taken to call html_quote repeatedly
    clock_t start_time = clock();
    for (int i = 0; i < num_iterations; i++)
    {
        output = html_quote(input);
        CPPUNIT_ASSERT_EQUAL(0, strcmp(output, expected_output));
    }
    clock_t end_time = clock();

    std::cout << "\nexpected: " << expected_output << '\n'
              << "actual  : " << output << '\n';
    CPPUNIT_ASSERT_EQUAL(0, strcmp(output, expected_output));
    // Calculate the average time per call
    double elapsed_time = static_cast<double>(end_time - start_time) / CLOCKS_PER_SEC;
    double time_per_call = elapsed_time / num_iterations;

    // Check that the time per call is reasonable
    double max_time_per_call = 0.0001; // 0.1 milliseconds
    CPPUNIT_ASSERT(time_per_call < max_time_per_call);
}

int main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
