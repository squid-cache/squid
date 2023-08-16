/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "HttpHeaderTools.h"
#include "unitTestMain.h"

#include <climits>
#include <list>
#include <map>
#include <stdexcept>
#include <string>
#include <tuple>

class TestHttpHeaderTools: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestHttpHeaderTools );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testHttpHeaderParseInt );
    CPPUNIT_TEST( testHttpHeaderParseOffset );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testHttpHeaderParseInt();
    void testHttpHeaderParseOffset();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestHttpHeaderTools );
void TestHttpHeaderTools::testHttpHeaderParseInt()
{
    // test we can successfully parse valid integers
    {
        std::string intmax(std::to_string(INT_MAX));
        std::string overflowing(std::to_string(static_cast<unsigned int>(INT_MAX) + 1));
        static std::map<const char *, int> testCases = {
            {"0", 0},
            {"-1", -1},
            {"1", 1},
            {"65535", 65535},
            {intmax.c_str(), INT_MAX},
        };
        for (const auto &i : testCases) {
            int output = INT_MIN;
            int rv = httpHeaderParseInt(i.first, &output);
            CPPUNIT_ASSERT_EQUAL(i.second, output);
            CPPUNIT_ASSERT_EQUAL(1, rv);
        }
    }

    // things we can parse although they are not valid integers
    {
        static std::map<const char *, int> testCases = {
            {"1h", 1},  // ignore trailing characters
            {"0x1", 0}, // doesn't parse hex
            {" 1", 1},  // ignore leading space
        };
        for (const auto &i : testCases)
        {
            int output = INT_MIN;
            int rv = httpHeaderParseInt(i.first, &output);
            CPPUNIT_ASSERT_EQUAL(i.second, output);
            CPPUNIT_ASSERT_EQUAL(1, rv);
        }
    }
    // things we should fail, but don't
    {
        std::string overflowing(std::to_string(static_cast<unsigned int>(INT_MAX) + 1));
        static std::map<const char *, int> testCases = {
            {"1h", 1},  // ignore trailing characters
            {"0x1", 0}, // doesn't parse hex
            {" 1", 1},  // ignore leading space
            {overflowing.c_str(), INT_MIN}, // ouch. Overflow doesn't error
        };
        for (const auto &i : testCases)
        {
            int output = INT_MIN;
            int rv = httpHeaderParseInt(i.first, &output);
            CPPUNIT_ASSERT_EQUAL(i.second, output);
            CPPUNIT_ASSERT_EQUAL(1, rv);
        }
    }
    // Things we correctly fail to parse
    {
        static std::vector<std::string> testCases = {
            "v",
            "h1",
        };
        for (const auto &i : testCases) {
            int output = INT_MIN;
            int rv = httpHeaderParseInt(i.c_str(), &output);
            CPPUNIT_ASSERT_EQUAL(0, rv);
            CPPUNIT_ASSERT_EQUAL(0, output);
        }
    }
}

void TestHttpHeaderTools::testHttpHeaderParseOffset()
{
    {
        // tuple fields: string to test, expected value,
        //  expected return value, bool if endPtr is expected to not be nullptr
        std::string overflowing(std::to_string(static_cast<uint64_t>(LLONG_MAX) + 1));
        std::list<std::tuple<const char *, int64_t, bool, bool>> testCases = {
            {"0", 0, true, true},
            {"1", 1, true, true},
            {"-1", -1, true, true},
            {"a", 0, false, false},
            {"1h", 1, true, true}, // ignore trailing characters
            {" 1", 1, true, true}, // ignore leading space
            {"1 ", 1, true, true}, // ignore trailing space
            {"", 0, false, false}, // empty value
            {overflowing.c_str(), 0, false, false}, // overflow
        };
        for (const auto &i : testCases)
        {
            int64_t value = -1;
            char* endPtr = nullptr;
            bool rv = httpHeaderParseOffset( std::get<0>(i), &value, &endPtr);
            CPPUNIT_ASSERT_EQUAL(std::get<1>(i), value);
            CPPUNIT_ASSERT_EQUAL(std::get<2>(i), rv);
            CPPUNIT_ASSERT_EQUAL(std::get<3>(i), (endPtr != nullptr));
        }
    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

