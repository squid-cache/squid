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

#include <map>
#include <stdexcept>

class TestHttpHeaderTools: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestHttpHeaderTools );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testHttpHeaderParseInt );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testHttpHeaderParseInt();
};


CPPUNIT_TEST_SUITE_REGISTRATION( TestHttpHeaderTools );


void TestHttpHeaderTools::testHttpHeaderParseInt()
{
    // test success case
    {
        static std::map<const char *, int> testCases = {
            { "0", 0 },
            { "-1", -1 },
            { "1", 1 },
            { "65535", 65535 },
            { "1h", 1}, // ignore trailing characters
            { "0x1", 0 }, // doesn't parse hex
            { " 1", 1 }, // ignore leading space
        };
        for (const auto& i : testCases ) {
            int output;
            int rv = httpHeaderParseInt(i.first, &output);
            CPPUNIT_ASSERT_EQUAL(1, rv);
            CPPUNIT_ASSERT_EQUAL(i.second, output);
        }
    }
    // test fail case
    {
        static std::map<const char *, int> testCases = {
            { "v", 0 },
            { "h1", 0 },
        };
        for (const auto &i : testCases) {
            int output;
            int rv = httpHeaderParseInt(i.first, &output);
            CPPUNIT_ASSERT_EQUAL(0, rv);
            CPPUNIT_ASSERT_EQUAL(i.second, output);
        }
    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

