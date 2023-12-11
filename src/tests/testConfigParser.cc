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
#include "sbuf/SBuf.h"
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
    void testParseQuoted();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestConfigParser );

int shutting_down = 0;

void
TestConfigParser::testParseQuoted()
{
    const std::array<std::pair<SBuf, SBuf>, 6> tokens = {{
 { SBuf("SingleToken"), SBuf("SingleToken") },
 { SBuf("\"This is a quoted \\\"string\\\" by me\""), SBuf("This is a quoted \"string\" by me") },
 { SBuf("\"escape sequence test: \\\\\\\\\\\"\\\\\\\"\\\\\\\\\\\"\""), SBuf("escape sequence test: \\\\\"\\\"\\\\\"") },
 { SBuf("\"\\\\beginning and end test\\\"\""), SBuf("\\beginning and end test\"") },
 { SBuf("\"\\\"\""), SBuf("\"") },
 { SBuf("\"\\\\\""), SBuf("\\") }
}};

    for(const auto &t : tokens) {
        auto *line = SBufToCstring(t.first);
        ConfigParser::SetCfgLine(line);
        const SBuf found(ConfigParser::NextToken());
        CPPUNIT_ASSERT_EQUAL(t.second, found);
        xfree(line);
    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

