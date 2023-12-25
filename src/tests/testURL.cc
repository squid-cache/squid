/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "anyp/Uri.h"
#include "compat/cppunit.h"
#include "debug/Stream.h"
#include "unitTestMain.h"

#include <cppunit/TestAssert.h>
#include <sstream>

/*
 * test the Anyp::Uri-related classes
 */

class TestUri : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestUri);
    CPPUNIT_TEST(testConstructScheme);
    CPPUNIT_TEST(testDefaultConstructor);
    CPPUNIT_TEST(testEncodeDecode);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testConstructScheme();
    void testDefaultConstructor();
    void testEncodeDecode();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestUri);

/// customizes our test setup
class MyTestProgram: public TestProgram
{
public:
    /* TestProgram API */
    void startup() override;
};

void
MyTestProgram::startup()
{
    Mem::Init();
    AnyP::UriScheme::Init();
}

/*
 * we can construct a URL with a AnyP::UriScheme.
 * This creates a URL for that scheme.
 */
void
TestUri::testConstructScheme()
{
    AnyP::UriScheme empty_scheme;
    AnyP::Uri protoless_url(AnyP::PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(empty_scheme, protoless_url.getScheme());

    AnyP::UriScheme ftp_scheme(AnyP::PROTO_FTP);
    AnyP::Uri ftp_url(AnyP::PROTO_FTP);
    CPPUNIT_ASSERT_EQUAL(ftp_scheme, ftp_url.getScheme());
}

/*
 * a default constructed URL has scheme "NONE".
 * Also, we should be able to use new and delete on
 * scheme instances.
 */
void
TestUri::testDefaultConstructor()
{
    AnyP::UriScheme aScheme;
    AnyP::Uri aUrl;
    CPPUNIT_ASSERT_EQUAL(aScheme, aUrl.getScheme());

    auto *urlPointer = new AnyP::Uri;
    CPPUNIT_ASSERT(urlPointer != nullptr);
    delete urlPointer;
}

void
TestUri::testEncodeDecode()
{
    std::vector<std::pair<const char *, const char *>>
        testCasesEncode = {
            {"foo", "foo"},
            {"foo%", "foo%25"},
            {"fo%o", "fo%25o"},
            {"fo%%o", "fo%25%25o"}
            } ,
        testCasesDecode = {
            {"foo", "foo"},
            {"foo%", "foo%"},
            {"foo%%", "foo%"},
            {"foo%25", "foo%"},
            {"foo%2", "foo%2"},
            {"fo%o", "fo%o"},
            {"fo%2o", "fo%2o"},
            {"fo%25o", "fo%o"},
            {"fo%%o", "fo%o"},
            {"fo%25%25o", "fo%%o"},
            {"fo%20o", "fo o"}
            }
        ;

    for (const auto &testCase: testCasesEncode) {
        // static char buffer[1024];
        CPPUNIT_ASSERT_EQUAL(SBuf(testCase.first), AnyP::Uri::Decode(AnyP::Uri::Rfc3986Encode(SBuf(testCase.first))));
        CPPUNIT_ASSERT_EQUAL(SBuf(testCase.second), AnyP::Uri::Rfc3986Encode(SBuf(testCase.first)));
    };

    for (const auto &testCase: testCasesDecode) {
        CPPUNIT_ASSERT_EQUAL(SBuf(testCase.second), AnyP::Uri::Decode(SBuf(testCase.first)));
    };
}

int
main(int argc, char *argv[])
{
    return MyTestProgram().run(argc, argv);
}
