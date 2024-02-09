/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "anyp/Uri.h"
#include "base/CharacterSet.h"
#include "base/TextException.h"
#include "compat/cppunit.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"
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
    CPPUNIT_TEST(testEncoding);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testConstructScheme();
    void testDefaultConstructor();
    void testEncoding();
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
TestUri::testEncoding()
{
    const std::vector< std::pair<SBuf, SBuf> > basicTestCases = {
        {SBuf(""), SBuf("")},
        {SBuf("foo"), SBuf("foo")},
        {SBuf("%"), SBuf("%25")},
        {SBuf("%foo"), SBuf("%25foo")},
        {SBuf("foo%"), SBuf("foo%25")},
        {SBuf("fo%o"), SBuf("fo%25o")},
        {SBuf("fo%%o"), SBuf("fo%25%25o")},
        {SBuf("fo o"), SBuf("fo%20o")},
        {SBuf("?1"), SBuf("%3F1")},
        {SBuf("\377"), SBuf("%FF")},
        {SBuf("fo\0o", 4), SBuf("fo%00o")},
    };

    for (const auto &testCase: basicTestCases) {
        CPPUNIT_ASSERT_EQUAL(testCase.first, AnyP::Uri::Decode(testCase.second));
        CPPUNIT_ASSERT_EQUAL(testCase.second, AnyP::Uri::Encode(testCase.first, CharacterSet::RFC3986_UNRESERVED()));
    };

    const auto invalidEncodings = {
        SBuf("%"),
        SBuf("%%"),
        SBuf("%%%"),
        SBuf("%1"),
        SBuf("%1Z"),
        SBuf("%1\000", 2),
        SBuf("%1\377"),
        SBuf("%\0002", 3),
        SBuf("%\3772"),
    };

    for (const auto &invalidEncoding: invalidEncodings) {
        // test various input positions of an invalid escape sequence
        CPPUNIT_ASSERT_THROW(AnyP::Uri::Decode(invalidEncoding), TextException);
        CPPUNIT_ASSERT_THROW(AnyP::Uri::Decode(ToSBuf("word", invalidEncoding)), TextException);
        CPPUNIT_ASSERT_THROW(AnyP::Uri::Decode(ToSBuf(invalidEncoding, "word")), TextException);
        CPPUNIT_ASSERT_THROW(AnyP::Uri::Decode(ToSBuf("word", invalidEncoding, "word")), TextException);
    };
}

int
main(int argc, char *argv[])
{
    return MyTestProgram().run(argc, argv);
}

