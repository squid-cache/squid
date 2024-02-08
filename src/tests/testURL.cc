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
#include "http/RequestMethod.h"
#include "SquidConfig.h"
#include "sbuf/Stream.h"
#include "unitTestMain.h"

#include <cppunit/TestAssert.h>
#include <sstream>
#include <vector>

/*
 * test the Anyp::Uri-related classes
 */

class TestUri : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestUri);
    CPPUNIT_TEST(testConstructScheme);
    CPPUNIT_TEST(testDefaultConstructor);
    CPPUNIT_TEST(testCanonicalCleanWithoutRequest);
    CPPUNIT_TEST(testCleanup);
    CPPUNIT_TEST(testEncoding);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testConstructScheme();
    void testDefaultConstructor();
    void testCanonicalCleanWithoutRequest();
    void testCleanup();
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
TestUri::testCanonicalCleanWithoutRequest()
{
    const std::vector<std::pair<SBuf,SBuf>> authorityPrefix = {
        {SBuf(),SBuf()},
        {SBuf("http://example.com"),SBuf("http://example.com")},
        {SBuf("http://example.com:1234"),SBuf("http://example.com:1234")}
// XXX: path with CTL chars
// XXX: path with ASCII-extended chars
    };

    const std::vector<std::pair<SBuf,SBuf>> path = {
        {SBuf(),SBuf()},
        {SBuf("/"),SBuf("/")},
        {SBuf("/path"),SBuf("/path")}
// XXX: path with CTL chars
// XXX: path with ASCII-extended chars
    };

    const std::vector<std::pair<SBuf,SBuf>> query =  {
        {SBuf(),SBuf()},
        {SBuf("?"),SBuf("?")},
        {SBuf("?query"),SBuf("?query")}
// XXX: query with CTL chars
// XXX: query with ASCII-extended chars
    };

    const std::vector<std::pair<SBuf,SBuf>> fragment = {
        {SBuf(),SBuf()},
        {SBuf("#"),SBuf("#")},
        {SBuf("#fragment"),SBuf("#fragment")}
// XXX: fragment with CTL chars
// XXX: fragment with ASCII-extended chars
    };

    const HttpRequestMethod mNil; // METHOD_NONE is sufficient for non-CONNECT tests
    const AnyP::UriScheme sNil;   // PROTO_NONE is sufficient for non-URN tests

    for (const auto &a : authorityPrefix) {
        for (const auto &p : path) {
            for (const auto &q : query) {
                for (const auto &f : fragment) {
                    SBuf in(a.first);
                    in.append(p.first);
                    in.append(q.first);
                    in.append(f.first);

                    Config.onoff.strip_query_terms = false;
                    SBuf outA(a.second);
                    outA.append(p.second);
                    outA.append(q.second);
                    outA.append(f.second);
                    CPPUNIT_ASSERT_EQUAL(outA, urlCanonicalCleanWithoutRequest(in, mNil, sNil));

                    Config.onoff.strip_query_terms = true;
                    SBuf outB(a.second);
                    outB.append(p.second);
                    if (!q.second.isEmpty())
                        outB.append('?');
                    else if (!f.second.isEmpty())
                        outB.append('#');
                    CPPUNIT_ASSERT_EQUAL(outB, urlCanonicalCleanWithoutRequest(in, mNil, sNil));
                }
            }
        }
    }

    // TODO test CONNECT URI cleaning

    // TODO test URN cleaning
}

void
TestUri::testCleanup()
{
    const std::vector<decltype(Config.uri_whitespace)> actions = {
        URI_WHITESPACE_STRIP,
        URI_WHITESPACE_ALLOW,
        URI_WHITESPACE_ENCODE,
        URI_WHITESPACE_CHOP,
        URI_WHITESPACE_DENY
    };

    const std::vector<unsigned char> whitespace = { '\t','\n','\v','\f','\r',' ' };

    // no whitespace
    {
        SBuf in("abcd");
        for (const auto action : actions) {
            Config.uri_whitespace = action;
            std::cerr << "CHECK: no-whitespace (" << action << ") in='" << in << "' == '" << AnyP::Uri::Cleanup(in) << "'" << std::endl;
            CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), in);
        }
    }

    // only whitespace
    {
        const SBuf nil;
        for (const auto wsp : whitespace) {
            SBuf in(reinterpret_cast<const char *>(&wsp), 1);

            SBuf encoded;
            encoded.appendf("%c%02X", '%', wsp);

            for (const auto action : actions) {
                Config.uri_whitespace = action;

                // XXX: allow ignores SP (only)
                if (action == URI_WHITESPACE_ALLOW) {
                    if (wsp == ' ')
                        CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), in);
                    else
                        CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), encoded);
                    continue;
                }

                // XXX: chop ignores VT and FF
                if (action == URI_WHITESPACE_CHOP) {
                    if (wsp == '\v' || wsp == '\f') {
                        CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), encoded);
                        continue;
                    }
                }

                if (action == URI_WHITESPACE_ENCODE) {
                    CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), encoded);
                    continue;
                }

                // else, the character is removed
                CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), nil);
            }
        }
    }

    // permutations of whitespace type and position
    {
        const std::vector<std::pair<SBuf,SBuf>> segments = {
            {SBuf(),SBuf("abc")},
            {SBuf("a"), SBuf("bc")},
            {SBuf("ab"), SBuf("c")},
            {SBuf("abc"),SBuf()}
        };

        // fixed string with various whitespace at any position
        for (const auto wsp : whitespace) {
            for (const auto &seg : segments) {
                for (int pos = 0; pos <= 4; ++pos) {
                    SBuf in;

                    // pos == 0 - no pre-encoded characters

                    // pos == 1 - start character is pre-encoded
                    if (pos == 1)
                        in.append("%20");

                    // prefix segment of valid URI characters
                    in.append(seg.first);

                    // pos == 2 - pre-encoded character immediately after prefix
                    if (pos == 2)
                        in.append("%20");

                    SBuf strip(in);
                    SBuf allow(in);
                    SBuf encode(in);
                    SBuf chop(in);

                    // i == 3 - pre-encode character after first whitespace
                    in.appendf("%c%s", wsp, (pos==3?"%20":""));
                    strip.appendf("%s", (pos==3?"%20":""));
                    // XXX: allow still encodes non-SP whitespace
                    if (wsp != ' ')
                        allow.appendf("%c%02X%s", '%', wsp, (pos==3?"%20":""));
                    else
                        allow.appendf("%c%s", wsp, (pos==3?"%20":""));
                    encode.appendf("%c%02X%s", '%', wsp, (pos==3?"%20":""));
                    // XXX: chop ignores VT and FF
                    if (wsp == '\v' || wsp == '\f')
                        chop.appendf("%c%02X%s", '%', wsp, (pos==3?"%20":""));

                    // suffix segment of valid URI characters after whitespace
                    in.append(seg.second);
                    strip.append(seg.second);
                    allow.append(seg.second);
                    encode.append(seg.second);
                    // XXX: chop ignores VT and FF
                    if (wsp == '\v' || wsp == '\f')
                        chop.append(seg.second);

                    // pos == 4 - final character is pre-encoded
                    if (pos == 4) {
                        in.append("%20");
                        strip.append("%20");
                        allow.append("%20");
                        encode.append("%20");
                        // XXX: chop ignores VT and FF
                        if (wsp == '\v' || wsp == '\f')
                            chop.append("%20");
                    }

                    Config.uri_whitespace = URI_WHITESPACE_ALLOW;
                    CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), allow);

                    Config.uri_whitespace = URI_WHITESPACE_ENCODE;
                    CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), encode);

                    Config.uri_whitespace = URI_WHITESPACE_CHOP;
                    CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), chop);

                    Config.uri_whitespace = URI_WHITESPACE_STRIP;
                    CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), strip);

                    Config.uri_whitespace = URI_WHITESPACE_DENY;
                    // XXX: deny makes same changes as strip.
                    CPPUNIT_ASSERT_EQUAL(AnyP::Uri::Cleanup(in), strip);
                }
            }
        }
    }
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
