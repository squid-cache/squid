/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "security/Handshake.h"
#include "unitTestMain.h"

#include <string>

namespace {

/// Encode a TLS length or type field in network byte order.
void
AppendInteger(SBuf &out, const uint32_t value, const unsigned int width)
{
    for (auto i = width; i > 0; --i) {
        const char octet = static_cast<char>(value >> ((i - 1) * 8));
        out.append(&octet, 1);
    }
}

SBuf
Handshake(const uint8_t type, const SBuf &body)
{
    SBuf result;
    AppendInteger(result, type, 1);
    AppendInteger(result, body.length(), 3);
    result.append(body);
    return result;
}

SBuf
Record(const SBuf &fragment, const uint8_t type = 22)
{
    SBuf result;
    AppendInteger(result, type, 1);
    AppendInteger(result, 0x0303, 2); // TLS v1.2
    AppendInteger(result, fragment.length(), 2);
    result.append(fragment);
    return result;
}

SBuf
HelloBody()
{
    SBuf result;
    AppendInteger(result, 0x0303, 2);
    result.append(std::string(32, 'R').data(), 32); // random
    AppendInteger(result, 0, 1); // empty session ID
    return result;
}

SBuf
ClientHello(const bool large)
{
    auto body = HelloBody();
    AppendInteger(body, 2, 2); // cipher suites length
    AppendInteger(body, 0x002f, 2); // TLS_RSA_WITH_AES_128_CBC_SHA
    AppendInteger(body, 1, 1); // compression methods length
    AppendInteger(body, 0, 1); // null compression
    if (large) {
        const auto ticket = std::string(16384, 'T');
        AppendInteger(body, ticket.size() + 4, 2); // extensions length
        AppendInteger(body, 35, 2); // session_ticket extension
        AppendInteger(body, ticket.size(), 2);
        body.append(ticket.data(), ticket.size());
    }
    return Handshake(1, body);
}

SBuf
ServerHello()
{
    auto body = HelloBody();
    AppendInteger(body, 0x002f, 2); // selected cipher suite
    AppendInteger(body, 0, 1); // null compression
    return Handshake(2, body);
}

} // namespace

class TestHandshake : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestHandshake);
    CPPUNIT_TEST(testDelayedClientHello);
    CPPUNIT_TEST(testFragmentedHandshakeHeader);
    CPPUNIT_TEST(testDripFeed);
    CPPUNIT_TEST(testDelayedServerMessages);
    CPPUNIT_TEST(testContentTypeChange);
    CPPUNIT_TEST(testMalformedHello);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testDelayedClientHello();
    void testFragmentedHandshakeHeader();
    void testDripFeed();
    void testDelayedServerMessages();
    void testContentTypeChange();
    void testMalformedHello();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestHandshake);

void
TestHandshake::testDelayedClientHello()
{
    const auto hello = ClientHello(true);
    const auto first = Record(hello.substr(0, 16384));
    auto all = first;
    all.append(Record(hello.substr(16384)));

    Security::HandshakeParser delayed(Security::HandshakeParser::fromClient);
    CPPUNIT_ASSERT(!delayed.parseHello(first));
    CPPUNIT_ASSERT(!delayed.parseHello(first)); // retry without new bytes
    CPPUNIT_ASSERT(delayed.parseHello(all));
    CPPUNIT_ASSERT(delayed.details->hasTlsTicket);

    Security::HandshakeParser together(Security::HandshakeParser::fromClient);
    CPPUNIT_ASSERT(together.parseHello(all));
    CPPUNIT_ASSERT(together.details->hasTlsTicket);
    CPPUNIT_ASSERT_EQUAL(together.details->clientRandom, delayed.details->clientRandom);
    CPPUNIT_ASSERT_EQUAL(together.details->tlsSupportedVersion, delayed.details->tlsSupportedVersion);
}

void
TestHandshake::testFragmentedHandshakeHeader()
{
    const auto hello = ClientHello(false);
    for (SBuf::size_type split = 1; split < hello.length(); ++split) {
        Security::HandshakeParser parser(Security::HandshakeParser::fromClient);
        auto input = Record(hello.substr(0, split));
        CPPUNIT_ASSERT(!parser.parseHello(input));
        input.append(Record(hello.substr(split)));
        CPPUNIT_ASSERT(parser.parseHello(input));
    }
}

void
TestHandshake::testDripFeed()
{
    const auto hello = ClientHello(false);
    SBuf input;
    for (SBuf::size_type i = 0; i < hello.length(); ++i)
        input.append(Record(hello.substr(i, 1)));

    Security::HandshakeParser parser(Security::HandshakeParser::fromClient);
    for (SBuf::size_type length = 1; length < input.length(); ++length)
        CPPUNIT_ASSERT(!parser.parseHello(input.substr(0, length)));
    CPPUNIT_ASSERT(parser.parseHello(input));
}

void
TestHandshake::testDelayedServerMessages()
{
    const auto hello = ServerHello();
    const auto certificate = Handshake(11, SBuf("certificate"));
    auto input = Record(hello);
    Security::HandshakeParser parser(Security::HandshakeParser::fromServer);
    CPPUNIT_ASSERT(!parser.parseHello(input));
    CPPUNIT_ASSERT_EQUAL(Security::HandshakeParser::atHelloReceived, parser.state);

    input.append(Record(certificate.substr(0, 6)));
    CPPUNIT_ASSERT(!parser.parseHello(input));
    input.append(Record(certificate.substr(6)));
    CPPUNIT_ASSERT(!parser.parseHello(input));
    input.append(Record(Handshake(14, SBuf()))); // ServerHelloDone
    CPPUNIT_ASSERT(parser.parseHello(input));
    CPPUNIT_ASSERT_EQUAL(Security::HandshakeParser::atHelloDoneReceived, parser.state);

    Security::HandshakeParser together(Security::HandshakeParser::fromServer);
    CPPUNIT_ASSERT(together.parseHello(input));
}

void
TestHandshake::testContentTypeChange()
{
    auto input = Record(ClientHello(false).substr(0, 10));
    Security::HandshakeParser parser(Security::HandshakeParser::fromClient);
    CPPUNIT_ASSERT(!parser.parseHello(input));
    input.append(Record(SBuf("\1", 1), 20)); // ChangeCipherSpec cannot continue Hello
    CPPUNIT_ASSERT_THROW(parser.parseHello(input), TextException);

    // A complete ServerHello followed by ChangeCipherSpec is valid in TLS v1.2.
    input = Record(ServerHello());
    Security::HandshakeParser server(Security::HandshakeParser::fromServer);
    CPPUNIT_ASSERT(!server.parseHello(input));
    input.append(Record(SBuf("\1", 1), 20));
    CPPUNIT_ASSERT(server.parseHello(input));
    CPPUNIT_ASSERT(server.resumingSession);
}

void
TestHandshake::testMalformedHello()
{
    // A complete handshake frame with an incomplete Hello body is an error.
    Security::HandshakeParser parser(Security::HandshakeParser::fromClient);
    CPPUNIT_ASSERT_THROW(parser.parseHello(Record(Handshake(1, SBuf("\3\3", 2)))), TextException);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
