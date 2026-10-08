/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "parser/BinaryTokenizer.h"
#include "security/Handshake.h"
#include "security/Session.h"
#include "ssl/gadgets.h"
#include "unitTestMain.h"

class TestHandshake : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestHandshake);
    CPPUNIT_TEST(testDelayedClientHello);
    CPPUNIT_TEST_SUITE_END();

protected:
    // A TLS record carries at most 16 KiB (RFC 5246 Section 6.2.1). A ticket of
    // that size forces the complete ClientHello into multiple records.
    static constexpr size_t TicketSize = 16 * 1024;
    SBuf makeClientHello();
    void testDelayedClientHello();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestHandshake);

/// Initializes process-wide dependencies before running the tests.
class HandshakeTestProgram: public TestProgram
{
public:
    void startup() override;
};

void
HandshakeTestProgram::startup()
{
    SQUID_OPENSSL_init_ssl();
}

/// Generate a ClientHello split across TLS records, using in-memory buffers.
SBuf
TestHandshake::makeClientHello()
{
    // Use TLS 1.2 to match the Bug 5562 traffic, where a large session ticket caused
    // the ClientHello to span records. The parser bug is version-independent; this
    // test forces the same split with a large opaque session ticket.
#if HAVE_OPENSSL_TLS_CLIENT_METHOD && HAVE_OPENSSL_TLS_VERSION_LIMITS
    const Security::ContextPointer context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
#else
    // Older TLS libraries select TLS 1.2 with a version-specific method.
    const Security::ContextPointer context(SSL_CTX_new(TLSv1_2_client_method()), SSL_CTX_free);
#endif
    CPPUNIT_ASSERT_MESSAGE("TLS library client context creation failed", context);
#if HAVE_OPENSSL_TLS_CLIENT_METHOD && HAVE_OPENSSL_TLS_VERSION_LIMITS
    // Pin both limits so the TLS library cannot choose a different version.
    CPPUNIT_ASSERT_MESSAGE("TLS library cannot set the minimum TLS version",
                           SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION));
    CPPUNIT_ASSERT_MESSAGE("TLS library cannot set the maximum TLS version",
                           SSL_CTX_set_max_proto_version(context.get(), TLS1_2_VERSION));
#endif

    const Security::SessionPointer session(SSL_new(context.get()), SSL_free);
    CPPUNIT_ASSERT_MESSAGE("TLS library client session creation failed", session);
    // Bug 5562 traffic carried a TLS 1.2 session ticket large enough to make the
    // ClientHello span records. Ticket contents are opaque to the client, so dummy
    // bytes reproduce that traffic (RFC 5077 Section 3.2).
    static unsigned char ticket[TicketSize] = {};
    CPPUNIT_ASSERT_MESSAGE("TLS library cannot set the session ticket",
                           SSL_set_session_ticket_ext(session.get(), ticket, sizeof(ticket)));
    // Use in-memory buffers for incoming and outgoing TLS data. The incoming buffer stays empty
    // because this test does not send a server response.
    Ssl::BIO_Pointer incoming(BIO_new(BIO_s_mem()));
    Ssl::BIO_Pointer outgoing(BIO_new(BIO_s_mem()));
    CPPUNIT_ASSERT_MESSAGE("TLS library input BIO creation failed", incoming);
    CPPUNIT_ASSERT_MESSAGE("TLS library output BIO creation failed", outgoing);
    SSL_set_bio(session.get(), incoming.release(), outgoing.release());
    SSL_set_connect_state(session.get());

    // Ask the TLS library to start the handshake and write a ClientHello. With no server response in the
    // input buffer, SSL_get_error() should report SSL_ERROR_WANT_READ.
    const auto result = SSL_do_handshake(session.get());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("TLS library must request a server response",
                                 SSL_ERROR_WANT_READ, SSL_get_error(session.get(), result));
    char *bytes = nullptr;
    const auto length = BIO_get_mem_data(SSL_get_wbio(session.get()), &bytes);
    CPPUNIT_ASSERT_MESSAGE("TLS library did not generate a ClientHello", length > 0);
    return SBuf(bytes, length);
}

void
TestHandshake::testDelayedClientHello()
{
    const auto input = makeClientHello();
    // Read the first record's length so we can deliver it separately.
    Parser::BinaryTokenizer records(input);
    records.skip(3, ".typeAndVersion");
    const auto fragmentSize = records.uint16(".length");
    const auto first = input.substr(0, records.parsed() + fragmentSize);
    CPPUNIT_ASSERT_MESSAGE("TLS library must fragment the ClientHello across records",
                           first.length() < input.length());

    // Check that the ClientHello parses when all records arrive together.
    Security::HandshakeParser together(Security::HandshakeParser::fromClient);
    CPPUNIT_ASSERT_MESSAGE("the complete ClientHello must parse", together.parseHello(input));

    // TLS record boundaries do not preserve handshake-message boundaries, so one
    // ClientHello may span several records (RFC 5246 Section 6.2.1).
    // Recreate the traffic that triggered Bug 5562 by delivering the first record before the rest.
    // The parser should return false until the remaining records arrive, then parse the message.
    Security::HandshakeParser delayed(Security::HandshakeParser::fromClient);
    CPPUNIT_ASSERT_MESSAGE("the first record requires a continuation", !delayed.parseHello(first));
    CPPUNIT_ASSERT_MESSAGE("retrying without new bytes still requires a continuation",
                           !delayed.parseHello(first));
    CPPUNIT_ASSERT_MESSAGE("the accumulated records must parse", delayed.parseHello(input));
    CPPUNIT_ASSERT_MESSAGE("the delayed ClientHello must carry the session ticket",
                           delayed.details->hasTlsTicket);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("delayed delivery must preserve the client random",
                                 together.details->clientRandom, delayed.details->clientRandom);
}

int
main(int argc, char *argv[])
{
    return HandshakeTestProgram().run(argc, argv);
}
