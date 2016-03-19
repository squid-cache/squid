/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SECURITY_HANDSHAKE_H
#define SQUID_SECURITY_HANDSHAKE_H

#include "fd.h"
#include "parser/BinaryTokenizer.h"
#include "sbuf/SBuf.h"
#if USE_OPENSSL
#include "ssl/gadgets.h"
#endif

namespace Security
{

// The Transport Layer Security (TLS) Protocol, Version 1.2

/// Helper class to debug parsing of various TLS structures
class FieldGroup
{
public:
    FieldGroup(BinaryTokenizer &tk, const char *description); ///< starts parsing

    void commit(BinaryTokenizer &tk); ///< commits successful parsing results
};

/// TLS Record Layer's content types from RFC 5246 Section 6.2.1
enum ContentType {
    ctChangeCipherSpec = 20,
    ctAlert = 21,
    ctHandshake = 22,
    ctApplicationData = 23
};

/// TLS Record Layer's protocol version from RFC 5246 Section 6.2.1
struct ProtocolVersion
{
    explicit ProtocolVersion(BinaryTokenizer &tk);

    // the "v" prefix works around environments that #define major and minor
    uint8_t vMajor;
    uint8_t vMinor;
};

/// TLS Record Layer's frame from RFC 5246 Section 6.2.1.
struct TLSPlaintext: public FieldGroup
{
    explicit TLSPlaintext(BinaryTokenizer &tk);

    uint8_t type; ///< Rfc5246::ContentType
    ProtocolVersion version;
    uint16_t length;
    SBuf fragment; ///< exactly length bytes
};

/// TLS Handshake protocol's handshake types from RFC 5246 Section 7.4
enum HandshakeType {
    hskServerHello = 2,
    hskCertificate = 11,
    hskServerHelloDone = 14
};

/// TLS Handshake Protocol frame from RFC 5246 Section 7.4.
struct Handshake: public FieldGroup
{
    explicit Handshake(BinaryTokenizer &tk);

    uint32_t msg_type: 8; ///< HandshakeType
    uint32_t length: 24;
    SBuf body; ///< Handshake Protocol message, exactly length bytes
};

/// TLS Alert protocol frame from RFC 5246 Section 7.2.
struct Alert: public FieldGroup
{
    explicit Alert(BinaryTokenizer &tk);
    uint8_t level; ///< warning or fatal
    uint8_t description; ///< close_notify, unexpected_message, etc.
};

/// Like a Pascal "length-first" string but with a 3-byte length field.
/// Used for (undocumented in RRC 5246?) Certificate and ASN1.Cert encodings.
struct P24String: public FieldGroup
{
    explicit P24String(BinaryTokenizer &tk, const char *description);

    uint32_t length;  // bytes in body (stored using 3 bytes, not 4!)
    SBuf body; ///< exactly length bytes
};

/// Incremental SSL Handshake parser.
class HandshakeParser {
public:
    /// The parsing states
    typedef enum {atHelloNone = 0, atHelloStarted, atHelloReceived, atCertificatesReceived, atHelloDoneReceived, atNstReceived, atCcsReceived, atFinishReceived} ParserState;

    HandshakeParser(): state(atHelloNone), ressumingSession(false), parseDone(false), parseError(false), currentContentType(0), unParsedContent(0), parsingPos(0), currentMsg(0), currentMsgSize(0), certificatesMsgPos(0), certificatesMsgSize(0) {}

    /// Parses the initial sequence of raw bytes sent by the SSL server.
    /// Returns true upon successful completion (HelloDone or Finished received).
    /// Otherwise, returns false (and sets parseError to true on errors).
    bool parseServerHello(const SBuf &data);

#if USE_OPENSSL
    Ssl::X509_STACK_Pointer serverCertificates; ///< parsed certificates chain
#endif

    ParserState state; ///< current parsing state.

    bool ressumingSession; ///< True if this is a resumming session

    bool parseDone; ///< The parser finishes its job
    bool parseError; ///< Set to tru by parse on parse error.

private:
    unsigned int currentContentType; ///< The current SSL record content type
    size_t unParsedContent; ///< The size of current SSL record, which is not parsed yet
    size_t parsingPos; ///< The parsing position from the beginning of parsed data
    size_t currentMsg; ///< The current handshake message possition from the beginning of parsed data
    size_t currentMsgSize; ///< The current handshake message size.

    size_t certificatesMsgPos; ///< The possition of certificates message from the beggining of parsed data
    size_t certificatesMsgSize; ///< The size of certificates message

private:
    void parseServerHelloTry();

    void parseRecord();
    void parseMessages();

    void parseChangeCipherCpecMessage();
    void parseAlertMessage();
    void parseHandshakeMessage();
    void parseApplicationDataMessage();
    void skipMessage(const char *msgType);

    void parseServerCertificates(const SBuf &raw);
#if USE_OPENSSL
    static X509 *ParseCertificate(const SBuf &raw);
#endif

    /// concatenated TLSPlaintext.fragments of TLSPlaintext.type
    SBuf fragments;

    BinaryTokenizer tkRecords; // TLS record layer (parsing uninterpreted data)
    BinaryTokenizer tkMessages; // TLS message layer (parsing fragments)
};

}

#endif // SQUID_SECURITY_HANDSHAKE_H
