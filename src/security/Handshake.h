/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SECURITY_HANDSHAKE_H
#define SQUID_SECURITY_HANDSHAKE_H

#include "base/RefCount.h"
#include "fd.h"
#include "parser/BinaryTokenizer.h"
#include "sbuf/SBuf.h"
#if USE_OPENSSL
#include "ssl/gadgets.h"
#endif

#include <list>

namespace Security
{

// The Transport Layer Security (TLS) Protocol, Version 1.2

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

    /// XXX: TlsDetails use "int" to manipulate version information.
    /// TODO: Use ProtocolVersion in TlsDetails and printTlsVersion().
    int toNumberXXX() const { return (vMajor << 8) | vMinor; }

    BinaryTokenizerContext context; ///< parsing context for debugging

    // the "v" prefix works around environments that #define major and minor
    uint8_t vMajor;
    uint8_t vMinor;
};

/// TLS Record Layer's frame from RFC 5246 Section 6.2.1.
struct TLSPlaintext
{
    explicit TLSPlaintext(BinaryTokenizer &tk);

    BinaryTokenizerContext context; ///< parsing context for debugging

    uint8_t type; ///< Rfc5246::ContentType
    ProtocolVersion version;
    uint16_t length;
    SBuf fragment; ///< exactly length bytes
};

/// draft-hickman-netscape-ssl-00. Section 4.1. SSL Record Header Format
struct Sslv2Record
{
    explicit Sslv2Record(BinaryTokenizer &tk);

    BinaryTokenizerContext context; ///< parsing context for debugging

    uint16_t length;
    SBuf fragment;
};

/// TLS Handshake protocol's handshake types from RFC 5246 Section 7.4
enum HandshakeType {
    hskClientHello = 1,
    hskServerHello = 2,
    hskCertificate = 11,
    hskServerHelloDone = 14
};

/// TLS Handshake Protocol frame from RFC 5246 Section 7.4.
struct Handshake
{
    explicit Handshake(BinaryTokenizer &tk);

    BinaryTokenizerContext context; ///< parsing context for debugging

    uint32_t msg_type: 8; ///< HandshakeType
    uint32_t length: 24;
    SBuf body; ///< Handshake Protocol message, exactly length bytes
};

/// TLS Alert protocol frame from RFC 5246 Section 7.2.
struct Alert
{
    explicit Alert(BinaryTokenizer &tk);


    bool fatal() const { return level == 2; }

    BinaryTokenizerContext context; ///< parsing context for debugging

    uint8_t level; ///< warning or fatal
    uint8_t description; ///< close_notify, unexpected_message, etc.
};

/// TLS Hello Extension from RFC 5246 Section 7.4.1.4.
struct Extension
{
    explicit Extension(BinaryTokenizer &tk);

    BinaryTokenizerContext context; ///< parsing context for debugging

    uint16_t type;
    uint16_t length; // XXX just use SBuf!
    SBuf body;
};

#define SQUID_TLS_RANDOM_SIZE 32

class TlsDetails: public RefCountable
{
public:
    typedef RefCount<TlsDetails> Pointer;

    TlsDetails();
    /// Prints to os stream a human readable form of TlsDetails object
    std::ostream & print(std::ostream &os) const;

    int tlsVersion; ///< The TLS hello message version
    int tlsSupportedVersion; ///< The requested/used TLS version
    int compressMethod; ///< The requested/used compressed  method
    SBuf serverName; ///< The SNI hostname, if any
    bool doHeartBeats;
    bool tlsTicketsExtension; ///< whether TLS tickets extension is enabled
    bool hasTlsTicket; ///< whether a TLS ticket is included
    bool tlsStatusRequest; ///< whether the TLS status request extension is set
    SBuf tlsAppLayerProtoNeg; ///< The value of the TLS application layer protocol extension if it is enabled
    /// The client random number
    SBuf clientRandom;
    SBuf sessionId;
    std::list<uint16_t> ciphers;
    std::list<uint16_t> extensions;
};

inline
std::ostream &operator <<(std::ostream &os, Security::TlsDetails const &details)
{
    return details.print(os);
}

/// Incremental SSL Handshake parser.
class HandshakeParser {
public:
    /// The parsing states
    typedef enum {atHelloNone = 0, atHelloStarted, atHelloReceived, atCertificatesReceived, atHelloDoneReceived, atNstReceived, atCcsReceived, atFinishReceived} ParserState;

    HandshakeParser();

    /// Parses the initial sequence of raw bytes sent by the SSL agent.
    /// Returns true upon successful completion (e.g., got HelloDone).
    /// Returns false if more data is needed.
    /// Throws on errors.
    bool parseHello(const SBuf &data);

    TlsDetails::Pointer details; ///< TLS handshake meta info or nil.

#if USE_OPENSSL
    Ssl::X509_STACK_Pointer serverCertificates; ///< parsed certificates chain
#endif

    ParserState state; ///< current parsing state.

    bool ressumingSession; ///< True if this is a resumming session

private:
    bool isSslv2Record(const SBuf &raw) const;
    void parseRecord();
    void parseModernRecord();
    void parseVersion2Record();
    void parseMessages();

    void parseChangeCipherCpecMessage();
    void parseAlertMessage();
    void parseHandshakeMessage();
    void parseApplicationDataMessage();
    void skipMessage(const char *msgType);

    bool parseRecordVersion2Try();
    void parseVersion2HandshakeMessage(const SBuf &raw);
    void parseClientHelloHandshakeMessage(const SBuf &raw);
    void parseServerHelloHandshakeMessage(const SBuf &raw);

    void parseExtensions(const SBuf &raw);
    SBuf parseSniExtension(const SBuf &extensionData) const;

    void parseCiphers(const SBuf &raw);
    void parseV23Ciphers(const SBuf &raw);

    void parseServerCertificates(const SBuf &raw);
#if USE_OPENSSL
    static X509 *ParseCertificate(const SBuf &raw);
#endif

    /* 
     * RFC 5246 Section 4.3: Variable-length vectors (a.k.a. prefix strings).
     * vectorN() returns raw post-length "contents" of vector<0..2^N-1>
     */
    SBuf pstring8(BinaryTokenizer &tk, const char *description) const;
    SBuf pstring16(BinaryTokenizer &tk, const char *description) const;
    SBuf pstring24(BinaryTokenizer &tk, const char *description) const;

    int parseProtocolVersion(BinaryTokenizer &tk) const;

    unsigned int currentContentType; ///< The current SSL record content type

    const char *done; ///< not nil iff we got what we were looking for

    /// concatenated TLSPlaintext.fragments of TLSPlaintext.type
    SBuf fragments;

    BinaryTokenizer tkRecords; // TLS record layer (parsing uninterpreted data)
    BinaryTokenizer tkMessages; // TLS message layer (parsing fragments)

    bool expectingModernRecords; // Whether to use TLS parser or a V2 compatible parser
};

}

#endif // SQUID_SECURITY_HANDSHAKE_H
