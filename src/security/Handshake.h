/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SECURITY_HANDSHAKE_H
#define SQUID_SECURITY_HANDSHAKE_H

#include "anyp/ProtocolVersion.h"
#include "base/YesNoNone.h"
#include "parser/BinaryTokenizer.h"
#include "security/forward.h"

#include <unordered_set>

namespace Security
{

class TlsDetails: public RefCountable
{
public:
    typedef RefCount<TlsDetails> Pointer;

    TlsDetails();
    /// Prints to os stream a human readable form of TlsDetails object
    std::ostream & print(std::ostream &os) const;

    AnyP::ProtocolVersion tlsVersion; ///< The TLS hello message version

    /// For most compliant TLS v1.3+ agents, this is supported_versions maximum.
    /// For others agents, this is the legacy_version field.
    AnyP::ProtocolVersion tlsSupportedVersion;

    bool compressionSupported; ///< The requested/used compressed  method
    SBuf serverName; ///< The SNI hostname, if any
    bool doHeartBeats;
    bool tlsTicketsExtension; ///< whether TLS tickets extension is enabled
    bool hasTlsTicket; ///< whether a TLS ticket is included
    bool tlsStatusRequest; ///< whether the TLS status request extension is set
    bool unsupportedExtensions; ///< whether any unsupported by Squid extensions are used
    SBuf tlsAppLayerProtoNeg; ///< The value of the TLS application layer protocol extension if it is enabled
    /// The client random number
    SBuf clientRandom;
    SBuf sessionId;

    typedef std::unordered_set<uint16_t> Ciphers;
    Ciphers ciphers;
};

inline
std::ostream &operator <<(std::ostream &os, Security::TlsDetails const &details)
{
    return details.print(os);
}

/// Incremental TLS/SSL Handshake parser.
class HandshakeParser
{
public:
    /// The parsing states
    typedef enum { atHelloNone = 0, atHelloStarted, atHelloReceived, atHelloDoneReceived, atNstReceived, atCcsReceived, atFinishReceived } ParserState;

    /// the originator of the TLS handshake being parsed
    typedef enum { fromClient = 0, fromServer } MessageSource;

    explicit HandshakeParser(MessageSource);

    /// Parses the initial sequence of raw bytes sent by the TLS/SSL agent.
    /// Returns true upon successful completion (e.g., got HelloDone).
    /// Returns false if more data is needed.
    /// Throws on errors.
    bool parseHello(const SBuf &data);

    TlsDetails::Pointer details; ///< TLS handshake meta info. Never nil.

    ParserState state; ///< current parsing state.

    bool resumingSession; ///< True if this is a resuming session

    /// whether we are parsing Server or Client TLS handshake messages
    MessageSource messageSource;

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

    bool parseCompressionMethods(const SBuf &raw);
    void parseExtensions(const SBuf &raw);
    SBuf parseSniExtension(const SBuf &extensionData) const;
    void parseSupportedVersionsExtension(const SBuf &extensionData) const;

    void parseCiphers(const SBuf &raw);
    void parseV23Ciphers(const SBuf &raw);

    void parseServerCertificates(const SBuf &raw);

    unsigned int currentContentType; ///< The current TLS/SSL record content type

    const char *done; ///< not nil if we got what we were looking for

    /// concatenated TLSPlaintext.fragments of TLSPlaintext.type
    SBuf fragments;

    /// TLS record layer (parsing uninterpreted data)
    Parser::BinaryTokenizer tkRecords;

    /// TLS message layer (parsing fragments)
    Parser::BinaryTokenizer tkMessages;

    /// Whether to use TLS parser or a V2 compatible parser
    YesNoNone expectingModernRecords;
};

/// whether the given protocol belongs to the TLS/SSL group of protocols
inline bool
TlsFamilyProtocol(const AnyP::ProtocolVersion &version)
{
    return (version.protocol == AnyP::PROTO_TLS || version.protocol == AnyP::PROTO_SSL);
}

/// whether TLS/SSL protocol `a` precedes TLS/SSL protocol `b`
inline bool
TlsVersionEarlierThan(const AnyP::ProtocolVersion &a, const AnyP::ProtocolVersion &b)
{
    Must(TlsFamilyProtocol(a));
    Must(TlsFamilyProtocol(b));

    if (a.protocol == b.protocol)
        return a < b;

    return a.protocol == AnyP::PROTO_SSL; // implies that b is TLS
}

/// whether the given TLS/SSL protocol is TLS v1.2 or earlier, including SSL
inline bool
Tls1p2orEarlier(const AnyP::ProtocolVersion &p)
{
    return TlsVersionEarlierThan(p, AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 3));
}

/// whether the given TLS/SSL protocol is TLS v1.3 or later
inline bool
Tls1p3orLater(const AnyP::ProtocolVersion &p)
{
    return !Tls1p2orEarlier(p);
}

}

#endif // SQUID_SECURITY_HANDSHAKE_H

