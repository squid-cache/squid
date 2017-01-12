/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
    AnyP::ProtocolVersion tlsSupportedVersion; ///< The requested/used TLS version
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
    typedef enum {atHelloNone = 0, atHelloStarted, atHelloReceived, atCertificatesReceived, atHelloDoneReceived, atNstReceived, atCcsReceived, atFinishReceived} ParserState;

    HandshakeParser();

    /// Parses the initial sequence of raw bytes sent by the TLS/SSL agent.
    /// Returns true upon successful completion (e.g., got HelloDone).
    /// Returns false if more data is needed.
    /// Throws on errors.
    bool parseHello(const SBuf &data);

    TlsDetails::Pointer details; ///< TLS handshake meta info or nil.

    Security::CertList serverCertificates; ///< parsed certificates chain

    ParserState state; ///< current parsing state.

    bool resumingSession; ///< True if this is a resuming session

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

    void parseCiphers(const SBuf &raw);
    void parseV23Ciphers(const SBuf &raw);

    void parseServerCertificates(const SBuf &raw);
    static void ParseCertificate(const SBuf &raw, CertPointer &cert);

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

}

#endif // SQUID_SECURITY_HANDSHAKE_H

