/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL-Bump Server/Peer negotiation */

#include "squid.h"
#include "security/Handshake.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <unordered_set>

namespace Security {
/*
 * The types below represent various SSL and TLS protocol elements. Most names
 * are based on RFC 5264 and RFC 6066 terminology. Objects of these explicit
 * types are stored or passed around. Other protocol elements are simply parsed
 * in-place, without declaring a corresponding explicit class.
 */

/// TLS Record Layer's content types from RFC 5246 Section 6.2.1
enum ContentType {
    ctChangeCipherSpec = 20,
    ctAlert = 21,
    ctHandshake = 22,
    ctApplicationData = 23
};

/// TLS Record Layer's frame from RFC 5246 Section 6.2.1.
class TLSPlaintext
{
public:
    explicit TLSPlaintext(Parser::BinaryTokenizer &tk);

    uint8_t type; ///< see ContentType
    AnyP::ProtocolVersion version; ///< Record Layer, not necessarily the negotiated TLS version;
    SBuf fragment; ///< possibly partial content
};

/// draft-hickman-netscape-ssl-00. Section 4.1. SSL Record Header Format
class Sslv2Record
{
public:
    explicit Sslv2Record(Parser::BinaryTokenizer &tk);

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
class Handshake
{
public:
    explicit Handshake(Parser::BinaryTokenizer &tk);

    uint8_t msg_type; ///< see HandshakeType
    SBuf msg_body; ///< Handshake Protocol message
};

/// TLS Alert protocol frame from RFC 5246 Section 7.2.
class Alert
{
public:
    explicit Alert(Parser::BinaryTokenizer &tk);

    bool fatal() const { return level == 2; }

    uint8_t level; ///< warning or fatal
    uint8_t description; ///< close_notify, unexpected_message, etc.
};

/// The size of the TLS Random structure from RFC 5246 Section 7.4.1.2.
static const uint64_t HelloRandomSize = 32;

/// TLS Hello Extension from RFC 5246 Section 7.4.1.4.
class Extension
{
public:
    typedef uint16_t Type;
    explicit Extension(Parser::BinaryTokenizer &tk);

    /// whether this extension is supported by Squid and, hence, may be bumped
    /// after peeking or spliced after staring (subject to other restrictions)
    bool supported() const;

    Type type;
    SBuf data;
};

/// Extension types optimized for fast lookups.
typedef std::unordered_set<Extension::Type> Extensions;
static Extensions SupportedExtensions();

} // namespace Security

/// Convenience helper: We parse ProtocolVersion but store "int".
static AnyP::ProtocolVersion
ParseProtocolVersion(Parser::BinaryTokenizer &tk)
{
    Parser::BinaryTokenizerContext context(tk, ".version");
    uint8_t vMajor = tk.uint8(".major");
    uint8_t vMinor = tk.uint8(".minor");
    if (vMajor == 0 && vMinor == 2)
        return AnyP::ProtocolVersion(AnyP::PROTO_SSL, 2, 0);

    Must(vMajor == 3);
    if (vMinor == 0)
        return AnyP::ProtocolVersion(AnyP::PROTO_SSL, 3, 0);

    return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, (vMinor - 1));
}

Security::TLSPlaintext::TLSPlaintext(Parser::BinaryTokenizer &tk)
{
    Parser::BinaryTokenizerContext context(tk, "TLSPlaintext");
    type = tk.uint8(".type");
    Must(type >= ctChangeCipherSpec && type <= ctApplicationData);
    version = ParseProtocolVersion(tk);
    // TODO: Must(version.major == 3);
    fragment = tk.pstring16(".fragment");
    context.success();
}

Security::Handshake::Handshake(Parser::BinaryTokenizer &tk)
{
    Parser::BinaryTokenizerContext context(tk, "Handshake");
    msg_type = tk.uint8(".msg_type");
    msg_body = tk.pstring24(".msg_body");
    context.success();
}

Security::Alert::Alert(Parser::BinaryTokenizer &tk)
{
    Parser::BinaryTokenizerContext context(tk, "Alert");
    level = tk.uint8(".level");
    description = tk.uint8(".description");
    context.success();
}

Security::Extension::Extension(Parser::BinaryTokenizer &tk)
{
    Parser::BinaryTokenizerContext context(tk, "Extension");
    type = tk.uint16(".type");
    data = tk.pstring16(".data");
    context.success();
}

bool
Security::Extension::supported() const
{
    static const Extensions supportedExtensions = SupportedExtensions();
    return supportedExtensions.find(type) != supportedExtensions.end();
}

Security::Sslv2Record::Sslv2Record(Parser::BinaryTokenizer &tk)
{
    Parser::BinaryTokenizerContext context(tk, "Sslv2Record");
    const uint16_t head = tk.uint16(".head");
    const uint16_t length = head & 0x7FFF;
    Must((head & 0x8000) && length); // SSLv2 message [without padding]
    fragment = tk.area(length, ".fragment");
    context.success();
}

Security::TlsDetails::TlsDetails():
    compressionSupported(false),
    doHeartBeats(false),
    tlsTicketsExtension(false),
    hasTlsTicket(false),
    tlsStatusRequest(false),
    unsupportedExtensions(false)
{
}

/* Security::HandshakeParser */

Security::HandshakeParser::HandshakeParser():
    details(new TlsDetails),
    state(atHelloNone),
    resumingSession(false),
    currentContentType(0),
    done(nullptr),
    expectingModernRecords(false)
{
}

void
Security::HandshakeParser::parseVersion2Record()
{
    const Sslv2Record record(tkRecords);
    tkRecords.commit();
    details->tlsVersion = AnyP::ProtocolVersion(AnyP::PROTO_SSL, 2, 0);
    parseVersion2HandshakeMessage(record.fragment);
    state = atHelloReceived;
    done = "SSLv2";
}

/// RFC 5246. Appendix E.2. Compatibility with SSL 2.0
/// And draft-hickman-netscape-ssl-00. Section 4.1. SSL Record Header Format
bool
Security::HandshakeParser::isSslv2Record(const SBuf &raw) const
{
    Parser::BinaryTokenizer tk(raw, true);
    const uint16_t head = tk.uint16("?v2Hello.msg_head");
    const uint8_t type = tk.uint8("?v2Hello.msg_type");
    const uint16_t length = head & 0x7FFF;
    return (head & 0x8000) && length && type == 1;
}

void
Security::HandshakeParser::parseRecord()
{
    if (expectingModernRecords)
        parseModernRecord();
    else
        parseVersion2Record();
}

/// parses a single TLS Record Layer frame
void
Security::HandshakeParser::parseModernRecord()
{
    const TLSPlaintext record(tkRecords);
    tkRecords.commit();

    details->tlsVersion = record.version;

    // RFC 5246: length MUST NOT exceed 2^14
    Must(record.fragment.length() <= (1 << 14));
    // RFC 5246: MUST NOT send zero-length [non-application] fragments
    Must(record.fragment.length() || record.type == ContentType::ctApplicationData);

    if (currentContentType != record.type) {
        Must(tkMessages.atEnd()); // no currentContentType leftovers
        fragments = record.fragment;
        tkMessages.reset(fragments, true); // true because more fragments may come
        currentContentType = record.type;
    } else {
        fragments.append(record.fragment);
        tkMessages.reinput(fragments, true); // true because more fragments may come
        tkMessages.rollback();
    }
    parseMessages();
}

/// parses one or more "higher-level protocol" frames of currentContentType
void
Security::HandshakeParser::parseMessages()
{
    for (; !tkMessages.atEnd(); tkMessages.commit()) {
        switch (currentContentType) {
        case ContentType::ctChangeCipherSpec:
            parseChangeCipherCpecMessage();
            continue;
        case ContentType::ctAlert:
            parseAlertMessage();
            continue;
        case ContentType::ctHandshake:
            parseHandshakeMessage();
            continue;
        case ContentType::ctApplicationData:
            parseApplicationDataMessage();
            continue;
        }
        skipMessage("unknown ContentType msg [fragment]");
    }
}

void
Security::HandshakeParser::parseChangeCipherCpecMessage()
{
    Must(currentContentType == ContentType::ctChangeCipherSpec);
    // We are currently ignoring Change Cipher Spec Protocol messages.
    skipMessage("ChangeCipherCpec msg [fragment]");

    // Everything after the ChangeCipherCpec message may be encrypted.
    // Continuing parsing is pointless. Stop here.
    resumingSession = true;
    done = "ChangeCipherCpec";
}

void
Security::HandshakeParser::parseAlertMessage()
{
    Must(currentContentType == ContentType::ctAlert);
    const Alert alert(tkMessages);
    debugs(83, (alert.fatal() ? 2:3),
           "level " << static_cast<int>(alert.level) <<
           " description " << static_cast<int>(alert.description));
    if (alert.fatal())
        done = "fatal Alert";
    // else ignore the warning (at least for now)
}

void
Security::HandshakeParser::parseHandshakeMessage()
{
    Must(currentContentType == ContentType::ctHandshake);

    const Handshake message(tkMessages);

    switch (message.msg_type) {
    case HandshakeType::hskClientHello:
        Must(state < atHelloReceived);
        Security::HandshakeParser::parseClientHelloHandshakeMessage(message.msg_body);
        state = atHelloReceived;
        done = "ClientHello";
        return;
    case HandshakeType::hskServerHello:
        Must(state < atHelloReceived);
        parseServerHelloHandshakeMessage(message.msg_body);
        state = atHelloReceived;
        return;
    case HandshakeType::hskCertificate:
        Must(state < atCertificatesReceived);
        parseServerCertificates(message.msg_body);
        state = atCertificatesReceived;
        return;
    case HandshakeType::hskServerHelloDone:
        Must(state < atHelloDoneReceived);
        // zero-length
        state = atHelloDoneReceived;
        done = "ServerHelloDone";
        return;
    }
    debugs(83, 5, "ignoring " << message.msg_body.length() << "-byte type-" <<
           static_cast<unsigned int>(message.msg_type) << " handshake message");
}

void
Security::HandshakeParser::parseApplicationDataMessage()
{
    Must(currentContentType == ContentType::ctApplicationData);
    skipMessage("app data [fragment]");
}

void
Security::HandshakeParser::parseVersion2HandshakeMessage(const SBuf &raw)
{
    Parser::BinaryTokenizer tk(raw);
    Parser::BinaryTokenizerContext hello(tk, "V2ClientHello");
    Must(tk.uint8(".type") == hskClientHello); // Only client hello supported.
    details->tlsSupportedVersion = ParseProtocolVersion(tk);
    const uint16_t ciphersLen = tk.uint16(".cipher_specs.length");
    const uint16_t sessionIdLen = tk.uint16(".session_id.length");
    const uint16_t challengeLen = tk.uint16(".challenge.length");
    parseV23Ciphers(tk.area(ciphersLen, ".cipher_specs.body"));
    details->sessionId = tk.area(sessionIdLen, ".session_id.body");
    tk.skip(challengeLen, ".challenge.body");
    hello.success();
}

void
Security::HandshakeParser::parseClientHelloHandshakeMessage(const SBuf &raw)
{
    Parser::BinaryTokenizer tk(raw);
    Parser::BinaryTokenizerContext hello(tk, "ClientHello");
    details->tlsSupportedVersion = ParseProtocolVersion(tk);
    details->clientRandom = tk.area(HelloRandomSize, ".random");
    details->sessionId = tk.pstring8(".session_id");
    parseCiphers(tk.pstring16(".cipher_suites"));
    details->compressionSupported = parseCompressionMethods(tk.pstring8(".compression_methods"));
    if (!tk.atEnd()) // extension-free message ends here
        parseExtensions(tk.pstring16(".extensions"));
    hello.success();
}

bool
Security::HandshakeParser::parseCompressionMethods(const SBuf &raw)
{
    if (raw.length() == 0)
        return false;
    Parser::BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        // Probably here we should check for DEFLATE(1) compression method
        // which is the only supported by openSSL subsystem.
        if (tk.uint8("compression_method") != 0)
            return true;
    }
    return false;
}

void
Security::HandshakeParser::parseExtensions(const SBuf &raw)
{
    Parser::BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        Extension extension(tk);

        if (!details->unsupportedExtensions && !extension.supported()) {
            debugs(83, 5, "first unsupported extension: " << extension.type);
            details->unsupportedExtensions = true;
        }

        switch(extension.type) {
        case 0: // The SNI extension; RFC 6066, Section 3
            details->serverName = parseSniExtension(extension.data);
            break;
        case 5: // Certificate Status Request; RFC 6066, Section 8
            details->tlsStatusRequest = true;
            break;
        case 15: // The heartBeats, RFC 6520
            details->doHeartBeats = true;
            break;
        case 16: { // Application-Layer Protocol Negotiation Extension, RFC 7301
            Parser::BinaryTokenizer tkAPN(extension.data);
            details->tlsAppLayerProtoNeg = tkAPN.pstring16("APN");
            break;
        }
        case 35: // SessionTicket TLS Extension; RFC 5077
            details->tlsTicketsExtension = true;
            details->hasTlsTicket = !extension.data.isEmpty();
        case 13172: // Next Protocol Negotiation Extension (expired draft?)
        default:
            break;
        }
    }
}

void
Security::HandshakeParser::parseCiphers(const SBuf &raw)
{
    details->ciphers.reserve(raw.length() / sizeof(uint16_t));
    Parser::BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        const uint16_t cipher = tk.uint16("cipher");
        details->ciphers.insert(cipher);
    }
}

void
Security::HandshakeParser::parseV23Ciphers(const SBuf &raw)
{
    Parser::BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        // RFC 6101 Appendix E, RFC 5246 Appendix E2
        // Unlike TLS, ciphers in SSLv23 Hellos are 3 bytes long and come in
        // two versions: v2 and v3. The two versions may co-exist in a single
        // SSLv23 Hello. Only v3 ciphers have a first byte value of zero.
        // The ciphers are needed for our peeking/staring code that
        // does not support SSLv2, so we ignore v2 ciphers.
        const uint8_t prefix = tk.uint8("prefix");
        const uint16_t cipher = tk.uint16("cipher");
        if (prefix == 0)
            details->ciphers.insert(cipher);
    }
}

/// RFC 5246 Section 7.4.1.3. Server Hello
void
Security::HandshakeParser::parseServerHelloHandshakeMessage(const SBuf &raw)
{
    Parser::BinaryTokenizer tk(raw);
    Parser::BinaryTokenizerContext hello(tk, "ServerHello");
    details->tlsSupportedVersion = ParseProtocolVersion(tk);
    tk.skip(HelloRandomSize, ".random");
    details->sessionId = tk.pstring8(".session_id");
    details->ciphers.insert(tk.uint16(".cipher_suite"));
    details->compressionSupported = tk.uint8(".compression_method") != 0; // not null
    if (!tk.atEnd()) // extensions present
        parseExtensions(tk.pstring16(".extensions"));
    hello.success();
}

// RFC 6066 Section 3: ServerNameList (may be sent by both clients and servers)
SBuf
Security::HandshakeParser::parseSniExtension(const SBuf &extensionData) const
{
    // Servers SHOULD send an empty SNI extension, not an empty ServerNameList!
    if (extensionData.isEmpty())
        return SBuf();

    // SNI MUST NOT contain more than one name of the same name_type but
    // we ignore violations and simply return the first host name found.
    Parser::BinaryTokenizer tkList(extensionData);
    Parser::BinaryTokenizer tkNames(tkList.pstring16("ServerNameList"));
    while (!tkNames.atEnd()) {
        Parser::BinaryTokenizerContext serverName(tkNames, "ServerName");
        const uint8_t nameType = tkNames.uint8(".name_type");
        const SBuf name = tkNames.pstring16(".name");
        serverName.success();

        if (nameType == 0) {
            debugs(83, 3, "host_name=" << name);
            return name; // it may be empty
        }
        // else we just parsed a new/unsupported NameType which,
        // according to RFC 6066, MUST begin with a 16-bit length field
    }
    return SBuf(); // SNI extension lacks host_name
}

void
Security::HandshakeParser::skipMessage(const char *description)
{
    // tkMessages/fragments can only contain messages of the same ContentType.
    // To skip a message, we can and should skip everything we have [left]. If
    // we have partial messages, debugging will mislead about their boundaries.
    tkMessages.skip(tkMessages.leftovers().length(), description);
}

bool
Security::HandshakeParser::parseHello(const SBuf &data)
{
    try {
        if (!expectingModernRecords.configured())
            expectingModernRecords.configure(!isSslv2Record(data));

        // data contains everything read so far, but we may read more later
        tkRecords.reinput(data, true);
        tkRecords.rollback();
        while (!done)
            parseRecord();
        debugs(83, 7, "success; got: " << done);
        // we are done; tkRecords may have leftovers we are not interested in
        return true;
    }
    catch (const Parser::BinaryTokenizer::InsufficientInput &) {
        debugs(83, 5, "need more data");
        return false;
    }
    return false; // unreached
}

/// Creates and returns a certificate by parsing a DER-encoded X509 structure.
/// Throws on failures.
Security::CertPointer
Security::HandshakeParser::ParseCertificate(const SBuf &raw)
{
    Security::CertPointer pCert;
#if USE_OPENSSL
    auto x509Start = reinterpret_cast<const unsigned char *>(raw.rawContent());
    auto x509Pos = x509Start;
    X509 *x509 = d2i_X509(nullptr, &x509Pos, raw.length());
    pCert.resetWithoutLocking(x509);
    Must(x509); // successfully parsed
    Must(x509Pos == x509Start + raw.length()); // no leftovers
#else
    assert(false);  // this code should never be reached
    pCert = Security::CertPointer(nullptr); // avoid warnings about uninitialized pCert; XXX: Fix CertPoint declaration.
    (void)raw; // avoid warnings about unused method parameter; TODO: Add a SimulateUse() macro.
#endif
    assert(pCert);
    return pCert;
}

void
Security::HandshakeParser::parseServerCertificates(const SBuf &raw)
{
#if USE_OPENSSL
    Parser::BinaryTokenizer tkList(raw);
    const SBuf clist = tkList.pstring24("CertificateList");
    Must(tkList.atEnd()); // no leftovers after all certificates

    Parser::BinaryTokenizer tkItems(clist);
    while (!tkItems.atEnd()) {
        if (Security::CertPointer cert = ParseCertificate(tkItems.pstring24("Certificate")))
            serverCertificates.push_back(cert);
        debugs(83, 7, "parsed " << serverCertificates.size() << " certificates so far");
    }
#else
    debugs(83, 7, "no support for CertificateList parsing; ignoring " << raw.length() << " bytes");
#endif
}

/// A helper function to create a set of all supported TLS extensions
static
Security::Extensions
Security::SupportedExtensions()
{
#if USE_OPENSSL

    // optimize lookup speed by reserving the number of values x3, approximately
    Security::Extensions extensions(64);

    // Keep this list ordered and up to date by running something like
    // egrep '# *define TLSEXT_TYPE_' /usr/include/openssl/tls1.h
    // TODO: Teach OpenSSL to return the list of extensions it supports.
#if defined(TLSEXT_TYPE_server_name) // 0
    extensions.insert(TLSEXT_TYPE_server_name);
#endif
#if defined(TLSEXT_TYPE_max_fragment_length) // 1
    extensions.insert(TLSEXT_TYPE_max_fragment_length);
#endif
#if defined(TLSEXT_TYPE_client_certificate_url) // 2
    extensions.insert(TLSEXT_TYPE_client_certificate_url);
#endif
#if defined(TLSEXT_TYPE_trusted_ca_keys) // 3
    extensions.insert(TLSEXT_TYPE_trusted_ca_keys);
#endif
#if defined(TLSEXT_TYPE_truncated_hmac) // 4
    extensions.insert(TLSEXT_TYPE_truncated_hmac);
#endif
#if defined(TLSEXT_TYPE_status_request) // 5
    extensions.insert(TLSEXT_TYPE_status_request);
#endif
#if defined(TLSEXT_TYPE_user_mapping) // 6
    extensions.insert(TLSEXT_TYPE_user_mapping);
#endif
#if defined(TLSEXT_TYPE_client_authz) // 7
    extensions.insert(TLSEXT_TYPE_client_authz);
#endif
#if defined(TLSEXT_TYPE_server_authz) // 8
    extensions.insert(TLSEXT_TYPE_server_authz);
#endif
#if defined(TLSEXT_TYPE_cert_type) // 9
    extensions.insert(TLSEXT_TYPE_cert_type);
#endif
#if defined(TLSEXT_TYPE_elliptic_curves) // 10
    extensions.insert(TLSEXT_TYPE_elliptic_curves);
#endif
#if defined(TLSEXT_TYPE_ec_point_formats) // 11
    extensions.insert(TLSEXT_TYPE_ec_point_formats);
#endif
#if defined(TLSEXT_TYPE_srp) // 12
    extensions.insert(TLSEXT_TYPE_srp);
#endif
#if defined(TLSEXT_TYPE_signature_algorithms) // 13
    extensions.insert(TLSEXT_TYPE_signature_algorithms);
#endif
#if defined(TLSEXT_TYPE_use_srtp) // 14
    extensions.insert(TLSEXT_TYPE_use_srtp);
#endif
#if defined(TLSEXT_TYPE_heartbeat) // 15
    extensions.insert(TLSEXT_TYPE_heartbeat);
#endif
#if defined(TLSEXT_TYPE_session_ticket) // 35
    extensions.insert(TLSEXT_TYPE_session_ticket);
#endif
#if defined(TLSEXT_TYPE_renegotiate) // 0xff01
    extensions.insert(TLSEXT_TYPE_renegotiate);
#endif
#if defined(TLSEXT_TYPE_next_proto_neg) // 13172
    extensions.insert(TLSEXT_TYPE_next_proto_neg);
#endif

    /*
     * OpenSSL does not support these last extensions by default, but those
     * building the OpenSSL libraries and/or Squid might define them.
     */

    // OpenSSL may be built to support draft-rescorla-tls-opaque-prf-input-00,
    // with the extension type value configured at build time. OpenSSL, Squid,
    // and TLS agents must all be built with the same extension type value.
#if defined(TLSEXT_TYPE_opaque_prf_input)
    extensions.insert(TLSEXT_TYPE_opaque_prf_input);
#endif

    // Define this to add extensions supported by your OpenSSL but unknown to
    // your Squid version. Use {list-initialization} to add multiple extensions.
#if defined(TLSEXT_TYPE_SUPPORTED_BY_MY_SQUID)
    extensions.insert(TLSEXT_TYPE_SUPPORTED_BY_MY_SQUID);
#endif

    return extensions; // might be empty
#else

    return Extensions(); // no extensions are supported without OpenSSL
#endif
}

