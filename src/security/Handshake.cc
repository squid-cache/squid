#include "squid.h"
#include "parser/BinaryTokenizer.h"
#include "security/Handshake.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

Security::FieldGroup::FieldGroup(BinaryTokenizer &tk, const char *description) {
    tk.context = description;
}

void
Security::FieldGroup::commit(BinaryTokenizer &tk) {
    tk.commit();
    tk.context = "";
}

Security::ProtocolVersion::ProtocolVersion(BinaryTokenizer &tk):
    vMajor(tk.uint8(".vMajor")),
    vMinor(tk.uint8(".vMinor"))
{
}

Security::TLSPlaintext::TLSPlaintext(BinaryTokenizer &tk):
    FieldGroup(tk, "TLSPlaintext"),
    type(tk.uint8(".type")),
    version(tk),
    length(tk.uint16(".length"))
{
    Must(version.vMajor == 3 && version.vMinor <= 3);
    Must(type >= ctChangeCipherSpec && type <= ctApplicationData);
    fragment = tk.area(length, ".fragment");
    commit(tk);
}

Security::Handshake::Handshake(BinaryTokenizer &tk):
    FieldGroup(tk, "Handshake"),
    msg_type(tk.uint8(".msg_type")),
    length(tk.uint24(".length")),
    body(tk.area(length, ".body"))
{
    commit(tk);
}

Security::Alert::Alert(BinaryTokenizer &tk):
    FieldGroup(tk, "Alert"),
    level(tk.uint8(".level")),
    description(tk.uint8(".description"))
{
    commit(tk);
}

Security::Extension::Extension(BinaryTokenizer &tk):
    FieldGroup(tk, "Extension"),
    type(tk.uint16(".type")),
    length(tk.uint16(".length")),
    body(tk.area(length, ".body"))
{
    commit(tk);
}

Security::Sslv2Record::Sslv2Record(BinaryTokenizer &tk):
    FieldGroup(tk, "Sslv2Record")
{
    const uint16_t head = tk.uint16(".head(Record+Length)");
    length = head & 0x7FFF;
    Must((head & 0x8000) && length); // SSLv2 message [without padding]
    version = 0x02;
    // The remained message has length of length-sizeof(type)=(length-1);
    fragment = tk.area(length, ".fragment");
    commit(tk);
}

Security::TlsDetails::TlsDetails():
    tlsVersion(-1),
    tlsSupportedVersion(-1),
    compressMethod(-1),
    doHeartBeats(true),
    tlsTicketsExtension(false),
    hasTlsTicket(false),
    tlsStatusRequest(false)
{
}

/// debugging helper to print various parsed records and messages
class DebugFrame
{
public:
    DebugFrame(const char *aName, uint64_t aType, uint64_t aSize):
        name(aName), type(aType), size(aSize) {}

    const char *name;
    uint64_t type;
    uint64_t size;
};

inline std::ostream &
operator <<(std::ostream &os, const DebugFrame &frame)
{
    return os << frame.size << "-byte type-" << frame.type << ' ' << frame.name;
}

/* Security::HandshakeParser */

Security::HandshakeParser::HandshakeParser():
    state(atHelloNone),
    ressumingSession(false),
    currentContentType(0),
    done(nullptr),
    expectingModernRecords(false)
{
}

void
Security::HandshakeParser::parseVersion2Record()
{
    const Sslv2Record record(tkRecords);
    Must(details);
    details->tlsVersion = record.version;
    parseVersion2HandshakeMessage(record.fragment);
    state = atHelloReceived;
    done = "SSL v2 Hello";
}

/// RFC 5246. Appendix E.2. Compatibility with SSL 2.0
/// And draft-hickman-netscape-ssl-00. Section 4.1 SSL Record Header Format
bool
Security::HandshakeParser::isSslv2Record(const SBuf &raw) const
{
    BinaryTokenizer tk(raw, true);
    const uint16_t head = tk.uint16("V2Hello.msg_length+");
    const uint8_t type = tk.uint8("V2Hello.msg_type");
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

    Must(record.length <= (1 << 14)); // RFC 5246: length MUST NOT exceed 2^14

    // RFC 5246: MUST NOT send zero-length [non-application] fragments
    Must(record.length || record.type == ContentType::ctApplicationData);

    details->tlsVersion = ((record.version.vMajor & 0xFF) << 8) | (record.version.vMinor & 0xFF);

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
    debugs(83, 7, DebugFrame("fragments", currentContentType, fragments.length()));
    while (!tkMessages.atEnd()) {
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
        skipMessage("unknown ContentType msg");
    }
}

void
Security::HandshakeParser::parseChangeCipherCpecMessage()
{
    Must(currentContentType == ContentType::ctChangeCipherSpec);
    // We are currently ignoring Change Cipher Spec Protocol messages.
    skipMessage("ChangeCipherCpec msg");
    
    // Everything after the ChangeCipherCpec message may be encrypted.
    // Continuing parsing is pointless. Stop here.
    ressumingSession = true;
    done = "ChangeCipherCpec";
}

void
Security::HandshakeParser::parseAlertMessage()
{
    Must(currentContentType == ContentType::ctAlert);
    const Alert alert(tkMessages);
    debugs(83, 3, "level " << alert.level << " description " << alert.description);
    // we are currently ignoring Alert Protocol messages
}

void
Security::HandshakeParser::parseHandshakeMessage()
{
    Must(currentContentType == ContentType::ctHandshake);

    const Handshake message(tkMessages);

    switch (message.msg_type) {
        case HandshakeType::hskClientHello:
            Must(state < atHelloReceived);
            Security::HandshakeParser::parseClientHelloHandshakeMessage(message.body);
            state = atHelloReceived;
            done = "ClientHello";
            return;
        case HandshakeType::hskServerHello:
            Must(state < atHelloReceived);
            parseServerHelloHandshakeMessage(message.body);
            state = atHelloReceived;
            return;
        case HandshakeType::hskCertificate:
            Must(state < atCertificatesReceived);
            parseServerCertificates(message.body);
            state = atCertificatesReceived;
            return;
        case HandshakeType::hskServerHelloDone:
            Must(state < atHelloDoneReceived);
            // zero-length
            state = atHelloDoneReceived;
            done = "ServerHelloDone";
            return;
    }
    debugs(83, 5, "ignoring " <<
           DebugFrame("handshake msg", message.msg_type, message.length));
}

void
Security::HandshakeParser::parseApplicationDataMessage()
{
    Must(currentContentType == ContentType::ctApplicationData);
    skipMessage("app data");
}

void
Security::HandshakeParser::parseVersion2HandshakeMessage(const SBuf &raw)
{
    BinaryTokenizer tkHsk(raw);
    Must(details);

    uint8_t type = tkHsk.uint8("type");
    Must(type == hskClientHello); // Only client hello supported.

    details->tlsSupportedVersion = tkHsk.uint16("tlsSupportedVersion");
    uint16_t ciphersLen = tkHsk.uint16(".cipherSpecLength");
    uint16_t sessionIdLen = tkHsk.uint16(".sessionIdLength");
    tkHsk.skip(sizeof(uint16_t), ".challengeLength");

    SBuf ciphers = tkHsk.area(ciphersLen, "Ciphers list");
    parseV23Ciphers(ciphers);
    details->sessionId = tkHsk.area(sessionIdLen, "Session Id");

    // tkHsk.skip(challengeLen, "Challenge");
}

void
Security::HandshakeParser::parseClientHelloHandshakeMessage(const SBuf &raw)
{
    BinaryTokenizer tkHsk(raw);
    Must(details);
    details->tlsSupportedVersion = tkHsk.uint16("tlsSupportedVersion");
    details->clientRandom = tkHsk.area(SQUID_TLS_RANDOM_SIZE, "Client Random");
    details->sessionId = pstring8(tkHsk, "Session ID");
    parseCiphers(pstring16(tkHsk, "Ciphers list"));
    details->compressMethod = pstring8(tkHsk, "Compression methods").length() > 0 ? 1 : 0; // Only deflate supported here.
    if (!tkHsk.atEnd()) // extension-free message ends here
        parseExtensions(pstring16(tkHsk, "Extensions List"));
}

void
Security::HandshakeParser::parseExtensions(const SBuf &raw)
{
    Must(details);
    BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        Extension extension(tk);
        details->extensions.push_back(extension.type);

        switch(extension.type) {
        case 0: // The SNI extension; RFC 6066, Section 3
            details->serverName = parseSniExtension(extension.body);
            break;
        case 5: // Certificate Status Request; RFC 6066, Section 8
            details->tlsStatusRequest = true;
            break;
        case 15: // The heartBeats, RFC 6520
            details->doHeartBeats = true;
            break;
        case 16: { // Application-Layer Protocol Negotiation Extension, RFC 7301
            BinaryTokenizer tkAPN(extension.body);
            details->tlsAppLayerProtoNeg = pstring16(tkAPN, "APN extension");
            break;
        }
        case 35: // SessionTicket TLS Extension; RFC 5077
            details->tlsTicketsExtension = true;
            if (extension.length)
                details->hasTlsTicket = true;
        case 13172: // Next Protocol Negotiation Extension (expired draft?)
        default:
            break;
        }
    }
}

void
Security::HandshakeParser::parseCiphers(const SBuf &raw)
{
    Must(details);
    BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        const uint16_t cipher = tk.uint16("cipher");
        details->ciphers.push_back(cipher);
    }
}

void
Security::HandshakeParser::parseV23Ciphers(const SBuf &raw)
{
    Must(details);
    BinaryTokenizer tk(raw);
    while (!tk.atEnd()) {
        // The v2 hello messages cipher has 3 bytes.
        // The v2 cipher has the first byte not null.
        // We support v3 messages only so we are ignoring v2 ciphers.
        const uint8_t prefix = tk.uint8("prefix");
        const uint16_t cipher = tk.uint16("cipher");
        if (prefix == 0)
            details->ciphers.push_back(cipher);
    }
}

void
Security::HandshakeParser::parseServerHelloHandshakeMessage(const SBuf &raw)
{
    BinaryTokenizer tkHsk(raw);
    Must(details);
    details->tlsSupportedVersion = tkHsk.uint16("tlsSupportedVersion");
    details->clientRandom = tkHsk.area(SQUID_TLS_RANDOM_SIZE, "Client Random");
    details->sessionId = pstring8(tkHsk, "Session ID");
    const uint16_t cipher = tkHsk.uint16("cipher");
    details->ciphers.push_back(cipher);
    const uint8_t compressionMethod = tkHsk.uint8("Compression method");
    details->compressMethod = compressionMethod > 0 ? 1 : 0; // Only deflate supported here.
    if (!tkHsk.atEnd()) // extensions present
        parseExtensions(pstring16(tkHsk, "Extensions List"));
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
    BinaryTokenizer tkList(extensionData);
    BinaryTokenizer tkNames(pstring16(tkList, "ServerNameList"));
    while (!tkNames.atEnd()) {
        const uint8_t nameType = tkNames.uint8("ServerName.name_type");
        const SBuf name = pstring16(tkNames, "ServerName.name");
        if (nameType == 0) {
            debugs(83, 3, "host_name=" << name);
            return name; // it may be empty
        }
        // else we just parsed a new/unsupported NameType which,
        // according to RFC 6066, MUST begin with a 16-bit length field
    }
    return SBuf(); // SNI present but contains no names
}

void
Security::HandshakeParser::skipMessage(const char *description)
{
    // tkMessages/fragments can only contain messages of the same ContentType.
    // To skip a message, we can and should skip everything we have [left]. If
    // we have partial messages, debugging will mislead about their boundaries.
    tkMessages.skip(tkMessages.leftovers().length(), description);
    tkMessages.commit();
}

bool
Security::HandshakeParser::parseHello(const SBuf &data)
{
    try {
        if (!details) {
            expectingModernRecords = !isSslv2Record(data);
            details = new TlsDetails; // after expectingModernRecords is known
        }

        // data contains everything read so far, but we may read more later
        tkRecords.reinput(data, true);
        tkRecords.rollback();
        while (!done)
            parseRecord();
        debugs(83, 7, "success; got: " << done);
        // we are done; tkRecords may have leftovers we are not interested in
        return true;
    }
    catch (const BinaryTokenizer::InsufficientInput &) {
        debugs(83, 5, "need more data");
        return false;
    }
    return false; // unreached
}

SBuf
Security::HandshakeParser::pstring8(BinaryTokenizer &tk, const char *description) const
{
    tk.context = description;
    const uint8_t length = tk.uint8(".length");
    const SBuf body = tk.area(length, ".body");
    tk.commit();
    tk.context = "";
    return body;
}

SBuf
Security::HandshakeParser::pstring16(BinaryTokenizer &tk, const char *description) const
{
    tk.context = description;
    const uint16_t length = tk.uint16(".length");
    const SBuf body = tk.area(length, ".body");
    tk.commit();
    tk.context = "";
    return body;
}

SBuf
Security::HandshakeParser::pstring24(BinaryTokenizer &tk, const char *description) const
{
    tk.context = description;
    const uint32_t length = tk.uint24(".length");
    const SBuf body = tk.area(length, ".body");
    tk.commit();
    tk.context = "";
    return body;
}

#if USE_OPENSSL
X509 *
Security::HandshakeParser::ParseCertificate(const SBuf &raw)
{
    typedef const unsigned char *x509Data;
    const x509Data x509Start = reinterpret_cast<x509Data>(raw.rawContent());
    x509Data x509Pos = x509Start;
    X509 *x509 = d2i_X509(nullptr, &x509Pos, raw.length());
    Must(x509); // successfully parsed
    Must(x509Pos == x509Start + raw.length()); // no leftovers
    return x509;
}

void
Security::HandshakeParser::parseServerCertificates(const SBuf &raw)
{
    BinaryTokenizer tkList(raw);
    const SBuf clist = pstring24(tkList, "CertificateList");
    Must(tkList.atEnd()); // no leftovers after all certificates

    BinaryTokenizer tkItems(clist);
    while (!tkItems.atEnd()) {
        X509 *cert = ParseCertificate(pstring24(tkItems, "Certificate"));
        if (!serverCertificates.get())
            serverCertificates.reset(sk_X509_new_null());
        sk_X509_push(serverCertificates.get(), cert);
        debugs(83, 7, "parsed " << sk_X509_num(serverCertificates.get()) << " certificates so far");
    }

}
#else
void
Security::HandshakeParser::parseServerCertificates(const SBuf &raw)
{
}
#endif
