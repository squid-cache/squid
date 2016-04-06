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

Security::P24String::P24String(BinaryTokenizer &tk, const char *description):
    FieldGroup(tk, description),
    length(tk.uint24(".length")),
    body(tk.area(length, ".body"))
{
    commit(tk);
}

Security::P16String::P16String(BinaryTokenizer &tk, const char *description):
    FieldGroup(tk, description),
    length(tk.uint16(".length")),
    body(tk.area(length, ".body"))
{
    commit(tk);
}

Security::P8String::P8String(BinaryTokenizer &tk, const char *description):
    FieldGroup(tk, description),
    length(tk.uint8(".length")),
    body(tk.area(length, ".body"))
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
    uint16_t head = tk.uint16(".head(Record+Length)");
    length = head & 0x7FFF;
    if ((head & 0x8000) == 0 || length == 0)
        throw TexcHere("Not an SSLv2 message");
    version = 0x02;
    // The remained message has length of length-sizeof(type)=(length-1);
    fragment = tk.area(length, ".fragment");
    commit(tk);
}

//The SNI extension has the type 0 (extType == 0)
// RFC6066 sections 3, 10.2
// The two first bytes indicates the length of the SNI data
// The next byte is the hostname type, it should be '0' for normal hostname
// The 3rd and 4th bytes are the length of the hostname
Security::SniExtension::SniExtension(BinaryTokenizer &tk):
    FieldGroup(tk, "Sni"),
    listLength(tk.uint16(".listLength")),
    type(tk.uint8(".type"))
{
    if (type == 0) {
        P16String aName(tk, ".serverName");
        serverName = aName.body;
    } else
        tk.skip(listLength - 1, ".unknownType");
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

void
Security::HandshakeParser::parseVersion2Record()
{
    const Sslv2Record record(tkRecords);
    Must(details);
    details->tlsVersion = record.version;
    parseVersion2HandshakeMessage(record.fragment);
    state = atHelloReceived;
    parseDone = true;
}

bool
Security::HandshakeParser::isSslv2Record()
{
    uint16_t head = tkRecords.uint16(".head(Record+Length)");
    uint16_t length = head & 0x7FFF;
    uint8_t type = tkRecords.uint8(".type");
    tkRecords.rollback();
    if ((head & 0x8000) == 0 || length == 0 || type != 0x01)
        return false;
    // It is an SSLv2 Client Hello Message
    return true;
}

void
Security::HandshakeParser::parseRecord()
{
    if (details == NULL) {
        details = new TlsDetails;
        expectingModernRecords = !isSslv2Record();
    }

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

    details->tlsVersion = (record.version.vMajor & 0xFF) << 8 | (record.version.vMinor & 0xFF);

    if (currentContentType != record.type) {
        Must(tkMessages.atEnd()); // no currentContentType leftovers
        fragments = record.fragment;
        tkMessages.reset(fragments);
        currentContentType = record.type;
    } else {
        fragments.append(record.fragment);
        tkMessages.reinput(fragments);
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
    // we are currently ignoring Change Cipher Spec Protocol messages
    // Everything after this message may be is encrypted
    // The continuing parsing is pointless, abort here and set parseDone
    skipMessage("ChangeCipherCpec msg");
    ressumingSession = true;
    parseDone = true;
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
            parseDone = true;
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
            parseDone = true;
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
    uint16_t challengeLen = tkHsk.uint16(".challengeLength");

    SBuf ciphers = tkHsk.area(ciphersLen, "Ciphers list");
    parseV23Ciphers(ciphers);
    details->sessionId = tkHsk.area(sessionIdLen, "Session Id");

    // We do not actually need it:
    SBuf challenge = tkHsk.area(challengeLen, "Challenge");
}

void
Security::HandshakeParser::parseClientHelloHandshakeMessage(const SBuf &raw)
{
    BinaryTokenizer tkHsk(raw);
    Must(details);

    details->tlsSupportedVersion = tkHsk.uint16("tlsSupportedVersion");
    details->clientRandom = tkHsk.area(SQUID_TLS_RANDOM_SIZE, "Client Random");
    P8String session(tkHsk, "Session ID");
    details->sessionId = session.body;
    P16String ciphers(tkHsk, "Ciphers list");
    parseCiphers(ciphers.body);
    P8String compression(tkHsk, "Compression methods");
    details->compressMethod = compression.length > 0 ? 1 : 0; // Only deflate supported here.
    if (!tkHsk.atEnd()) { //Then we have extensions
        P16String extensions(tkHsk, "Extensions List");
        parseExtensions(extensions.body);
    }
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
        case 0: { //The SNI extension, RFC6066 sections 3, 10.2
            BinaryTokenizer tkSNI(extension.body);
            SniExtension sni(tkSNI);
            details->serverName = sni.serverName;
        }
            break;
        case 5: // RFC6066 sections 8, 10.2
            details->tlsStatusRequest = true;
            break;
        case 15:// The heartBeats, RFC6520
            details->doHeartBeats = true;
            break;
        case 16: { // Application-Layer Protocol Negotiation Extension, RFC7301
            BinaryTokenizer tkAPN(extension.body);
            P16String apn(tkAPN, "APN extension");
            details->tlsAppLayerProtoNeg = apn.body;
        }
            break;
        case 35: //SessionTicket TLS Extension RFC5077
            details->tlsTicketsExtension = true;
            if (extension.length)
                details->hasTlsTicket = true;
        case 13172: //Next Protocol Negotiation Extension, (expired draft?)
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
        // The v2 cipher has the first byte not null
        // We are supporting only v3 message so we
        // are ignoring v2 ciphers
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
#if 0  // Always retrieve details, enough fast operation
    if (::Config.onoff.logTlsServerHelloDetails) {
#endif
        details->tlsSupportedVersion = tkHsk.uint16("tlsSupportedVersion");
        tkHsk.commit();
        details->clientRandom = tkHsk.area(SQUID_TLS_RANDOM_SIZE, "Client Random");
        tkHsk.commit();
        P8String session(tkHsk, "Session ID");
        details->sessionId = session.body;
        P16String extensions(tkHsk, "Extensions List");
        parseExtensions(extensions.body);
#if 0
    }
#endif
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

/// parseServerHelloTry() wrapper that maintains parseDone/parseError state
bool
Security::HandshakeParser::parseServerHello(const SBuf &data)
{
    try {
        tkRecords.reinput(data); // data contains _everything_ read so far
        tkRecords.rollback();
        while (!tkRecords.atEnd() && !parseDone)
            parseRecord();
        debugs(83, 7, "success; done: " << parseDone);
        return parseDone;
    }
    catch (const BinaryTokenizer::InsufficientInput &) {
        debugs(83, 5, "need more data");
        Must(!parseError);
    }
    catch (const std::exception &ex) {
        debugs(83, 2, "parsing error: " << ex.what());
        parseError = true;
    }
    return false;
}

bool
Security::HandshakeParser::parseClientHello(const SBuf &data)
{
    try {
        tkRecords.reinput(data); // data contains _everything_ read so far
        tkRecords.rollback();
        while (!tkRecords.atEnd() && !parseDone)
            parseRecord();
        debugs(83, 7, "success; done: " << parseDone);
        return parseDone;
    }
    catch (const BinaryTokenizer::InsufficientInput &) {
        debugs(83, 5, "need more data");
        Must(!parseError);
    }
    catch (const std::exception &ex) {
        debugs(83, 2, "parsing error: " << ex.what());
        parseError = true;
    }
    return false;
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
    const P24String list(tkList, "CertificateList");
    Must(tkList.atEnd()); // no leftovers after all certificates

    BinaryTokenizer tkItems(list.body);
    while (!tkItems.atEnd()) {
        const P24String item(tkItems, "Certificate");
        X509 *cert = ParseCertificate(item.body);
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
