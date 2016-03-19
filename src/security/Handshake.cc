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
    length(tk.uint16(".length")),
    fragment(tk.area(length, ".fragment"))
{
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

/// parses a single TLS Record Layer frame
void
Security::HandshakeParser::parseRecord()
{
    const TLSPlaintext record(tkRecords);

    Must(record.length <= (1 << 14)); // RFC 5246: length MUST NOT exceed 2^14

    // RFC 5246: MUST NOT send zero-length [non-application] fragments
    Must(record.length || record.type == ContentType::ctApplicationData);

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
        case HandshakeType::hskServerHello:
            Must(state < atHelloReceived);
            // TODO: Parse ServerHello in message.body; extract version/session
            // If the server is resuming a session, stop parsing w/o certificates
            // because all subsequent [Finished] messages will be encrypted, right?
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
#endif
