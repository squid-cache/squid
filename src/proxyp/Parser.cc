/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "parser/BinaryTokenizer.h"
#include "parser/Tokenizer.h"
#include "proxyp/Elements.h"
#include "proxyp/Header.h"
#include "proxyp/Parser.h"
#include "sbuf/Stream.h"

#include <algorithm>
#include <limits>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

namespace ProxyProtocol {
namespace One {
/// magic octet prefix for PROXY protocol version 1
static const SBuf Magic("PROXY", 5);
/// extracts PROXY protocol v1 header from the given buffer
static Parsed Parse(const SBuf &buf);

static void ExtractIp(Parser::Tokenizer &tok, Ip::Address &addr);
static void ExtractPort(Parser::Tokenizer &tok, Ip::Address &addr, const bool trailingSpace);
static void ParseAddresses(Parser::Tokenizer &tok, Header::Pointer &header);
}

namespace Two {
/// magic octet prefix for PROXY protocol version 2
static const SBuf Magic("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
/// extracts PROXY protocol v2 header from the given buffer
static Parsed Parse(const SBuf &buf);

static void ParseAddresses(const uint8_t family, Parser::BinaryTokenizer &tok, Header::Pointer &header);
static void ParseTLVs(Parser::BinaryTokenizer &tok, Header::Pointer &header);
}
}

void
ProxyProtocol::One::ExtractIp(Parser::Tokenizer &tok, Ip::Address &addr)
{
    static const auto ipChars = CharacterSet("IP Address",".:") + CharacterSet::HEXDIG;

    SBuf ip;

    if (!tok.prefix(ip, ipChars))
        throw TexcHere("PROXY/1.0 error: malformed IP address");

    if (!tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: garbage after IP address");

    if (!addr.GetHostByName(ip.c_str()))
        throw TexcHere("PROXY/1.0 error: invalid IP address");

}

void
ProxyProtocol::One::ExtractPort(Parser::Tokenizer &tok, Ip::Address &addr, const bool trailingSpace)
{
    int64_t port = -1;

    if (!tok.int64(port, 10, false))
        throw TexcHere("PROXY/1.0 error: malformed port");

    if (trailingSpace && !tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: garbage after port");

    if (port > std::numeric_limits<uint16_t>::max())
        throw TexcHere("PROXY/1.0 error: invalid port");

    addr.port(static_cast<uint16_t>(port));
}

void
ProxyProtocol::One::ParseAddresses(Parser::Tokenizer &tok, Header::Pointer &header)
{
    static const CharacterSet addressFamilies("Address family", "46");
    SBuf parsedAddressFamily;

    if (!tok.prefix(parsedAddressFamily, addressFamilies, 1))
        throw TexcHere("PROXY/1.0 error: missing or invalid IP address family");

    if (!tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: missing SP after the IP address family");

    // parse: src-IP SP dst-IP SP src-port SP dst-port
    ExtractIp(tok, header->sourceAddress);
    ExtractIp(tok, header->destinationAddress);

    if (header->addressFamily() != parsedAddressFamily)
        throw TexcHere("PROXY/1.0 error: declared and/or actual IP address families mismatch");

    ExtractPort(tok, header->sourceAddress, true);
    ExtractPort(tok, header->destinationAddress, false);
}

/// parses PROXY protocol v1 header from the buffer
ProxyProtocol::Parsed
ProxyProtocol::One::Parse(const SBuf &buf)
{
    Parser::Tokenizer tok(buf);

    static const SBuf::size_type maxHeaderLength = 107; // including CRLF
    static const auto maxInteriorLength = maxHeaderLength - Magic.length() - 2;
    static const auto interiorChars = CharacterSet::CR.complement().rename("non-CR");
    SBuf interior;

    if (!(tok.prefix(interior, interiorChars, maxInteriorLength) &&
            tok.skip('\r') &&
            tok.skip('\n'))) {
        if (tok.atEnd())
            throw Parser::BinaryTokenizer::InsufficientInput();
        // "empty interior", "too-long interior", or "missing LF after CR"
        throw TexcHere("PROXY/1.0 error: malformed header");
    }
    // extracted all PROXY protocol bytes

    static const SBuf v1("1.0");
    Header::Pointer header = new Header(v1, Two::cmdProxy);

    Parser::Tokenizer interiorTok(interior);

    if (!interiorTok.skip(' '))
        throw TexcHere("PROXY/1.0 error: missing SP after the magic sequence");

    static const SBuf protoUnknown("UNKNOWN");
    static const SBuf protoTcp("TCP");

    if (interiorTok.skip(protoTcp))
        ParseAddresses(interiorTok, header);
    else if (interiorTok.skip(protoUnknown))
        header->ignoreAddresses();
    else
        throw TexcHere("PROXY/1.0 error: invalid INET protocol or family");

    return Parsed(header, tok.parsedSize());
}

void
ProxyProtocol::Two::ParseAddresses(const uint8_t family, Parser::BinaryTokenizer &tok, Header::Pointer &header)
{
    switch (family) {

    case afInet: {
        header->sourceAddress = tok.inet4("src_addr IPv4");
        header->destinationAddress = tok.inet4("dst_addr IPv4");
        header->sourceAddress.port(tok.uint16("src_port"));
        header->destinationAddress.port(tok.uint16("dst_port"));
        break;
    }

    case afInet6: {
        header->sourceAddress = tok.inet6("src_addr IPv6");
        header->destinationAddress = tok.inet6("dst_addr IPv6");
        header->sourceAddress.port(tok.uint16("src_port"));
        header->destinationAddress.port(tok.uint16("dst_port"));
        break;
    }

    case afUnix: { // TODO: add support
        // the address block length is 216 bytes
        tok.skip(216, "unix_addr");
        break;
    }

    default: {
        // unreachable code: we have checked family validity already
        Must(false);
        break;
    }
    }
}

void
ProxyProtocol::Two::ParseTLVs(Parser::BinaryTokenizer &tok, Header::Pointer &header) {
    while (!tok.atEnd()) {
        const auto type = tok.uint8("pp2_tlv::type");
        header->tlvs.emplace_back(type, tok.pstring16("pp2_tlv::value"));
    }
}

ProxyProtocol::Parsed
ProxyProtocol::Two::Parse(const SBuf &buf)
{
    Parser::BinaryTokenizer tokHeader(buf, true);

    const auto versionAndCommand = tokHeader.uint8("version and command");

    const auto version = (versionAndCommand & 0xF0) >> 4;
    if (version != 2) // version == 2 is mandatory
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid version ", version));

    const auto command = (versionAndCommand & 0x0F);
    if (command > cmdProxy)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid command ", command));

    const auto familyAndProto = tokHeader.uint8("family and proto");

    const auto family = (familyAndProto & 0xF0) >> 4;
    if (family > afUnix)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid address family ", family));

    const auto proto = (familyAndProto & 0x0F);
    if (proto > tpDgram)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid transport protocol ", proto));

    const auto rawHeader = tokHeader.pstring16("header");

    static const SBuf v2("2.0");
    Header::Pointer header = new Header(v2, Two::Command(command));

    if (proto == tpUnspecified || family == afUnspecified) {
        header->ignoreAddresses();
        // discard address block and TLVs because we cannot tell
        // how to parse such addresses and where the TLVs start.
    } else {
        Parser::BinaryTokenizer leftoverTok(rawHeader);
        ParseAddresses(family, leftoverTok, header);
        // TODO: parse TLVs for LOCAL connections
        if (header->hasForwardedAddresses())
            ParseTLVs(leftoverTok, header);
    }

    return Parsed(header, tokHeader.parsed());
}

ProxyProtocol::Parsed
ProxyProtocol::Parse(const SBuf &buf)
{
    Parser::Tokenizer magicTok(buf);

    const auto parser =
        magicTok.skip(Two::Magic) ? &Two::Parse :
        magicTok.skip(One::Magic) ? &One::Parse :
        nullptr;

    if (parser) {
        const auto parsed = (parser)(magicTok.remaining());
        return Parsed(parsed.header, magicTok.parsedSize() + parsed.size);
    }

    // detect and terminate other protocols
    if (buf.length() >= Two::Magic.length()) {
        // PROXY/1.0 magic is shorter, so we know that
        // the input does not start with any PROXY magic
        throw TexcHere("PROXY protocol error: invalid magic");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse magic yet
    throw Parser::BinaryTokenizer::InsufficientInput();
}

ProxyProtocol::Parsed::Parsed(const Header::Pointer &parsedHeader, const size_t parsedSize):
    header(parsedHeader),
    size(parsedSize)
{
    assert(bool(parsedHeader));
}

