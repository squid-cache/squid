/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "parser/Tokenizer.h"
#include "proxyp/Elements.h"
#include "sbuf/Stream.h"

#include <limits>

const ProxyProtocol::FieldMap ProxyProtocol::PseudoHeaderFields = {
    { SBuf(":version"), ProxyProtocol::Two::htPseudoVersion },
    { SBuf(":command"), ProxyProtocol::Two::htPseudoCommand },
    { SBuf(":src_addr"), ProxyProtocol::Two::htPseudoSrcAddr },
    { SBuf(":dst_addr"), ProxyProtocol::Two::htPseudoDstAddr },
    { SBuf(":src_port"), ProxyProtocol::Two::htPseudoSrcPort },
    { SBuf(":dst_port"), ProxyProtocol::Two::htPseudoDstPort }
};

namespace ProxyProtocol {
static Two::HeaderType NameToHeaderType(const SBuf &);
static Two::HeaderType IntegerToHeaderType(const SBuf &);
} // namespace ProxyProtocol

/// HeaderNameToHeaderType() helper that handles pseudo headers
ProxyProtocol::Two::HeaderType
ProxyProtocol::NameToHeaderType(const SBuf &name)
{
    const auto it = PseudoHeaderFields.find(name);
    if (it != PseudoHeaderFields.end())
        return it->second;

    static const SBuf pseudoMark(":");
    if (name.startsWith(pseudoMark))
        throw TexcHere(ToSBuf("Unsupported PROXY protocol pseudo header: ", name));

    throw TexcHere(ToSBuf("Invalid PROXY protocol pseudo header or TLV type name. ",
                          "Expected a pseudo header like :src_addr but got '", name, "'"));
}

/// HeaderNameToHeaderType() helper that handles integer TLV types
ProxyProtocol::Two::HeaderType
ProxyProtocol::IntegerToHeaderType(const SBuf &rawInteger)
{
    int64_t tlvType = 0;

    Parser::Tokenizer ptok(rawInteger);
    if (!ptok.int64(tlvType, 10, false) || !ptok.atEnd())
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type value. ",
                              "Expected a decimal integer but got '", rawInteger, "'"));

    const auto limit = std::numeric_limits<uint8_t>::max();
    if (tlvType > limit)
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type value. ",
                              "Expected an integer less than ", limit,
                              " but got '", tlvType, "'"));

    return Two::HeaderType(tlvType);
}

ProxyProtocol::Two::HeaderType
ProxyProtocol::HeaderNameToHeaderType(const SBuf &tlvTypeRaw)
{
    // we could branch on ":" instead of DIGIT but then header names that lack a
    // leading ":" (like "version") would get a less accurate error message
    return Parser::Tokenizer(tlvTypeRaw).skipOne(CharacterSet::DIGIT) ?
           IntegerToHeaderType(tlvTypeRaw):
           NameToHeaderType(tlvTypeRaw);
}

