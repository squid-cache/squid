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
static Two::FieldType NameToFieldType(const SBuf &);
static Two::FieldType IntegerToFieldType(const SBuf &);
} // namespace ProxyProtocol

/// FieldNameToFieldType() helper that handles pseudo headers
ProxyProtocol::Two::FieldType
ProxyProtocol::NameToFieldType(const SBuf &name)
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

/// FieldNameToFieldType() helper that handles integer TLV types
ProxyProtocol::Two::FieldType
ProxyProtocol::IntegerToFieldType(const SBuf &rawInteger)
{
    int64_t tlvType = 0;

    Parser::Tokenizer ptok(rawInteger);
    if (ptok.skip('0')) {
        if (!ptok.atEnd())
            throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type value. ",
                                  "Expected a decimal integer without leading zeros but got '",
                                  rawInteger, "'")); // e.g., 077, 0xFF, or 0b101
        // tlvType stays zero
    } else {
        Must(ptok.int64(tlvType, 10, false)); // the first character is a DIGIT
        if (!ptok.atEnd())
            throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type value. ",
                                  "Trailing garbage after ", tlvType, " in '",
                                  rawInteger, "'")); // e.g., 1.0 or 5e0
    }

    const auto limit = std::numeric_limits<uint8_t>::max();
    if (tlvType > limit)
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type value. ",
                              "Expected an integer less than ", limit,
                              " but got '", tlvType, "'"));

    return Two::FieldType(tlvType);
}

ProxyProtocol::Two::FieldType
ProxyProtocol::FieldNameToFieldType(const SBuf &tlvTypeRaw)
{
    // we could branch on ":" instead of DIGIT but then field names that lack a
    // leading ":" (like "version") would get a less accurate error message
    return Parser::Tokenizer(tlvTypeRaw).skipOne(CharacterSet::DIGIT) ?
           IntegerToFieldType(tlvTypeRaw):
           NameToFieldType(tlvTypeRaw);
}

