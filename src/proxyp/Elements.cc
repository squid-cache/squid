/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "parser/Tokenizer.h"
#include "proxyp/Elements.h"
#include "sbuf/Stream.h"

#include <algorithm>
#include <limits>
#include <vector>

namespace ProxyProtocol {
namespace Two {

/// a mapping between pseudo header names and ids
typedef std::vector< std::pair<SBuf, FieldType> > FieldMap;
static const FieldMap PseudoHeaderFields = {
    { SBuf(":version"), htPseudoVersion },
    { SBuf(":command"), htPseudoCommand },
    { SBuf(":src_addr"), htPseudoSrcAddr },
    { SBuf(":dst_addr"), htPseudoDstAddr },
    { SBuf(":src_port"), htPseudoSrcPort },
    { SBuf(":dst_port"), htPseudoDstPort }
};

} // namespace Two

static Two::FieldType NameToFieldType(const SBuf &);
static Two::FieldType IntegerToFieldType(const SBuf &);

} // namespace ProxyProtocol

const SBuf &
ProxyProtocol::PseudoFieldTypeToFieldName(const Two::FieldType fieldType)
{
    const auto it = std::find_if(Two::PseudoHeaderFields.begin(), Two::PseudoHeaderFields.end(),
    [fieldType](const Two::FieldMap::value_type &item) {
        return item.second == fieldType;
    });

    assert(it != Two::PseudoHeaderFields.end());
    return it->first;
}

/// FieldNameToFieldType() helper that handles pseudo headers
ProxyProtocol::Two::FieldType
ProxyProtocol::NameToFieldType(const SBuf &name)
{
    const auto it = std::find_if(Two::PseudoHeaderFields.begin(), Two::PseudoHeaderFields.end(),
    [&name](const Two::FieldMap::value_type &item) {
        return item.first == name;
    });

    if (it != Two::PseudoHeaderFields.end())
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

