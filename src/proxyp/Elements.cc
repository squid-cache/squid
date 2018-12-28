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
#include "proxyp/Message.h"
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

ProxyProtocol::Two::HeaderType
ProxyProtocol::HeaderNameToHeaderType(const SBuf &nameOrId)
{
    const auto it = PseudoHeaderFields.find(nameOrId);
    if (it != PseudoHeaderFields.end())
        return it->second;

    Parser::Tokenizer ptok(nameOrId);
    int64_t tlvType = 0;
    if (!ptok.int64(tlvType, 10, false))
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type. Expecting a positive decimal integer but got ", nameOrId));
    if (tlvType > std::numeric_limits<uint8_t>::max())
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type. Expecting an integer less than ",
                              std::numeric_limits<uint8_t>::max(), " but got ", tlvType));
    return Two::HeaderType(tlvType);
}

