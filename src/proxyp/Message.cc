/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "proxyp/Elements.h"
#include "proxyp/Message.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "StrList.h"

ProxyProtocol::Message::Message(const SBuf &ver, const Two::Command cmd):
    version_(ver),
    command_(cmd),
    ignoreAddresses_(false)
{}

SBuf
ProxyProtocol::Message::toMime() const
{
    SBufStream result;
    for (const auto &p: PseudoHeaderFields) {
        const auto value = getValues(p.second);
        if (!value.isEmpty())
            result << p.first << ": " << value << "\r\n";
    }
    // cannot reuse Message::getValues(): need the original TLVs layout
    for (const auto &tlv: tlvs)
        result << tlv.type << ": " << tlv.value << "\r\n";
    return result.buf();
}

SBuf
ProxyProtocol::Message::getValues(const uint32_t headerType, const char sep) const
{
    switch (headerType) {

    case Two::htPseudoVersion:
        return version_;

    case Two::htPseudoCommand:
        return ToSBuf(command_);

    case Two::htPseudoSrcAddr: {
        if (!hasAddresses())
            return SBuf();
        auto logAddr = sourceAddress;
        (void)logAddr.applyClientMask(Config.Addrs.client_netmask);
        char ipBuf[MAX_IPSTRLEN];
        return SBuf(logAddr.toStr(ipBuf, sizeof(ipBuf)));
    }

    case Two::htPseudoDstAddr: {
        if (!hasAddresses())
            return SBuf();
        char ipBuf[MAX_IPSTRLEN];
        return SBuf(destinationAddress.toStr(ipBuf, sizeof(ipBuf)));
    }

    case Two::htPseudoSrcPort: {
        return hasAddresses() ? ToSBuf(sourceAddress.port()) : SBuf();
    }

    case Two::htPseudoDstPort: {
        return hasAddresses() ? ToSBuf(destinationAddress.port()) : SBuf();
    }

    default: {
        SBufStream result;
        for (const auto &m: tlvs) {
            if (m.type == headerType) {
                // XXX: result.tellp() always returns -1
                if (!result.buf().isEmpty())
                    result << sep;
                result << m.value;
            }
        }
        return result.buf();
    }
    }
}

SBuf
ProxyProtocol::Message::getElem(const uint32_t headerType, const char *member, const char sep) const
{
    const auto whole = SBufToString(getValues(headerType, sep));
    return getListMember(whole, member, sep);
}

const SBuf &
ProxyProtocol::Message::addressFamily() const
{
    static const SBuf v4("4");
    static const SBuf v6("6");
    static const SBuf vMix("mix");
    return
        (sourceAddress.isIPv6() && destinationAddress.isIPv6()) ? v6 :
        (sourceAddress.isIPv4() && destinationAddress.isIPv4()) ? v4 :
        vMix;
}

