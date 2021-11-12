/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/EnumIterator.h"
#include "proxyp/Elements.h"
#include "proxyp/Header.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "StrList.h"

ProxyProtocol::Header::Header(const SBuf &ver, const Two::Command cmd):
    version_(ver),
    command_(cmd),
    ignoreAddresses_(false)
{}

SBuf
ProxyProtocol::Header::toMime() const
{
    SBuf result;
    PackableStream os(result);
    for (const auto fieldType: EnumRange(Two::htPseudoBegin, Two::htPseudoEnd)) {
        const auto value = getValues(fieldType);
        if (!value.isEmpty())
            os << PseudoFieldTypeToFieldName(fieldType) << ": " << value << "\r\n";
    }
    // cannot reuse Header::getValues(): need the original TLVs layout
    for (const auto &tlv: tlvs)
        os << tlv.type << ": " << tlv.value << "\r\n";
    return result;
}

SBuf
ProxyProtocol::Header::getValues(const uint32_t headerType, const char sep) const
{
    static char ipBuf[MAX_IPSTRLEN];
    SBuf result;
    PackableStream os(result);

    switch (headerType) {

    case Two::htPseudoVersion:
        os << version_;
        break;

    case Two::htPseudoCommand:
        os << command_;
        break;

    case Two::htPseudoSrcAddr:
        if (hasAddresses()) {
            auto logAddr = sourceAddress;
            logAddr.applyClientMask(Config.Addrs.client_netmask);
            os << logAddr.toStr(ipBuf, sizeof(ipBuf));
        }
        break;

    case Two::htPseudoDstAddr:
        if (!hasAddresses())
            os << destinationAddress.toStr(ipBuf, sizeof(ipBuf));
        break;

    case Two::htPseudoSrcPort:
        if (hasAddresses())
            os << sourceAddress.port();
        break;

    case Two::htPseudoDstPort:
        if (hasAddresses())
            os << destinationAddress.port();
        break;

    default:
        for (const auto &m: tlvs) {
            if (m.type == headerType) {
                if (!result.isEmpty())
                    os << sep;
                os << m.value;
            }
        }
    }
    return result;
}

SBuf
ProxyProtocol::Header::getElem(const uint32_t headerType, const char *member, const char sep) const
{
    const auto whole = SBufToString(getValues(headerType, sep));
    return getListMember(whole, member, sep);
}

const SBuf &
ProxyProtocol::Header::addressFamily() const
{
    static const SBuf v4("4");
    static const SBuf v6("6");
    static const SBuf vMix("mix");
    return
        (sourceAddress.isIPv6() && destinationAddress.isIPv6()) ? v6 :
        (sourceAddress.isIPv4() && destinationAddress.isIPv4()) ? v4 :
        vMix;
}

