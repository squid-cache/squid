/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Host.h"

#include <iostream>

std::optional<AnyP::Host>
AnyP::Host::FromIp(const Ip::Address &ip)
{
    // any IP value is acceptable
    debugs(23, 7, ip);
    return Host(ip);
}

/// common parts of FromSimpleDomain() and FromWildDomain()
std::optional<AnyP::Host>
AnyP::Host::FromDomainName(const SBuf &rawName)
{
    if (rawName.isEmpty()) {
        debugs(23, 3, "rejecting empty name");
        return std::nullopt;
    }

    // Reject bytes incompatible with rfc1035NamePack() and ::matchDomainName()
    // implementations (at least). Such bytes can come from percent-encoded HTTP
    // URIs or length-based X.509 fields, for example. Higher-level parsers must
    // reject or convert domain name encodings like UTF-16, but this low-level
    // check works as an additional (albeit unreliable) layer of defense against
    // those (unsupported by Squid DNS code) encodings.
    if (rawName.find('\0') != SBuf::npos) {
        const auto description = "XXX";
        debugs(83, 3, "rejects " << description << " with an ASCII NUL character: " << rawName);
        return std::nullopt;
    }

    // TODO: Consider rejecting names with isspace(3) bytes.

    debugs(23, 7, rawName);
    return Host(rawName);
}

std::optional<AnyP::Host>
AnyP::Host::FromSimpleDomainName(const SBuf &rawName)
{
    if (rawName.find('*') != SBuf::npos) {
        debugs(23, 3, "rejecting wildcard: " << rawName);
        return std::nullopt;
    }
    return FromDomainName(rawName);
}

std::optional<AnyP::Host>
AnyP::Host::FromWildDomainName(const SBuf &rawName)
{
    const static SBuf wildcardLabel("*.");
    if (rawName.startsWith(wildcardLabel)) {
        if (rawName.find('*', 2) != SBuf::npos) {
            debugs(23, 3, "rejecting excessive wildcards: " << rawName);
            return std::nullopt;
        }
        // else: fall through to final checks
    } else {
        if (rawName.find('*', 0) != SBuf::npos) {
            // this case includes "*" and "example.*" input
            debugs(23, 3, "rejecting unsupported wildcard: " << rawName);
            return std::nullopt;
        }
        // else: fall through to final checks
    }
    return FromDomainName(rawName);
}

std::ostream &
AnyP::operator <<(std::ostream &os, const Host &host)
{
    if (const auto ip = host.ip()) {
        char buf[MAX_IPSTRLEN];
        (void)ip->toStr(buf, sizeof(buf)); // no brackets
        os << buf;
    } else {
        // If Host object creators start applying Uri::Decode() to reg-names,
        // then we must start applying Uri::Encode() here, but only to names
        // that require it. See "The reg-name syntax allows percent-encoded
        // octets" paragraph in RFC 3986.
        const auto domainName = host.domainName();
        Assure(domainName);
        os << *domainName;
    }
    return os;
}

std::ostream &
AnyP::operator <<(std::ostream &os, const Bracketed &hostWrapper)
{
    bool addBrackets = false;
    if (const auto ip = hostWrapper.host.ip())
        addBrackets = ip->isIPv6();

    if (addBrackets)
        os << '[';
    os << hostWrapper.host;
    if (addBrackets)
        os << ']';

    return os;
}


