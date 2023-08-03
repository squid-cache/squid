/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Address.h"
#include "acl/Gadgets.h"
#include "client_side.h"
#include "debug/Stream.h"
#include "http/Stream.h"
#include "HttpRequest.h"

CBDATA_NAMESPACED_CLASS_INIT(Acl, Address);

Acl::Address::~Address()
{
    aclDestroyAclList(&aclList);
    delete next;
}

std::optional<Ip::Address>
Acl::Address::findAddressCandidate(HttpRequest * const request) const
{
    if (std::holds_alternative<UseClientAddress>(addressSource)) {
        if (request && request->clientConnectionManager.valid()) {
            auto localAddr = request->clientConnectionManager->clientConnection->local;
            localAddr.port(0);
            return localAddr;
        }

        // not DBG_IMPORTANT or Assure() because the client may simply be gone by now
        debugs(17, 3, "WARNING: Skipping tcp_outgoing_address match_client_tcp_dst rule");
        return std::nullopt;
    }

    return std::get<Ip::Address>(addressSource);
}

std::ostream &
Acl::operator <<(std::ostream &os, const Address::AddressSource &source)
{
    if (std::holds_alternative<Address::UseClientAddress>(source)) {
        os << "match_client_tcp_dst";
        return os;
    }

    const auto &addr = std::get<Ip::Address>(source);

    if (addr.isAnyAddr()) {
        // XXX: Use squid.conf syntax (e.g., "any_addr") for all special values
        os << "autoselect";
        return os;
    }

    char buf[MAX_IPSTRLEN];
    os << addr.toStr(buf, MAX_IPSTRLEN);
    return os;
}

