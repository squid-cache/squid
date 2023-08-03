/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ACL_ADDRESS_H
#define _SQUID_SRC_ACL_ADDRESS_H

#include "acl/Acl.h"
#include "http/forward.h"
#include "ip/Address.h"

#include <variant>
#include <optional>

namespace Acl
{

/// an invasive list of tcp_outgoing_address directives
class Address
{
    CBDATA_CLASS(Address);

public:
    Address() : next(nullptr), aclList(nullptr) {}
    ~Address();

    /// computes Ip::Address corresponding to this tcp_outgoing_address directive
    /// \param request optional (adapted) client request
    /// \returns std::nullopt if this directive should be skipped
    std::optional<Ip::Address> findAddressCandidate(HttpRequest *) const;

    Acl::Address *next;
    ACLList *aclList;

    /// an AddressSource variant representing match_client_tcp_dst configuration
    struct MatchClientTcpDst {};

    /// an outgoing address value or value computation algorithm
    using AddressSource = std::variant<Ip::Address, MatchClientTcpDst>;

    /// configured Ip::Address provider
    AddressSource addressSource;
};

/// reports AddressSource configuration using squid.conf syntax
std::ostream &operator <<(std::ostream &, const Address::AddressSource &);

} // namespace Acl

#endif /* _SQUID_SRC_ACL_ADDRESS_H */

