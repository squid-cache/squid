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
#include "ip/Address.h"

#include <variant>

namespace Acl
{

/// an invasive list of tcp_outgoing_address directives
class Address
{
    CBDATA_CLASS(Address);

public:
    Address() : next(nullptr), aclList(nullptr) {}
    ~Address();

    Acl::Address *next;
    ACLList *aclList;

    /// an AddressSource variant representing match_client_tcp_dst configuration
    struct UseClientAddress {};

    /// an outgoing address value or value computation algorithm
    using AddressSource = std::variant<Ip::Address, UseClientAddress>;

    /// configured Ip::Address provider
    AddressSource addressSource;
};

/// reports AddressSource configuration using squid.conf syntax
std::ostream &operator <<(std::ostream &, const Address::AddressSource &);

} // namespace Acl

#endif /* _SQUID_SRC_ACL_ADDRESS_H */

