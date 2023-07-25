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
#include "SquidString.h"

#include <variant>

namespace Acl
{

/// list of address-based ACLs.
class Address
{
    CBDATA_CLASS(Address);

public:
    Address() : next(nullptr), aclList(nullptr) {}
    ~Address();

    Acl::Address *next;
    ACLList *aclList;

    struct UseClientAddress {};
    using AddressSource = std::variant<Ip::Address, UseClientAddress>;
    AddressSource addr; ///< Ip::Address provider
};

} // namespace Acl

#endif /* _SQUID_SRC_ACL_ADDRESS_H */

