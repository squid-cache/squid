/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ADDRESS_H
#define SQUID_SRC_ACL_ADDRESS_H

#include "acl/Acl.h"
#include "cbdata.h"
#include "ip/Address.h"

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

    Ip::Address addr;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_ADDRESS_H */

