/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ACL_ADDRESS_H
#define _SQUID_SRC_ACL_ADDRESS_H

#include "acl/Acl.h"
#include "ip/Address.h"

namespace Acl
{

/// list of address-based ACLs.
class Address
{
    CBDATA_CLASS(Address);

public:
    Address() : next(NULL), aclList(NULL) {}
    ~Address();

    Acl::Address *next;
    ACLList *aclList;

    Ip::Address addr;
};

} // namespace Acl

#endif /* _SQUID_SRC_ACL_ADDRESS_H */

