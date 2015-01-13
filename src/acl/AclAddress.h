/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef ACLADDRESS_H_
#define ACLADDRESS_H_

#include "acl/Acl.h"
#include "ip/Address.h"

/// list of address-based ACLs.
class AclAddress
{
public:
    AclAddress *next;
    ACLList *aclList;

    Ip::Address addr;
};

#endif /* ACLADDRESS_H_ */

