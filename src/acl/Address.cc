/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Address.h"
#include "acl/Gadgets.h"

CBDATA_NAMESPACED_CLASS_INIT(Acl, Address);

Acl::Address::~Address()
{
    aclDestroyAclList(&aclList);
    delete next;
}

