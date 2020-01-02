/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AclSizeLimit.h"
#include "acl/Gadgets.h"

CBDATA_CLASS_INIT(AclSizeLimit);

AclSizeLimit::~AclSizeLimit()
{
    aclDestroyAclList(&aclList);
    delete next;
}

