/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/LocalIp.h"

char const *
ACLLocalIP::typeString() const
{
    return "localip";
}

int
ACLLocalIP::match(ACLChecklist *checklist)
{
    return ACLIP::match (Filled(checklist)->my_addr);
}

ACL *
ACLLocalIP::clone() const
{
    return new ACLLocalIP(*this);
}

