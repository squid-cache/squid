/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/SourceIp.h"

char const *
ACLSourceIP::typeString() const
{
    return "src";
}

int
ACLSourceIP::match(ACLChecklist *checklist)
{
    return ACLIP::match(Filled(checklist)->src_addr);
}

ACL *
ACLSourceIP::clone() const
{
    return new ACLSourceIP(*this);
}

