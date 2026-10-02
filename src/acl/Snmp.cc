/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Snmp.h"

#if SQUID_SNMP

int
Acl::Snmp::CommunityCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    if (!checklist->snmp)
        return -1;

    return data->match(reinterpret_cast<const char *>(checklist->snmp->community));
}

#endif /* SQUID_SNMP */
