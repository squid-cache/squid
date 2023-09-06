/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/PeerName.h"

int
Acl::PeerNameCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    if (!checklist->dst_peer_name.isEmpty())
        return data->match(checklist->dst_peer_name.c_str());
    return 0;
}

