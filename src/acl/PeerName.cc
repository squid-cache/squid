/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/PeerName.h"
#include "acl/RegexData.h"
#include "acl/StringData.h"

int
ACLPeerNameStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    if (!checklist->dst_peer_name.isEmpty())
        return data->match(checklist->dst_peer_name.c_str());
    return 0;
}

