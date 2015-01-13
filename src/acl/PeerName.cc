/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/PeerName.h"
#include "acl/RegexData.h"
#include "acl/StringData.h"
#include "CachePeer.h"

int
ACLPeerNameStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    if (checklist->dst_peer != NULL && checklist->dst_peer->name != NULL)
        return data->match(checklist->dst_peer->name);
    return 0;
}

ACLPeerNameStrategy *
ACLPeerNameStrategy::Instance()
{
    return &Instance_;
}

ACLPeerNameStrategy ACLPeerNameStrategy::Instance_;

