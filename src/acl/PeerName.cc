#include "squid.h"
#include "acl/PeerName.h"
#include "acl/RegexData.h"
#include "acl/StringData.h"
#include "acl/Checklist.h"
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
