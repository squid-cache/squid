#include "squid.h"
#include "acl/PeerName.h"
#include "acl/StringData.h"
#include "acl/Checklist.h"

ACL::Prototype ACLPeerName::RegistryProtoype(&ACLPeerName::RegistryEntry_, "peername");

ACLStrategised<const char *> ACLPeerName::RegistryEntry_(new ACLStringData, ACLPeerNameStrategy::Instance(), "peername");

int
ACLPeerNameStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
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
