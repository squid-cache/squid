#ifndef SQUID_ACLPEERNAME_H
#define SQUID_ACLPEERNAME_H

#include "acl/Strategy.h"
#include "acl/Strategised.h"

class ACLPeerNameStrategy : public ACLStrategy<const char *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    static ACLPeerNameStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLPeerNameStrategy(ACLPeerNameStrategy const &);

private:
    static ACLPeerNameStrategy Instance_;
    ACLPeerNameStrategy() {}

    ACLPeerNameStrategy&operator=(ACLPeerNameStrategy const &);
};

class ACLPeerName
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<const char *> RegistryEntry_;
};

#endif /* SQUID_ACLPEERNAME_H */
