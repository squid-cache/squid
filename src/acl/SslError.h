
/*
 * $Id$
 */

#ifndef SQUID_ACLSSL_ERROR_H
#define SQUID_ACLSSL_ERROR_H
#include "acl/Strategy.h"
#include "acl/Strategised.h"

class ACLSslErrorStrategy : public ACLStrategy<int>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    static ACLSslErrorStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSslErrorStrategy(ACLSslErrorStrategy const &);

private:
    static ACLSslErrorStrategy Instance_;
    ACLSslErrorStrategy() {}

    ACLSslErrorStrategy&operator=(ACLSslErrorStrategy const &);
};

class ACLSslError
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<int> RegistryEntry_;
};

#endif /* SQUID_ACLSSL_ERROR_H */
