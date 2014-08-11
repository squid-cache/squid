#ifndef SQUID_ACLATSTEP_H
#define SQUID_ACLATSTEP_H
#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "ssl/support.h"

/// \ingroup ACLAPI
class ACLAtStepStrategy : public ACLStrategy<Ssl::BumpStep>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLAtStepStrategy *Instance();
    /**
     * Not implemented to prevent copies of the instance.
     */
    ACLAtStepStrategy(ACLAtStepStrategy const &);

private:
    static ACLAtStepStrategy Instance_;
    ACLAtStepStrategy() {}

    ACLAtStepStrategy&operator=(ACLAtStepStrategy const &);
};

class ACLAtStep
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<Ssl::BumpStep> RegistryEntry_;
};

#endif /* SQUID_ACLATSTEP_H */
