/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLADAPTATIONSERVICE_H
#define SQUID_ACLADAPTATIONSERVICE_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLAdaptationServiceStrategy : public ACLStrategy<const char *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLAdaptationServiceStrategy *Instance();
    /**
     * Not implemented to prevent copies of the instance.
     */
    ACLAdaptationServiceStrategy(ACLAdaptationServiceStrategy const &);

private:
    static ACLAdaptationServiceStrategy Instance_;
    ACLAdaptationServiceStrategy() {}

    ACLAdaptationServiceStrategy &operator = (ACLAdaptationServiceStrategy const &);
};

/// \ingroup ACLAPI
class ACLAdaptationService
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<const char *> RegistryEntry_;
};

#endif /* SQUID_ACLADAPTATIONSERVICE_H */

