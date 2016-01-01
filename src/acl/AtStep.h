/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLATSTEP_H
#define SQUID_ACLATSTEP_H

#if USE_OPENSSL

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "ssl/support.h"

/// \ingroup ACLAPI
class ACLAtStepStrategy : public ACLStrategy<Ssl::BumpStep>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLAtStepStrategy *Instance();

    // Not implemented to prevent copies of the instance.
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

#endif /* USE_OPENSSL */

#endif /* SQUID_ACLATSTEP_H */

