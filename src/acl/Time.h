/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTIME_H
#define SQUID_ACLTIME_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/Strategised.h"

class ACLChecklist; // XXX: we do not need it

class ACLTimeStrategy : public ACLStrategy<time_t>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLTimeStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLTimeStrategy(ACLTimeStrategy const &);

private:
    static ACLTimeStrategy Instance_;
    ACLTimeStrategy() {}

    ACLTimeStrategy&operator=(ACLTimeStrategy const &);
};

class ACLTime
{

public:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<time_t> RegistryEntry_;
};

#endif /* SQUID_ACLTIME_H */

