/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLURLPORT_H
#define SQUID_ACLURLPORT_H
#include "acl/Strategised.h"
#include "acl/Strategy.h"

class ACLUrlPortStrategy : public ACLStrategy<int>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLUrlPortStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLUrlPortStrategy(ACLUrlPortStrategy const &);

private:
    static ACLUrlPortStrategy Instance_;
    ACLUrlPortStrategy() {}

    ACLUrlPortStrategy&operator=(ACLUrlPortStrategy const &);
};

class ACLUrlPort
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<int> RegistryEntry_;
};

#endif /* SQUID_ACLURLPORT_H */

