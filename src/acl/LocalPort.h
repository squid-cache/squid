/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLLOCALPORT_H
#define SQUID_ACLLOCALPORT_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLLocalPortStrategy : public ACLStrategy<int>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLLocalPortStrategy *Instance();
    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends
     */
    ACLLocalPortStrategy(ACLLocalPortStrategy const &);

private:
    static ACLLocalPortStrategy Instance_;
    ACLLocalPortStrategy() {}

    ACLLocalPortStrategy&operator=(ACLLocalPortStrategy const &);
};

/// \ingroup ACLAPI
class ACLLocalPort
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<int> RegistryEntry_;
};

#endif /* SQUID_ACLLOCALPORT_H */

