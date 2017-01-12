/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHIERCODE_H
#define SQUID_ACLHIERCODE_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "hier_code.h"

/// \ingroup ACLAPI
class ACLHierCodeStrategy : public ACLStrategy<hier_code>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLHierCodeStrategy *Instance();

    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends
     */
    ACLHierCodeStrategy(ACLHierCodeStrategy const &);

private:
    static ACLHierCodeStrategy Instance_;
    ACLHierCodeStrategy() {}

    ACLHierCodeStrategy &operator=(ACLHierCodeStrategy const &);
};

/// \ingroup ACLAPI
class ACLHierCode
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<hier_code> RegistryEntry_;
};

#endif /* SQUID_ACLHIERCODE_H */

