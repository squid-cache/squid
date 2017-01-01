/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSQUIDERROR_H
#define SQUID_ACLSQUIDERROR_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "err_type.h"

class ACLSquidErrorStrategy : public ACLStrategy<err_type>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);

    static ACLSquidErrorStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSquidErrorStrategy(ACLSquidErrorStrategy const &);

private:
    static ACLSquidErrorStrategy Instance_;
    ACLSquidErrorStrategy() {}

    ACLSquidErrorStrategy&operator=(ACLSquidErrorStrategy const &);
};

class ACLSquidError
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<err_type> RegistryEntry_;
};

#endif /* SQUID_ACLSQUIDERROR_H */

