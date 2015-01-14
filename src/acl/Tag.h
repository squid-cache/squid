/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTAG_H
#define SQUID_ACLTAG_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"

class ACLTagStrategy : public ACLStrategy<const char *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLTagStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLTagStrategy(ACLTagStrategy const &);

private:
    static ACLTagStrategy Instance_;
    ACLTagStrategy() {}

    ACLTagStrategy&operator=(ACLTagStrategy const &);
};

class ACLTag
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<const char *> RegistryEntry_;
};

#endif /* SQUID_ACLMYPORTNAME_H */

