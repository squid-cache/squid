/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLURLLOGIN_H
#define SQUID_ACLURLLOGIN_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
#include "acl/Strategy.h"

class ACLUrlLoginStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<char const *> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLUrlLoginStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLUrlLoginStrategy(ACLUrlLoginStrategy const &);

private:
    static ACLUrlLoginStrategy Instance_;
    ACLUrlLoginStrategy() {}

    ACLUrlLoginStrategy&operator=(ACLUrlLoginStrategy const &);
};

class ACLUrlLogin
{

public:
    static ACL::Prototype RegistryProtoype;
    static ACL::Prototype LegacyRegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

#endif /* SQUID_ACLURLLOGIN_H */

