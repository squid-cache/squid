/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLURL_H
#define SQUID_ACLURL_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/Strategised.h"

class ACLUrlStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<char const *> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLUrlStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLUrlStrategy(ACLUrlStrategy const &);

private:
    static ACLUrlStrategy Instance_;
    ACLUrlStrategy() {}

    ACLUrlStrategy&operator=(ACLUrlStrategy const &);
};

class ACLUrl
{

public:
    static ACL::Prototype RegistryProtoype;
    static ACL::Prototype LegacyRegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

#endif /* SQUID_ACLURL_H */

