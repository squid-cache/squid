/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLPEERNAME_H
#define SQUID_ACLPEERNAME_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"

class ACLPeerNameStrategy : public ACLStrategy<const char *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLPeerNameStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLPeerNameStrategy(ACLPeerNameStrategy const &);

private:
    static ACLPeerNameStrategy Instance_;
    ACLPeerNameStrategy() {}

    ACLPeerNameStrategy&operator=(ACLPeerNameStrategy const &);
};

class ACLPeerName
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<const char *> RegistryEntry_;
    static ACL::Prototype RegexRegistryProtoype;
    static ACLStrategised<char const *> RegexRegistryEntry_;
};

#endif /* SQUID_ACLPEERNAME_H */

