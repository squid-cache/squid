/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMYPORTNAME_H
#define SQUID_ACLMYPORTNAME_H
#include "acl/Strategised.h"
#include "acl/Strategy.h"

class ACLMyPortNameStrategy : public ACLStrategy<const char *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLMyPortNameStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLMyPortNameStrategy(ACLMyPortNameStrategy const &);

private:
    static ACLMyPortNameStrategy Instance_;
    ACLMyPortNameStrategy() {}

    ACLMyPortNameStrategy&operator=(ACLMyPortNameStrategy const &);
};

class ACLMyPortName
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<const char *> RegistryEntry_;
};

#endif /* SQUID_ACLMYPORTNAME_H */

