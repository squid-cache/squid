/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSERVERNAME_H
#define SQUID_ACLSERVERNAME_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/DomainData.h"
#include "acl/Strategised.h"

class ACLServerNameData : public ACLDomainData {
    MEMPROXY_CLASS(ACLServerNameData);
public:
    ACLServerNameData() : ACLDomainData() {}
    virtual bool match(const char *);
    virtual ACLData<char const *> *clone() const;
};

class ACLServerNameStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLServerNameStrategy *Instance();
    virtual bool requiresRequest() const {return true;}

    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends
     */
    ACLServerNameStrategy(ACLServerNameStrategy const &);

private:
    static ACLServerNameStrategy Instance_;
    ACLServerNameStrategy() {}

    ACLServerNameStrategy&operator=(ACLServerNameStrategy const &);
};

class ACLServerName
{

private:
    static ACL::Prototype LiteralRegistryProtoype;
    static ACLStrategised<char const *> LiteralRegistryEntry_;
    static ACL::Prototype RegexRegistryProtoype;
    static ACLStrategised<char const *> RegexRegistryEntry_;
};

#endif /* SQUID_ACLSERVERNAME_H */

