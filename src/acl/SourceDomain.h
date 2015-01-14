/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSOURCEDOMAIN_H
#define SQUID_ACLSOURCEDOMAIN_H
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"

class ACLSourceDomainStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLSourceDomainStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSourceDomainStrategy(ACLSourceDomainStrategy const &);

private:
    static ACLSourceDomainStrategy Instance_;
    ACLSourceDomainStrategy() {}

    ACLSourceDomainStrategy&operator=(ACLSourceDomainStrategy const &);
};

class SourceDomainLookup : public ACLChecklist::AsyncState
{

public:
    static SourceDomainLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static SourceDomainLookup instance_;
    static void LookupDone(const char *, const DnsLookupDetails &, void *);
};

class ACLSourceDomain
{

private:
    static ACL::Prototype LiteralRegistryProtoype;
    static ACLStrategised<char const *> LiteralRegistryEntry_;
    static ACL::Prototype RegexRegistryProtoype;
    static ACLStrategised<char const *> RegexRegistryEntry_;
};

#endif /* SQUID_ACLSOURCEDOMAIN_H */

