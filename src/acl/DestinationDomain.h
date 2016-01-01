/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDESTINATIONDOMAIN_H
#define SQUID_ACLDESTINATIONDOMAIN_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"

/// \ingroup ACLAPI
class ACLDestinationDomainStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLDestinationDomainStrategy *Instance();
    virtual bool requiresRequest() const {return true;}

    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends
     */
    ACLDestinationDomainStrategy(ACLDestinationDomainStrategy const &);

private:
    static ACLDestinationDomainStrategy Instance_;
    ACLDestinationDomainStrategy() {}

    ACLDestinationDomainStrategy&operator=(ACLDestinationDomainStrategy const &);
};

/// \ingroup ACLAPI
class DestinationDomainLookup : public ACLChecklist::AsyncState
{

public:
    static DestinationDomainLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static DestinationDomainLookup instance_;
    static void LookupDone(const char *, const DnsLookupDetails &, void *);
};

/// \ingroup ACLAPI
class ACLDestinationDomain
{

private:
    static ACL::Prototype LiteralRegistryProtoype;
    static ACLStrategised<char const *> LiteralRegistryEntry_;
    static ACL::Prototype RegexRegistryProtoype;
    static ACLStrategised<char const *> RegexRegistryEntry_;
};

#endif /* SQUID_ACLDESTINATIONDOMAIN_H */

