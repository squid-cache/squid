/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLANNOTATECLIENT
#define SQUID_ACLANNOTATECLIENT

#include "acl/Strategised.h"
#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLAnnotateClientStrategy : public ACLStrategy<NotePairs::Entry *>
{
public:
    static ACLAnnotateClientStrategy *Instance();
    ACLAnnotateClientStrategy(ACLAnnotateClientStrategy const &) = delete;
    ACLAnnotateClientStrategy& operator=(ACLAnnotateClientStrategy const &) = delete;

    virtual bool requiresRequest() const { return true; }
    virtual int match(ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);

private:
    static ACLAnnotateClientStrategy Instance_;
    ACLAnnotateClientStrategy() { }
};

/// \ingroup ACLAPI
class ACLAnnotateClient
{
private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<NotePairs::Entry *> RegistryEntry_;
};

#endif /* SQUID_ACLANNOTATECLIENT */

