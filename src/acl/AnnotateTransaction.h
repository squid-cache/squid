/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLANNOTATETRANSACTION
#define SQUID_ACLANNOTATETRANSACTION

#include "acl/Strategised.h"
#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLAnnotateTransactionStrategy : public ACLStrategy<NotePairs::Entry *>
{
public:
    virtual int match(ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const { return true; }

    static ACLAnnotateTransactionStrategy *Instance();
    ACLAnnotateTransactionStrategy(ACLAnnotateTransactionStrategy const &) = delete;
    ACLAnnotateTransactionStrategy& operator=(ACLAnnotateTransactionStrategy const &) = delete;

private:
    static ACLAnnotateTransactionStrategy Instance_;
    ACLAnnotateTransactionStrategy() {}
};

/// \ingroup ACLAPI
class ACLAnnotateTransaction
{
private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<NotePairs::Entry *> RegistryEntry_;
};

#endif /* SQUID_ACLANNOTATETRANSACTION */

