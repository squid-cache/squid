/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SOURCEDOMAIN_H
#define SQUID_SRC_ACL_SOURCEDOMAIN_H
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategy.h"
#include "dns/forward.h"

class ACLSourceDomainStrategy : public ACLStrategy<char const *>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

class SourceDomainLookup : public ACLChecklist::AsyncState
{

public:
    static SourceDomainLookup *Instance();
    void checkForAsync(ACLChecklist *)const override;

private:
    static SourceDomainLookup instance_;
    static void LookupDone(const char *, const Dns::LookupDetails &, void *);
};

#endif /* SQUID_SRC_ACL_SOURCEDOMAIN_H */

