/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_DESTINATIONDOMAIN_H
#define SQUID_SRC_ACL_DESTINATIONDOMAIN_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
#include "dns/forward.h"

/// \ingroup ACLAPI
class ACLDestinationDomainStrategy : public ACLStrategy<char const *>
{

public:
    /* ACLStrategy API */
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override {return true;}
    const Acl::Options &options() override;

private:
    Acl::BooleanOptionValue lookupBanned; ///< Are DNS lookups allowed?
};

/// \ingroup ACLAPI
class DestinationDomainLookup : public ACLChecklist::AsyncState
{

public:
    static DestinationDomainLookup *Instance();
    void checkForAsync(ACLChecklist *)const override;

private:
    static DestinationDomainLookup instance_;
    static void LookupDone(const char *, const Dns::LookupDetails &, void *);
};

#endif /* SQUID_SRC_ACL_DESTINATIONDOMAIN_H */

