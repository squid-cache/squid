/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_DESTINATIONIP_H
#define SQUID_SRC_ACL_DESTINATIONIP_H

#include "acl/Checklist.h"
#include "acl/Ip.h"
#include "ipcache.h"

class ACLDestinationIP : public ACLIP
{
    MEMPROXY_CLASS(ACLDestinationIP);

public:
    static void StartLookup(ACLFilledChecklist &, const Acl::Node &);

    char const *typeString() const override;
    const Acl::Options &options() override;
    int match(ACLChecklist *checklist) override;

private:
    static void LookupDone(const ipcache_addrs *, const Dns::LookupDetails &, void *data);

    Acl::BooleanOptionValue lookupBanned; ///< are DNS lookups allowed?
};

#endif /* SQUID_SRC_ACL_DESTINATIONIP_H */

