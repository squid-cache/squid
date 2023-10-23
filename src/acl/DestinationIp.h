/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDESTINATIONIP_H
#define SQUID_ACLDESTINATIONIP_H

#include "acl/Checklist.h"
#include "acl/Ip.h"
#include "ipcache.h"

class ACLDestinationIP : public ACLIP
{
    MEMPROXY_CLASS(ACLDestinationIP);

public:
    static ACLChecklist::AsyncStarter StartLookup;

    char const *typeString() const override;
    const Acl::Options &options() override;
    int match(ACLChecklist *checklist) override;

private:
    Acl::BooleanOptionValue lookupBanned; ///< are DNS lookups allowed?
};

#endif /* SQUID_ACLDESTINATIONIP_H */

