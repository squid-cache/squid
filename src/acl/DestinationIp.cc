/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/DestinationIp.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "SquidConfig.h"

char const *
ACLDestinationIP::typeString() const
{
    return "dst";
}

const Acl::Options &
ACLDestinationIP::options()
{
    static const Acl::BooleanOption LookupBan;
    static const Acl::Options MyOptions = { { "-n", &LookupBan } };
    LookupBan.linkWith(&lookupBanned);
    return MyOptions;
}

int
ACLDestinationIP::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);

    // if there is no HTTP request details fallback to the dst_addr
    if (!checklist->request)
        return ACLIP::match(checklist->dst_addr);

    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we will force DIRECT and only to the original client destination.
    // In which case, we also need this ACL to accurately match the destination
    if (Config.onoff.client_dst_passthru && (checklist->request->flags.intercepted || checklist->request->flags.interceptTproxy)) {
        const auto conn = checklist->conn();
        return (conn && conn->clientConnection) ?
               ACLIP::match(conn->clientConnection->local) : -1;
    }

    if (lookupBanned) {
        if (!checklist->request->url.hostIsNumeric()) {
            debugs(28, 3, "No-lookup DNS ACL '" << AclMatchedName << "' for " << checklist->request->url.host());
            return 0;
        }

        if (ACLIP::match(checklist->request->url.hostIP()))
            return 1;
        return 0;
    }

    const ipcache_addrs *ia = ipcache_gethostbyname(checklist->request->url.host(), IP_LOOKUP_IF_MISS);

    if (ia) {
        /* Entry in cache found */

        for (int k = 0; k < (int) ia->count; ++k) {
            if (ACLIP::match(ia->in_addrs[k]))
                return 1;
        }

        return 0;
    } else if (!checklist->request->flags.destinationIpLookedUp) {
        /* No entry in cache, lookup not attempted */
        debugs(28, 3, "can't yet compare '" << name << "' ACL for " << checklist->request->url.host());
        if (checklist->goAsync(DestinationIPLookup::Instance()))
            return -1;
        // else fall through to mismatch, hiding the lookup failure (XXX)
    }

    return 0;
}

DestinationIPLookup DestinationIPLookup::instance_;

DestinationIPLookup *
DestinationIPLookup::Instance()
{
    return &instance_;
}

void
DestinationIPLookup::checkForAsync(ACLChecklist *cl)const
{
    ACLFilledChecklist *checklist = Filled(cl);
    ipcache_nbgethostbyname(checklist->request->url.host(), LookupDone, checklist);
}

void
DestinationIPLookup::LookupDone(const ipcache_addrs *, const Dns::LookupDetails &details, void *data)
{
    ACLFilledChecklist *checklist = Filled((ACLChecklist*)data);
    checklist->request->flags.destinationIpLookedUp = true;
    checklist->request->recordLookup(details);
    checklist->resumeNonBlockingCheck(DestinationIPLookup::Instance());
}

ACL *
ACLDestinationIP::clone() const
{
    return new ACLDestinationIP(*this);
}

