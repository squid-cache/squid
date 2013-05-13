/*
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/DestinationIp.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "HttpRequest.h"
#include "SquidConfig.h"

ACLFlag ACLDestinationIP::SupportedFlags[] = {ACL_F_NO_LOOKUP, ACL_F_END};

char const *
ACLDestinationIP::typeString() const
{
    return "dst";
}

int
ACLDestinationIP::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);

    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we will force DIRECT and only to the original client destination.
    // In which case, we also need this ACL to accurately match the destination
    if (Config.onoff.client_dst_passthru && (checklist->request->flags.intercepted || checklist->request->flags.interceptTproxy)) {
        assert(checklist->conn() && checklist->conn()->clientConnection != NULL);
        return ACLIP::match(checklist->conn()->clientConnection->local);
    }

    if (flags.isSet(ACL_F_NO_LOOKUP)) {
        if (!checklist->request->GetHostIsNumeric()) {
            debugs(28, 3, "aclMatchAcl:  No-lookup DNS ACL '" << AclMatchedName << "' for '" << checklist->request->GetHost() << "'");
            return 0;
        }

        if (ACLIP::match(checklist->request->host_addr))
            return 1;
        return 0;
    }

    const ipcache_addrs *ia = ipcache_gethostbyname(checklist->request->GetHost(), IP_LOOKUP_IF_MISS);

    if (ia) {
        /* Entry in cache found */

        for (int k = 0; k < (int) ia->count; ++k) {
            if (ACLIP::match(ia->in_addrs[k]))
                return 1;
        }

        return 0;
    } else if (!checklist->request->flags.destinationIpLookedUp) {
        /* No entry in cache, lookup not attempted */
        debugs(28, 3, "aclMatchAcl: Can't yet compare '" << name << "' ACL for '" << checklist->request->GetHost() << "'");
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
    ipcache_nbgethostbyname(checklist->request->GetHost(), LookupDone, checklist);
}

void
DestinationIPLookup::LookupDone(const ipcache_addrs *, const DnsLookupDetails &details, void *data)
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
