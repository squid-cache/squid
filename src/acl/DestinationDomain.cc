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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/DestinationDomain.h"
#include "acl/Checklist.h"
#include "acl/RegexData.h"
#include "acl/DomainData.h"
#include "fqdncache.h"
#include "HttpRequest.h"
#include "ipcache.h"

DestinationDomainLookup DestinationDomainLookup::instance_;

DestinationDomainLookup *
DestinationDomainLookup::Instance()
{
    return &instance_;
}

void
DestinationDomainLookup::checkForAsync(ACLChecklist *cl) const
{
    ACLFilledChecklist *checklist = Filled(cl);
    fqdncache_nbgethostbyaddr(checklist->dst_addr, LookupDone, checklist);
}

void
DestinationDomainLookup::LookupDone(const char *fqdn, const DnsLookupDetails &details, void *data)
{
    ACLFilledChecklist *checklist = Filled((ACLChecklist*)data);
    checklist->markDestinationDomainChecked();
    checklist->request->recordLookup(details);
    checklist->resumeNonBlockingCheck(DestinationDomainLookup::Instance());
}

int
ACLDestinationDomainStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &flags)
{
    assert(checklist != NULL && checklist->request != NULL);

    if (data->match(checklist->request->GetHost())) {
        return 1;
    }

    if (flags.isSet(ACL_F_NO_LOOKUP)) {
        debugs(28, 3, "aclMatchAcl:  No-lookup DNS ACL '" << AclMatchedName << "' for '" << checklist->request->GetHost() << "'");
        return 0;
    }

    /* numeric IPA? no, trust the above result. */
    if (checklist->request->GetHostIsNumeric() == 0) {
        return 0;
    }

    /* do we already have the rDNS? match on it if we do. */
    if (checklist->dst_rdns) {
        debugs(28, 3, "aclMatchAcl: '" << AclMatchedName << "' match with stored rDNS '" << checklist->dst_rdns << "' for '" << checklist->request->GetHost() << "'");
        return data->match(checklist->dst_rdns);
    }

    /* raw IP without rDNS? look it up and wait for the result */
    const ipcache_addrs *ia = ipcacheCheckNumeric(checklist->request->GetHost());
    if (!ia) {
        /* not a valid IPA */
        checklist->dst_rdns = xstrdup("invalid");
        return 0;
    }

    checklist->dst_addr = ia->in_addrs[0];
    const char *fqdn = fqdncache_gethostbyaddr(checklist->dst_addr, FQDN_LOOKUP_IF_MISS);

    if (fqdn) {
        checklist->dst_rdns = xstrdup(fqdn);
        return data->match(fqdn);
    } else if (!checklist->destinationDomainChecked()) {
        /* FIXME: Using AclMatchedName here is not OO correct. Should find a way to the current acl */
        debugs(28, 3, "aclMatchAcl: Can't yet compare '" << AclMatchedName << "' ACL for '" << checklist->request->GetHost() << "'");
        if (checklist->goAsync(DestinationDomainLookup::Instance()))
            return -1;
        // else fall through to "none" match, hiding the lookup failure (XXX)
    }

    return data->match("none");
}

ACLDestinationDomainStrategy *
ACLDestinationDomainStrategy::Instance()
{
    return &Instance_;
}

ACLDestinationDomainStrategy ACLDestinationDomainStrategy::Instance_;
