/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/DestinationDomain.h"
#include "acl/DomainData.h"
#include "acl/RegexData.h"
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
DestinationDomainLookup::LookupDone(const char *, const Dns::LookupDetails &details, void *data)
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

    if (data->match(checklist->request->url.host())) {
        return 1;
    }

    if (flags.isSet(ACL_F_NO_LOOKUP)) {
        debugs(28, 3, "No-lookup DNS ACL '" << AclMatchedName << "' for " << checklist->request->url.host());
        return 0;
    }

    /* numeric IPA? no, trust the above result. */
    if (!checklist->request->url.hostIsNumeric()) {
        return 0;
    }

    /* do we already have the rDNS? match on it if we do. */
    if (checklist->dst_rdns) {
        debugs(28, 3, "'" << AclMatchedName << "' match with stored rDNS '" << checklist->dst_rdns << "' for " << checklist->request->url.host());
        return data->match(checklist->dst_rdns);
    }

    /* raw IP without rDNS? look it up and wait for the result */
    const ipcache_addrs *ia = ipcacheCheckNumeric(checklist->request->url.host());
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
        debugs(28, 3, "Can't yet compare '" << AclMatchedName << "' ACL for " << checklist->request->url.host());
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

