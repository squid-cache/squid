/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/DestinationDomain.h"
#include "acl/DomainData.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "fqdncache.h"
#include "HttpRequest.h"

static void LookupDone(const char *, const Dns::LookupDetails &, void *data);

static void
StartLookup(ACLFilledChecklist &cl, const Acl::Node &)
{
    fqdncache_nbgethostbyaddr(cl.dst_addr, LookupDone, &cl);
}

static void
LookupDone(const char *, const Dns::LookupDetails &details, void *data)
{
    ACLFilledChecklist *checklist = Filled((ACLChecklist*)data);
    checklist->markDestinationDomainChecked();
    checklist->request->recordLookup(details);
    checklist->resumeNonBlockingCheck();
}

/* Acl::DestinationDomainCheck */

const Acl::Options &
Acl::DestinationDomainCheck::options()
{
    static const Acl::BooleanOption LookupBanFlag("-n");
    static const Acl::Options MyOptions = { &LookupBanFlag };
    LookupBanFlag.linkWith(&lookupBanned);
    return MyOptions;
}

int
Acl::DestinationDomainCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    assert(checklist != nullptr && checklist->request != nullptr);

    if (data->match(checklist->request->url.host())) {
        return 1;
    }

    if (lookupBanned) {
        debugs(28, 3, "No-lookup DNS ACL '" << name << "' for " << checklist->request->url.host());
        return 0;
    }

    /* numeric IPA? no, trust the above result. */
    if (!checklist->request->url.hostIsNumeric()) {
        return 0;
    }

    /* do we already have the rDNS? match on it if we do. */
    if (checklist->dst_rdns) {
        debugs(28, 3, "'" << name << "' match with stored rDNS '" << checklist->dst_rdns << "' for " << checklist->request->url.host());
        return data->match(checklist->dst_rdns);
    }

    /* raw IP without rDNS? look it up and wait for the result */
    if (!checklist->dst_addr.fromHost(checklist->request->url.host())) {
        /* not a valid IPA */
        checklist->dst_rdns = xstrdup("invalid");
        return 0;
    }

    const char *fqdn = fqdncache_gethostbyaddr(checklist->dst_addr, FQDN_LOOKUP_IF_MISS);

    if (fqdn) {
        checklist->dst_rdns = xstrdup(fqdn);
        return data->match(fqdn);
    } else if (!checklist->destinationDomainChecked()) {
        debugs(28, 3, "Can't yet compare '" << name << "' ACL for " << checklist->request->url.host());
        if (checklist->goAsync(StartLookup, *this))
            return -1;
        // else fall through to "none" match, hiding the lookup failure (XXX)
    }

    return data->match("none");
}

