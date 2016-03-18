/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/DomainData.h"
#include "acl/RegexData.h"
#include "acl/SourceDomain.h"
#include "fqdncache.h"
#include "HttpRequest.h"

SourceDomainLookup SourceDomainLookup::instance_;

SourceDomainLookup *
SourceDomainLookup::Instance()
{
    return &instance_;
}

void
SourceDomainLookup::checkForAsync(ACLChecklist *checklist) const
{
    fqdncache_nbgethostbyaddr(Filled(checklist)->src_addr, LookupDone, checklist);
}

void
SourceDomainLookup::LookupDone(const char *, const Dns::LookupDetails &details, void *data)
{
    ACLFilledChecklist *checklist = Filled((ACLChecklist*)data);
    checklist->markSourceDomainChecked();
    checklist->request->recordLookup(details);
    checklist->resumeNonBlockingCheck(SourceDomainLookup::Instance());
}

int
ACLSourceDomainStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    const char *fqdn = NULL;
    fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);

    if (fqdn) {
        return data->match(fqdn);
    } else if (!checklist->sourceDomainChecked()) {
        /* FIXME: Using AclMatchedName here is not OO correct. Should find a way to the current acl */
        debugs(28, 3, "aclMatchAcl: Can't yet compare '" << AclMatchedName << "' ACL for '" << checklist->src_addr << "'");
        if (checklist->goAsync(SourceDomainLookup::Instance()))
            return -1;
        // else fall through to "none" match, hiding the lookup failure (XXX)
    }

    return data->match("none");
}

ACLSourceDomainStrategy *
ACLSourceDomainStrategy::Instance()
{
    return &Instance_;
}

ACLSourceDomainStrategy ACLSourceDomainStrategy::Instance_;

