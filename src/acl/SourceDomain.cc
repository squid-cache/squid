/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/DomainData.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/SourceDomain.h"
#include "fqdncache.h"
#include "HttpRequest.h"

static void LookupDone(const char *, const Dns::LookupDetails &, void *data);

static void
StartLookup(ACLChecklist &checklist, const ACL &)
{
    fqdncache_nbgethostbyaddr(Filled(&checklist)->src_addr, LookupDone, &checklist);
}

static void
LookupDone(const char *, const Dns::LookupDetails &details, void *data)
{
    ACLFilledChecklist *checklist = Filled((ACLChecklist*)data);
    checklist->markSourceDomainChecked();
    checklist->request->recordLookup(details);
    checklist->resumeNonBlockingCheck(StartLookup);
}

int
Acl::SourceDomainCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    const char *fqdn = nullptr;
    fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);

    if (fqdn) {
        return data->match(fqdn);
    } else if (!checklist->sourceDomainChecked()) {
        // TODO: Using AclMatchedName here is not OO correct. Should find a way to the current acl
        debugs(28, 3, "aclMatchAcl: Can't yet compare '" << AclMatchedName << "' ACL for '" << checklist->src_addr << "'");
        if (checklist->goAsync(StartLookup, *this))
            return -1;
        // else fall through to "none" match, hiding the lookup failure (XXX)
    }

    return data->match("none");
}

