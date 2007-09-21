/*
 * $Id: ACLSourceDomain.cc,v 1.6 2007/09/21 11:41:52 amosjeffries Exp $
 *
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
#include "ACLSourceDomain.h"
#include "ACLChecklist.h"
#include "ACLRegexData.h"
#include "ACLDomainData.h"

SourceDomainLookup SourceDomainLookup::instance_;

SourceDomainLookup *
SourceDomainLookup::Instance()
{
    return &instance_;
}

void
SourceDomainLookup::checkForAsync(ACLChecklist *checklist) const
{
    checklist->asyncInProgress(true);
    fqdncache_nbgethostbyaddr(checklist->src_addr, LookupDone, checklist);
}

void
SourceDomainLookup::LookupDone(const char *fqdn, void *data)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    assert (checklist->asyncState() == SourceDomainLookup::Instance());

    checklist->asyncInProgress(false);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->markSourceDomainChecked();
    checklist->check();
}

ACL::Prototype ACLSourceDomain::LiteralRegistryProtoype(&ACLSourceDomain::LiteralRegistryEntry_, "srcdomain");
ACLStrategised<char const *> ACLSourceDomain::LiteralRegistryEntry_(new ACLDomainData, ACLSourceDomainStrategy::Instance(), "srcdomain");
ACL::Prototype ACLSourceDomain::RegexRegistryProtoype(&ACLSourceDomain::RegexRegistryEntry_, "srcdom_regex");
ACLStrategised<char const *> ACLSourceDomain::RegexRegistryEntry_(new ACLRegexData,ACLSourceDomainStrategy::Instance() ,"srcdom_regex");

int
ACLSourceDomainStrategy::match (ACLData<MatchType> * &data, ACLChecklist *checklist)
{
    const char *fqdn = NULL;
    fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);

    if (fqdn) {
        return data->match(fqdn);
    } else if (!checklist->sourceDomainChecked()) {
        /* FIXME: Using AclMatchedName here is not OO correct. Should find a way to the current acl */
        debugs(28, 3, "aclMatchAcl: Can't yet compare '" << AclMatchedName << "' ACL for '" << inet_ntoa(checklist->src_addr) << "'");
        checklist->changeState(SourceDomainLookup::Instance());
        return 0;
    }

    return data->match("none");
}

ACLSourceDomainStrategy *
ACLSourceDomainStrategy::Instance()
{
    return &Instance_;
}

ACLSourceDomainStrategy ACLSourceDomainStrategy::Instance_;
