/*
 * $Id: ACLSourceDomain.cc,v 1.1 2003/02/16 02:23:18 robertc Exp $
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
#include "authenticate.h"
#include "ACLChecklist.h"
#include "ACLRegexData.h"
#include "ACLDomainData.h"

MemPool *ACLSourceDomain::Pool(NULL);
void *
ACLSourceDomain::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ACLSourceDomain));
    if (!Pool)
	Pool = memPoolCreate("ACLSourceDomain", sizeof (ACLSourceDomain));
    return memPoolAlloc(Pool);
}

void
ACLSourceDomain::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
ACLSourceDomain::deleteSelf() const
{
    delete this;
}

ACLSourceDomain::~ACLSourceDomain()
{
    data->deleteSelf();
}

ACLSourceDomain::ACLSourceDomain(ACLData *newData, char const *theType) : data (newData), type_(theType) {}
ACLSourceDomain::ACLSourceDomain (ACLSourceDomain const &old) : data (old.data->clone()), type_(old.type_)
{
}
ACLSourceDomain &
ACLSourceDomain::operator= (ACLSourceDomain const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLSourceDomain::typeString() const
{
    return type_;
}

void
ACLSourceDomain::parse()
{
    data->parse();
}

int
ACLSourceDomain::match(ACLChecklist *checklist)
{
    const char *fqdn = NULL;
    fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);
    if (fqdn) {
	return data->match(fqdn);
    } else if (!checklist->sourceDomainChecked()) {
	debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		      name, inet_ntoa(checklist->src_addr));
	checklist->changeState(SourceDomainLookup::Instance());
	return 0;
    }
    return data->match("none");
}

wordlist *
ACLSourceDomain::dump() const
{
    return data->dump();
}

bool
ACLSourceDomain::valid () const
{
    return data != NULL;
}

SourceDomainLookup SourceDomainLookup::instance_;

SourceDomainLookup *
SourceDomainLookup::Instance()
{
    return &instance_;
}

void
SourceDomainLookup::checkForAsync(ACLChecklist *checklist)const
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
ACLSourceDomain ACLSourceDomain::LiteralRegistryEntry_(new ACLDomainData, "srcdomain");
ACL::Prototype ACLSourceDomain::RegexRegistryProtoype(&ACLSourceDomain::RegexRegistryEntry_, "srcdom_regex");
ACLSourceDomain ACLSourceDomain::RegexRegistryEntry_(new ACLRegexData, "srcdom_regex");

ACL *
ACLSourceDomain::clone() const
{
    return new ACLSourceDomain(*this);
}
