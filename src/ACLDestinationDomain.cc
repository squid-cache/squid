/*
 * $Id: ACLDestinationDomain.cc,v 1.4 2003/07/11 01:40:34 robertc Exp $
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
#include "ACLDestinationDomain.h"
#include "authenticate.h"
#include "ACLChecklist.h"
#include "ACLRegexData.h"
#include "ACLDomainData.h"
#include "HttpRequest.h"

MemPool *ACLDestinationDomain::Pool(NULL);
void *
ACLDestinationDomain::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ACLDestinationDomain));

    if (!Pool)
        Pool = memPoolCreate("ACLDestinationDomain", sizeof (ACLDestinationDomain));

    return memPoolAlloc(Pool);
}

void
ACLDestinationDomain::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
ACLDestinationDomain::deleteSelf() const
{
    delete this;
}

ACLDestinationDomain::~ACLDestinationDomain()
{
    data->deleteSelf();
}

ACLDestinationDomain::ACLDestinationDomain(ACLData<char const *> *newData, char const *theType) : data (newData), type_(theType) {}

ACLDestinationDomain::ACLDestinationDomain (ACLDestinationDomain const &old) : data (old.data->clone()), type_(old.type_)
{}

ACLDestinationDomain &
ACLDestinationDomain::operator= (ACLDestinationDomain const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLDestinationDomain::typeString() const
{
    return type_;
}

void
ACLDestinationDomain::parse()
{
    data->parse();
}

int
ACLDestinationDomain::match(ACLChecklist *checklist)
{
    const ipcache_addrs *ia = NULL;

    if ((ia = ipcacheCheckNumeric(checklist->request->host)) == NULL)
        return data->match(checklist->request->host);

    const char *fqdn = NULL;

    fqdn = fqdncache_gethostbyaddr(ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);

    if (fqdn)
        return data->match(fqdn);

    if (!checklist->destinationDomainChecked()) {
        debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
                      name, inet_ntoa(ia->in_addrs[0]));
        checklist->changeState(DestinationDomainLookup::Instance());
        return 0;
    }

    return data->match("none");
}

wordlist *
ACLDestinationDomain::dump() const
{
    return data->dump();
}

bool
ACLDestinationDomain::valid () const
{
    return data != NULL;
}

DestinationDomainLookup DestinationDomainLookup::instance_;

DestinationDomainLookup *
DestinationDomainLookup::Instance()
{
    return &instance_;
}

void
DestinationDomainLookup::checkForAsync(ACLChecklist *checklist)const
{

    ipcache_addrs *ia;
    ia = ipcacheCheckNumeric(checklist->request->host);

    if (ia == NULL) {
        /* Make fatal? XXX this is checked during match() */
        checklist->markDestinationDomainChecked();
        checklist->changeState (ACLChecklist::NullState::Instance());
    } else {
        checklist->asyncInProgress(true);
        checklist->dst_addr = ia->in_addrs[0];
        fqdncache_nbgethostbyaddr(checklist->dst_addr,
                                  LookupDone, checklist);
    }
}

void
DestinationDomainLookup::LookupDone(const char *fqdn, void *data)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    assert (checklist->asyncState() == DestinationDomainLookup::Instance());

    checklist->asyncInProgress(false);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->markDestinationDomainChecked();
    checklist->check();
}

ACL::Prototype ACLDestinationDomain::LiteralRegistryProtoype(&ACLDestinationDomain::LiteralRegistryEntry_, "dstdomain");
ACL::Prototype ACLDestinationDomain::LegacyRegistryProtoype(&ACLDestinationDomain::LiteralRegistryEntry_, "domain");
ACLDestinationDomain ACLDestinationDomain::LiteralRegistryEntry_(new ACLDomainData, "dstdomain");
ACL::Prototype ACLDestinationDomain::RegexRegistryProtoype(&ACLDestinationDomain::RegexRegistryEntry_, "dstdom_regex");
ACLDestinationDomain ACLDestinationDomain::RegexRegistryEntry_(new ACLRegexData, "dstdom_regex");

ACL *
ACLDestinationDomain::clone() const
{
    return new ACLDestinationDomain(*this);
}
