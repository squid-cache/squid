/*
 * $Id: ACLDomainData.cc,v 1.13 2007/04/28 22:26:37 hno Exp $
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
#include "ACLDomainData.h"
#include "authenticate.h"
#include "ACLChecklist.h"
#include "wordlist.h"

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLDomainData::~ACLDomainData()
{
    if (domains)
        domains->destroy(xRefFree);
}

template<class T>
inline int
splaystrcasecmp (T&l, T&r)
{
    return strcasecmp ((char *)l,(char *)r);
}

template<class T>
inline int
splaystrcmp (T&l, T&r)
{
    return strcmp ((char *)l,(char *)r);
}

/* general compare functions, these are used for tree search algorithms
 * so they return <0, 0 or >0 */

/* compare a host and a domain */

static int
aclHostDomainCompare( char *const &a, char * const &b)
{
    const char *h = (const char *)a;
    const char *d = (const char *)b;
    return matchDomainName(h, d);
}


/* compare two domains */

template<class T>
int
aclDomainCompare(T const &a, T const &b)
{
    char * const d1 = (char *const)b;
    char * const d2 = (char *const )a;
    int ret;
    ret = aclHostDomainCompare(d1, d2);

    if (ret != 0) {
        char *const d3 = d2;
        char *const d4 = d1;
        ret = aclHostDomainCompare(d3, d4);
    }

    /* FIXME this warning may display d1 and d2 when it should display d3 and d4 */
    if (ret == 0) {
        debugs(28, 0, "WARNING: '" << d1 << "' is a subdomain of '" << d2 << "'");
        debugs(28, 0, "WARNING: because of this '" << (char *) a << "' is ignored to keep splay tree searching predictable");
        debugs(28, 0, "WARNING: You should probably remove '" << d1 << "' from the ACL named '" << AclMatchedName << "'");
    }

    return ret;
}

bool
ACLDomainData::match(char const *host)
{
    if (host == NULL)
        return 0;

    debugs(28, 3, "aclMatchDomainList: checking '" << host << "'");

    domains = domains->splay((char *)host, aclHostDomainCompare);

    debugs(28, 3, "aclMatchDomainList: '" << host << "' " << (splayLastResult ? "NOT found" : "found"));

    return !splayLastResult;
}

static void
aclDumpDomainListWalkee(char * const & node_data, void *outlist)
{
    /* outlist is really a wordlist ** */
    wordlistAdd((wordlist **)outlist, (char const *)node_data);
}

wordlist *
ACLDomainData::dump()
{
    wordlist *wl = NULL;
    /* damn this is VERY inefficient for long ACL lists... filling
     * a wordlist this way costs Sum(1,N) iterations. For instance
     * a 1000-elements list will be filled in 499500 iterations.
     */
    domains->walk(aclDumpDomainListWalkee, &wl);
    return wl;
}

void
ACLDomainData::parse()
{
    char *t = NULL;

    while ((t = strtokFile())) {
        Tolower(t);
        domains = domains->insert(xstrdup(t), aclDomainCompare);
    }
}

bool
ACLDomainData::empty() const
{
    return domains->empty();
}


ACLData<char const *> *
ACLDomainData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!domains);
    return new ACLDomainData;
}
