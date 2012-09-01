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
#include "acl/StringData.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "Debug.h"
#include "wordlist.h"

ACLStringData::ACLStringData() : values (NULL)
{}

ACLStringData::ACLStringData(ACLStringData const &old) : values (NULL)
{
    assert (!old.values);
}

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLStringData::~ACLStringData()
{
    if (values)
        values->destroy(xRefFree);
}

static int
splaystrcmp (char * const &l, char * const &r)
{
    return strcmp (l,r);
}

bool
ACLStringData::match(char const *toFind)
{
    if (!values || !toFind)
        return 0;

    debugs(28, 3, "aclMatchStringList: checking '" << toFind << "'");

    values = values->splay((char *)toFind, splaystrcmp);

    debugs(28, 3, "aclMatchStringList: '" << toFind << "' " << (splayLastResult ? "NOT found" : "found"));

    return !splayLastResult;
}

static void
aclDumpStringWalkee(char * const & node_data, void *outlist)
{
    /* outlist is really a wordlist ** */
    wordlistAdd((wordlist **)outlist, node_data);
}

wordlist *
ACLStringData::dump()
{
    wordlist *wl = NULL;
    /* damn this is VERY inefficient for long ACL lists... filling
     * a wordlist this way costs Sum(1,N) iterations. For instance
     * a 1000-elements list will be filled in 499500 iterations.
     */
    values->walk(aclDumpStringWalkee, &wl);
    return wl;
}

void
ACLStringData::parse()
{
    char *t;

    while ((t = strtokFile()))
        values = values->insert(xstrdup(t), splaystrcmp);
}

bool
ACLStringData::empty() const
{
    return values->empty();
}

ACLData<char const *> *
ACLStringData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!values);
    return new ACLStringData(*this);
}
