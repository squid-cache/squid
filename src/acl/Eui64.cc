/*
 * DEBUG: section 28    Access Control
 * AUTHOR: Amos Jeffries
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

#if USE_SQUID_EUI

#include "acl/Eui64.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "Debug.h"
#include "eui/Eui64.h"
#include "ip/Address.h"
#include "wordlist.h"

static void aclParseEuiList(SplayNode<Eui::Eui64 *> **curlist);
static int aclMatchEui(SplayNode<Eui::Eui64 *> **dataptr, Ip::Address &c);
static SplayNode<Eui::Eui64 *>::SPLAYCMP aclEui64Compare;
static SplayNode<Eui::Eui64 *>::SPLAYWALKEE aclDumpEuiListWalkee;

ACL *
ACLEui64::clone() const
{
    return new ACLEui64(*this);
}

ACLEui64::ACLEui64 (char const *theClass) : data (NULL), class_ (theClass)
{}

ACLEui64::ACLEui64 (ACLEui64 const & old) : data (NULL), class_ (old.class_)
{
    /* we don't have copy constructors for the data yet */
    assert (!old.data);
}

ACLEui64::~ACLEui64()
{
    if (data)
        data->destroy(SplayNode<Eui::Eui64*>::DefaultFree);
}

char const *
ACLEui64::typeString() const
{
    return class_;
}

bool
ACLEui64::empty () const
{
    return data->empty();
}

Eui::Eui64 *
aclParseEuiData(const char *t)
{
    char buf[256];
    Eui::Eui64 *q = new Eui::Eui64;
    debugs(28, 5, "aclParseEuiData: " << t);

    if (sscanf(t, "%[0-9a-fA-F:]", buf) != 1) {
        debugs(28, DBG_CRITICAL, "aclParseEuiData: Bad EUI-64 address: '" << t << "'");
        safe_free(q);
        return NULL;
    }

    if (!q->decode(buf)) {
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseEuiData: Ignoring invalid EUI-64 acl entry: can't parse '" << buf << "'");
        safe_free(q);
        return NULL;
    }

    return q;
}

/*******************/
/* aclParseEuiList */
/*******************/
void
ACLEui64::parse()
{
    aclParseEuiList(&data);
}

void
aclParseEuiList(SplayNode<Eui::Eui64 *> **curlist)
{
    char *t = NULL;
    SplayNode<Eui::Eui64*> **Top = curlist;
    Eui::Eui64 *q = NULL;

    while ((t = strtokFile())) {
        if ((q = aclParseEuiData(t)) == NULL)
            continue;

        *Top = (*Top)->insert(q, aclEui64Compare);
    }
}

int
ACLEui64::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);

    /* IPv4 does not do EUI-64 (yet) */
    if (!checklist->src_addr.IsIPv6()) {
        debugs(14, 3, "ACLEui64::match: IPv6 Required for EUI-64 Lookups. Skipping " << checklist->src_addr );
        return 0;
    }

    return aclMatchEui(&data, checklist->src_addr);
}

/***************/
/* aclMatchEui */
/***************/
int
aclMatchEui(SplayNode<Eui::Eui64 *> **dataptr, Ip::Address &c)
{
    Eui::Eui64 result;
    SplayNode<Eui::Eui64 *> **Top = dataptr;

    if (result.lookup(c)) {
        /* Do ACL match lookup */
        *Top = (*Top)->splay(&result, aclEui64Compare);
        debugs(28, 3, "aclMatchEui: '" << c << "' " << (splayLastResult ? "NOT found" : "found"));
        return (0 == splayLastResult);
    }

    /*
     * Address was not found on any interface
     */
    debugs(28, 3, "aclMatchEui: " << c << " NOT found");
    return 0;
}

static int
aclEui64Compare(Eui::Eui64 * const &a, Eui::Eui64 * const &b)
{
    return memcmp(a, b, sizeof(Eui::Eui64));
}

static void
aclDumpEuiListWalkee(Eui::Eui64 * const &node, void *state)
{
    static char buf[48];
    node->encode(buf, 48);
    wordlistAdd((wordlist **)state, buf);
}

wordlist *
ACLEui64::dump() const
{
    wordlist *w = NULL;
    data->walk(aclDumpEuiListWalkee, &w);
    return w;
}

#endif /* USE_SQUID_EUI */
