/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#if USE_SQUID_EUI

#include "acl/Arp.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "Debug.h"
#include "eui/Eui48.h"
#include "globals.h"
#include "ip/Address.h"

static void aclParseArpList(SplayNode<Eui::Eui48 *> **curlist);
static int aclMatchArp(SplayNode<Eui::Eui48 *> **dataptr, Ip::Address &c);
static SplayNode<Eui::Eui48 *>::SPLAYCMP aclArpCompare;
static SplayNode<Eui::Eui48 *>::SPLAYWALKEE aclDumpArpListWalkee;

ACL *
ACLARP::clone() const
{
    return new ACLARP(*this);
}

ACLARP::ACLARP (char const *theClass) : data (NULL), class_ (theClass)
{}

ACLARP::ACLARP (ACLARP const & old) : data (NULL), class_ (old.class_)
{
    /* we don't have copy constructors for the data yet */
    assert (!old.data);
}

ACLARP::~ACLARP()
{
    if (data)
        data->destroy(SplayNode<Eui::Eui48*>::DefaultFree);
}

char const *
ACLARP::typeString() const
{
    return class_;
}

bool
ACLARP::empty () const
{
    return data->empty();
}

/* ==== BEGIN ARP ACL SUPPORT ============================================= */

/*
 * From:    dale@server.ctam.bitmcnit.bryansk.su (Dale)
 * To:      wessels@nlanr.net
 * Subject: Another Squid patch... :)
 * Date:    Thu, 04 Dec 1997 19:55:01 +0300
 * ============================================================================
 *
 * Working on setting up a proper firewall for a network containing some
 * Win'95 computers at our Univ, I've discovered that some smart students
 * avoid the restrictions easily just changing their IP addresses in Win'95
 * Contol Panel... It has been getting boring, so I took Squid-1.1.18
 * sources and added a new acl type for hard-wired access control:
 *
 * acl <name> arp <Ethernet address> ...
 *
 * For example,
 *
 * acl students arp 00:00:21:55:ed:22 00:00:21:ff:55:38
 *
 * NOTE: Linux code by David Luyer <luyer@ucs.uwa.edu.au>.
 *       Original (BSD-specific) code no longer works.
 *       Solaris code by R. Gancarz <radekg@solaris.elektrownia-lagisza.com.pl>
 */

Eui::Eui48 *
aclParseArpData(const char *t)
{
    char buf[256];
    Eui::Eui48 *q = new Eui::Eui48;
    debugs(28, 5, "aclParseArpData: " << t);

    if (sscanf(t, "%[0-9a-fA-F:]", buf) != 1) {
        debugs(28, DBG_CRITICAL, "aclParseArpData: Bad ethernet address: '" << t << "'");
        safe_free(q);
        return NULL;
    }

    if (!q->decode(buf)) {
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseArpData: Ignoring invalid ARP acl entry: can't parse '" << buf << "'");
        safe_free(q);
        return NULL;
    }

    return q;
}

/*******************/
/* aclParseArpList */
/*******************/
void
ACLARP::parse()
{
    aclParseArpList(&data);
}

void
aclParseArpList(SplayNode<Eui::Eui48 *> **curlist)
{
    char *t = NULL;
    SplayNode<Eui::Eui48*> **Top = curlist;
    Eui::Eui48 *q = NULL;

    while ((t = strtokFile())) {
        if ((q = aclParseArpData(t)) == NULL)
            continue;

        *Top = (*Top)->insert(q, aclArpCompare);
    }
}

int
ACLARP::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);

    /* IPv6 does not do ARP */
    if (!checklist->src_addr.isIPv4()) {
        debugs(14, 3, "ACLARP::match: IPv4 Required for ARP Lookups. Skipping " << checklist->src_addr );
        return 0;
    }

    return aclMatchArp(&data, checklist->src_addr);
}

/***************/
/* aclMatchArp */
/***************/
int
aclMatchArp(SplayNode<Eui::Eui48 *> **dataptr, Ip::Address &c)
{
    Eui::Eui48 result;
    SplayNode<Eui::Eui48 *> **Top = dataptr;

    if (result.lookup(c)) {
        /* Do ACL match lookup */
        *Top = (*Top)->splay(&result, aclArpCompare);
        debugs(28, 3, "aclMatchArp: '" << c << "' " << (splayLastResult ? "NOT found" : "found"));
        return (0 == splayLastResult);
    }

    /*
     * Address was not found on any interface
     */
    debugs(28, 3, "aclMatchArp: " << c << " NOT found");
    return 0;
}

static int
aclArpCompare(Eui::Eui48 * const &a, Eui::Eui48 * const &b)
{
    return memcmp(a, b, sizeof(Eui::Eui48));
}

static void
aclDumpArpListWalkee(Eui::Eui48 * const &node, void *state)
{
    static char buf[48];
    node->encode(buf, 48);
    static_cast<SBufList *>(state)->push_back(SBuf(buf));
}

SBufList
ACLARP::dump() const
{
    SBufList sl;
    data->walk(aclDumpArpListWalkee, &sl);
    return sl;
}

/* ==== END ARP ACL SUPPORT =============================================== */

#endif /* USE_SQUID_EUI */
