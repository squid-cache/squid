/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
#include "Debug.h"
#include "eui/Eui48.h"
#include "globals.h"
#include "ip/Address.h"

#include <algorithm>

ACL *
ACLARP::clone() const
{
    return new ACLARP(*this);
}

ACLARP::ACLARP (char const *theClass) : class_ (theClass)
{}

ACLARP::ACLARP (ACLARP const & old) : class_ (old.class_), aclArpData(old.aclArpData)
{
}

char const *
ACLARP::typeString() const
{
    return class_;
}

bool
ACLARP::empty () const
{
    return aclArpData.empty();
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
        delete q;
        return NULL;
    }

    if (!q->decode(buf)) {
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseArpData: Ignoring invalid ARP acl entry: can't parse '" << buf << "'");
        delete q;
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
    while (const char *t = ConfigParser::strtokFile()) {
        if (Eui::Eui48 *q = aclParseArpData(t)) {
            aclArpData.insert(*q);
            delete q;
        }
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

    Eui::Eui48 lookingFor;
    lookingFor.lookup(checklist->src_addr);
    return (aclArpData.find(lookingFor) != aclArpData.end());
}

SBufList
ACLARP::dump() const
{
    SBufList sl;
    for (auto i = aclArpData.begin(); i != aclArpData.end(); ++i) {
        char buf[48];
        i->encode(buf,48);
        sl.push_back(SBuf(buf));
    }
    return sl;
}

/* ==== END ARP ACL SUPPORT =============================================== */

#endif /* USE_SQUID_EUI */

