/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#if USE_SQUID_EUI

#include "acl/Eui64.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "debug/Stream.h"
#include "eui/Eui64.h"
#include "globals.h"
#include "ip/Address.h"

ACLEui64::ACLEui64 (char const *theClass) : class_ (theClass)
{}

char const *
ACLEui64::typeString() const
{
    return class_;
}

bool
ACLEui64::empty () const
{
    return eui64Data.empty();
}

static Eui::Eui64 *
aclParseEuiData(const char *t)
{
    char buf[256];
    Eui::Eui64 *q = new Eui::Eui64;
    debugs(28, 5, "aclParseEuiData: " << t);

    if (sscanf(t, "%[0-9a-fA-F:]", buf) != 1) {
        debugs(28, DBG_CRITICAL, "ERROR: aclParseEuiData: Bad EUI-64 address: '" << t << "'");
        delete q;
        return nullptr;
    }

    if (!q->decode(buf)) {
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: aclParseEuiData: Ignoring invalid EUI-64 acl entry: cannot parse '" << buf << "'");
        delete q;
        return nullptr;
    }

    return q;
}

/*******************/
/* aclParseEuiList */
/*******************/
void
ACLEui64::parse()
{
    while (const char * t = ConfigParser::strtokFile()) {
        if (Eui::Eui64 * q = aclParseEuiData(t)) {
            eui64Data.insert(*q);
            delete q;
        }
    }
}

int
ACLEui64::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);

    /* IPv4 does not do EUI-64 (yet) */
    if (!checklist->src_addr.isIPv6()) {
        debugs(14, 3, "ACLEui64::match: IPv6 Required for EUI-64 Lookups. Skipping " << checklist->src_addr );
        return 0;
    }

    Eui::Eui64 lookingFor;
    if (lookingFor.lookup(checklist->src_addr)) {
        bool found = (eui64Data.find(lookingFor) != eui64Data.end());
        debugs(28, 3,  checklist->src_addr << "' " << (found ? "found" : "NOT found"));
        return found;
    }

    debugs(28, 3, checklist->src_addr << " NOT found");
    return 0;
}

SBufList
ACLEui64::dump() const
{
    SBufList sl;
    for (auto i = eui64Data.begin(); i != eui64Data.end(); ++i) {
        static char buf[48];
        i->encode(buf,48);
        sl.push_back(SBuf(buf));
    }
    return sl;
}

#endif /* USE_SQUID_EUI */

