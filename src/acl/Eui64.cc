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

#include "acl/Eui64.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "Debug.h"
#include "eui/Eui64.h"
#include "globals.h"
#include "ip/Address.h"

static void aclParseEuiList(Splay<Eui::Eui64 *> **curlist);
static int aclMatchEui(Splay<Eui::Eui64 *> **dataptr, Ip::Address &c);
static Splay<Eui::Eui64 *>::SPLAYCMP aclEui64Compare;

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
    if (data) {
        data->destroy();
        delete data;
    }
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
aclParseEuiList(Splay<Eui::Eui64 *> **curlist)
{
    char *t = NULL;
    Eui::Eui64 *q = NULL;

    while ((t = strtokFile())) {
        if ((q = aclParseEuiData(t)) == NULL)
            continue;

        (*curlist)->insert(q, aclEui64Compare);
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

    return aclMatchEui(&data, checklist->src_addr);
}

/***************/
/* aclMatchEui */
/***************/
int
aclMatchEui(Splay<Eui::Eui64 *> **dataptr, Ip::Address &c)
{
    Eui::Eui64 lookingFor;

    if (lookingFor.lookup(c)) {
        Eui::Eui64 * const * lookupResult = (*dataptr)->find(&lookingFor, aclEui64Compare);
        debugs(28, 3, "aclMatchEui: '" << c << "' " << (lookupResult ? "found" : "NOT found"));
        return (lookupResult != NULL);
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

struct AclEui64DumpVisitor {
    SBufList contents;
    void operator() ( const Eui::Eui64 * v) {
        static char buf[48];
        v->encode(buf, 48);
        contents.push_back(SBuf(buf));
    }
};

SBufList
ACLEui64::dump() const
{
    AclEui64DumpVisitor visitor;
    data->visit(visitor);
    return visitor.contents;
}

#endif /* USE_SQUID_EUI */

