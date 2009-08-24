
/*
 * $Id$
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
 */

#include "squid.h"
#include "structs.h"

#include "ConfigParser.h"
#include "acl/Gadgets.h"
#include "Store.h"
#include "Array.h"    // really Vector
#include "adaptation/Config.h"
#include "adaptation/Service.h"
#include "adaptation/AccessRule.h"
#include "adaptation/ServiceGroups.h"
#include "adaptation/History.h"


bool Adaptation::Config::Enabled = false;
char *Adaptation::Config::masterx_shared_name = NULL;
int Adaptation::Config::service_iteration_limit = 16;

void
Adaptation::Config::parseService()
{
    ServiceConfig *cfg = new ServiceConfig;
    if (!cfg->parse()) {
        fatalf("%s:%d: malformed adaptation service configuration",
               cfg_filename, config_lineno);
    }
    serviceConfigs.push_back(cfg);
}

void
Adaptation::Config::freeService()
{
    while (!serviceConfigs.empty()) {
        delete serviceConfigs.back();
        serviceConfigs.pop_back();
    }
}

void
Adaptation::Config::dumpService(StoreEntry *entry, const char *name) const
{
    typedef Services::iterator SCI;
    for (SCI i = AllServices().begin(); i != AllServices().end(); ++i) {
        const ServiceConfig &cfg = (*i)->cfg();
        storeAppendPrintf(entry, "%s " SQUIDSTRINGPH "_%s %s %d " SQUIDSTRINGPH "\n",
                          name,
                          SQUIDSTRINGPRINT(cfg.key),
                          cfg.methodStr(), cfg.vectPointStr(), cfg.bypass,
                          SQUIDSTRINGPRINT(cfg.uri));
    }
}

void
Adaptation::Config::finalize()
{
    // create service reps from service configs
    typedef Vector<ServiceConfig*>::const_iterator VISCI;
    const Vector<ServiceConfig*> &configs = serviceConfigs;
    debugs(93,3, HERE << "Found " << configs.size() << " service configs.");
    for (VISCI i = configs.begin(); i != configs.end(); ++i) {
        const ServiceConfig &cfg = **i;
        if (FindService(cfg.key) != NULL) {
            debugs(93,0, "ERROR: Duplicate adaptation service name: " <<
                   cfg.key);
            continue; // TODO: make fatal
        }
        ServicePointer s = createService(**i);
        if (s != NULL)
            AllServices().push_back(s);
    }

    debugs(93,3, HERE << "Created " << configs.size() <<
           " message adaptation services.");
}

// poor man for_each
template <class Collection>
static void
FinalizeEach(Collection &collection, const char *label)
{
    typedef typename Collection::iterator CI;
    for (CI i = collection.begin(); i != collection.end(); ++i)
        (*i)->finalize();

    debugs(93,2, HERE << "Initialized " << collection.size() << ' ' << label);
}

void
Adaptation::Config::Finalize(bool enabled)
{
    Enabled = enabled;
    debugs(93,1, "Adaptation support is " << (Enabled ? "on" : "off."));

    FinalizeEach(AllServices(), "message adaptation services");
    FinalizeEach(AllGroups(), "message adaptation service groups");
    FinalizeEach(AllRules(), "message adaptation access rules");
}

void
Adaptation::Config::ParseServiceSet()
{
    Adaptation::Config::ParseServiceGroup(new ServiceSet);
}

void
Adaptation::Config::ParseServiceChain()
{
    Adaptation::Config::ParseServiceGroup(new ServiceChain);
}

void
Adaptation::Config::ParseServiceGroup(ServiceGroupPointer g)
{
    assert(g != NULL);
    g->parse();
    AllGroups().push_back(g);
}

void
Adaptation::Config::FreeServiceGroups()
{
    while (!AllGroups().empty()) {
        // groups are refcounted so we do not explicitly delete them
        AllGroups().pop_back();
    }
}

void
Adaptation::Config::DumpServiceGroups(StoreEntry *entry, const char *name)
{
    typedef Groups::iterator GI;
    for (GI i = AllGroups().begin(); i != AllGroups().end(); ++i)
        storeAppendPrintf(entry, "%s " SQUIDSTRINGPH "\n", name, SQUIDSTRINGPRINT((*i)->id));
}

void
Adaptation::Config::ParseAccess(ConfigParser &parser)
{
    String groupId;
    ConfigParser::ParseString(&groupId);
    AccessRule *r;
    if (!(r=FindRuleByGroupId(groupId))) {
        r = new AccessRule(groupId);
        AllRules().push_back(r);
    }
    r->parse(parser);
}

void
Adaptation::Config::FreeAccess()
{
    while (!AllRules().empty()) {
        delete AllRules().back();
        AllRules().pop_back();
    }
}

void
Adaptation::Config::DumpAccess(StoreEntry *entry, const char *name)
{
    LOCAL_ARRAY(char, nom, 64);

    typedef AccessRules::iterator CI;
    for (CI i = AllRules().begin(); i != AllRules().end(); ++i) {
        snprintf(nom, 64, "%s " SQUIDSTRINGPH, name, SQUIDSTRINGPRINT((*i)->groupId));
        dump_acl_access(entry, nom, (*i)->acl);
    }
}

Adaptation::Config::Config()
{
    // XXX: should we init members?
}

// XXX: this is called for ICAP and eCAP configs, but deals mostly
// with global arrays shared by those individual configs
Adaptation::Config::~Config()
{
    FreeAccess();
    FreeServiceGroups();

    // invalidate each service so that it can be deleted when refcount=0
    while (!AllServices().empty()) {
        AllServices().back()->invalidate();
        AllServices().pop_back();
    }

    freeService();
}
