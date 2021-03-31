/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Config.h"
#include "adaptation/History.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "ConfigParser.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "Store.h"

#include <algorithm>

bool Adaptation::Config::Enabled = false;
char *Adaptation::Config::masterx_shared_name = NULL;
int Adaptation::Config::service_iteration_limit = 16;
int Adaptation::Config::send_client_ip = false;
int Adaptation::Config::send_username = false;
int Adaptation::Config::use_indirect_client = true;
static const char *protectedFieldNamesRaw[] = {
    "Allow",
    "Date",
    "Encapsulated",
    "ISTag",
    "Max-Connections",
    "Methods",
    "Opt-body-type",
    "Options-TTL",
    "Preview",
    "Service",
    "Service-ID",
    "Transfer-Complete",
    "Transfer-Ignore",
    "Transfer-Preview"
};
static const Notes::Keys protectedFieldNames(std::begin(protectedFieldNamesRaw), std::end(protectedFieldNamesRaw));
Notes Adaptation::Config::metaHeaders("ICAP header", &protectedFieldNames);
bool Adaptation::Config::needHistory = false;

Adaptation::ServiceConfig*
Adaptation::Config::newServiceConfig() const
{
    return new ServiceConfig();
}

void
Adaptation::Config::removeService(const String& service)
{
    removeRule(service);
    const Groups& groups = AllGroups();
    for (unsigned int i = 0; i < groups.size(); ) {
        const ServiceGroupPointer group = groups[i];
        const ServiceGroup::Store& services = group->services;
        typedef ServiceGroup::Store::const_iterator SGSI;
        for (SGSI it = services.begin(); it != services.end(); ++it) {
            if (*it == service) {
                group->removedServices.push_back(service);
                ServiceGroup::Store::iterator newend;
                newend = std::remove(group->services.begin(), group->services.end(), service);
                group->services.resize(newend-group->services.begin());
                debugs(93, 5, "adaptation service " << service <<
                       " removed from group " << group->id);
                break;
            }
        }
        if (services.empty()) {
            removeRule(group->id);
            Groups::iterator newend;
            newend = std::remove(AllGroups().begin(), AllGroups().end(), group);
            AllGroups().resize(newend-AllGroups().begin());
        } else {
            ++i;
        }
    }
}

Adaptation::ServiceConfigPointer
Adaptation::Config::findServiceConfig(const String &service)
{
    typedef ServiceConfigs::const_iterator SCI;
    const ServiceConfigs& configs = serviceConfigs;
    for (SCI cfg = configs.begin(); cfg != configs.end(); ++cfg) {
        if ((*cfg)->key == service)
            return *cfg;
    }
    return NULL;
}

void
Adaptation::Config::removeRule(const String& id)
{
    typedef AccessRules::const_iterator ARI;
    const AccessRules& rules = AllRules();
    for (ARI it = rules.begin(); it != rules.end(); ++it) {
        AccessRule* rule = *it;
        if (rule->groupId == id) {
            debugs(93, 5, "removing access rules for:" << id);
            AccessRules::iterator newend;
            newend = std::remove(AllRules().begin(), AllRules().end(), rule);
            AllRules().resize(newend-AllRules().begin());
            delete (rule);
            break;
        }
    }
}

void
Adaptation::Config::clear()
{
    debugs(93, 3, HERE << "rules: " << AllRules().size() << ", groups: " <<
           AllGroups().size() << ", services: " << serviceConfigs.size());
    typedef ServiceConfigs::const_iterator SCI;
    const ServiceConfigs& configs = serviceConfigs;
    for (SCI cfg = configs.begin(); cfg != configs.end(); ++cfg)
        removeService((*cfg)->key);
    serviceConfigs.clear();
    debugs(93, 3, HERE << "rules: " << AllRules().size() << ", groups: " <<
           AllGroups().size() << ", services: " << serviceConfigs.size());
}

void
Adaptation::Config::parseService()
{
    ServiceConfigPointer cfg = newServiceConfig();
    if (!cfg->parse()) {
        fatalf("%s:%d: malformed adaptation service configuration",
               cfg_filename, config_lineno);
    }
    serviceConfigs.push_back(cfg);
}

void
Adaptation::Config::freeService()
{
    FreeAccess();
    FreeServiceGroups();

    DetachServices();

    serviceConfigs.clear();
}

void
Adaptation::Config::dumpService(StoreEntry *entry, const char *name) const
{
    typedef Services::iterator SCI;
    for (SCI i = AllServices().begin(); i != AllServices().end(); ++i) {
        const ServiceConfig &cfg = (*i)->cfg();
        bool isEcap = cfg.protocol.caseCmp("ecap") == 0;
        bool isIcap = !isEcap;
        const char *optConnectionEncryption = "";
        // Print connections_encrypted option if no default value is used
        if (cfg.secure.encryptTransport && !cfg.connectionEncryption)
            optConnectionEncryption = " connection-encryption=off";
        else if (isEcap && !cfg.connectionEncryption)
            optConnectionEncryption = " connection-encryption=off";
        else if (isIcap && !cfg.secure.encryptTransport && cfg.connectionEncryption)
            optConnectionEncryption = " connection-encryption=on";

        storeAppendPrintf(entry, "%s " SQUIDSTRINGPH " %s_%s %d " SQUIDSTRINGPH "%s\n",
                          name,
                          SQUIDSTRINGPRINT(cfg.key),
                          cfg.methodStr(), cfg.vectPointStr(), cfg.bypass,
                          SQUIDSTRINGPRINT(cfg.uri),

                          optConnectionEncryption);
    }
}

bool
Adaptation::Config::finalize()
{
    if (!onoff) {
        clear();
        return false;
    }

    // create service reps from service configs
    int created = 0;

    typedef ServiceConfigs::const_iterator VISCI;
    const ServiceConfigs &configs = serviceConfigs;
    for (VISCI i = configs.begin(); i != configs.end(); ++i) {
        const ServiceConfigPointer cfg = *i;
        if (FindService(cfg->key) != NULL) {
            debugs(93, DBG_CRITICAL, "ERROR: Duplicate adaptation service name: " <<
                   cfg->key);
            continue; // TODO: make fatal
        }
        ServicePointer s = createService(cfg);
        if (s != NULL) {
            AllServices().push_back(s);
            ++created;
        }
    }

    debugs(93,3, HERE << "Created " << created << " adaptation services");

    // services remember their configs; we do not have to
    serviceConfigs.clear();
    return true;
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
    debugs(93, DBG_IMPORTANT, "Adaptation support is " << (Enabled ? "on" : "off."));

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
    String groupId = ConfigParser::NextToken();
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

Adaptation::Config::Config() :
    onoff(0), service_failure_limit(0), oldest_service_failure(0),
    service_revival_delay(0)
{}

// XXX: this is called for ICAP and eCAP configs, but deals mostly
// with global arrays shared by those individual configs
Adaptation::Config::~Config()
{
    freeService();
}

