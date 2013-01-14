
/*
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
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Config.h"
#include "adaptation/History.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "Array.h"
#include "ConfigParser.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "Store.h"

bool Adaptation::Config::Enabled = false;
char *Adaptation::Config::masterx_shared_name = NULL;
int Adaptation::Config::service_iteration_limit = 16;
int Adaptation::Config::send_client_ip = false;
int Adaptation::Config::send_username = false;
int Adaptation::Config::use_indirect_client = true;
Adaptation::Config::MetaHeaders Adaptation::Config::metaHeaders;

Adaptation::Config::MetaHeader::Value::~Value()
{
    aclDestroyAclList(&aclList);
}

Adaptation::Config::MetaHeader::Value::Pointer
Adaptation::Config::MetaHeader::addValue(const String &value)
{
    Value::Pointer v = new Value(value);
    values.push_back(v);
    return v;
}

const char *
Adaptation::Config::MetaHeader::match(HttpRequest *request, HttpReply *reply)
{

    typedef Values::iterator VLI;
    ACLFilledChecklist ch(NULL, request, NULL);
    if (reply)
        ch.reply = HTTPMSGLOCK(reply);

    for (VLI i = values.begin(); i != values.end(); ++i ) {
        const int ret= ch.fastCheck((*i)->aclList);
        debugs(93, 5, HERE << "Check for header name: " << name << ": " << (*i)->value
               <<", HttpRequest: " << request << " HttpReply: " << reply << " matched: " << ret);
        if (ret == ACCESS_ALLOWED)
            return (*i)->value.termedBuf();
    }
    return NULL;
}

Adaptation::Config::MetaHeader::Pointer
Adaptation::Config::addMetaHeader(const String &headerName)
{
    typedef MetaHeaders::iterator AMLI;
    for (AMLI i = metaHeaders.begin(); i != metaHeaders.end(); ++i) {
        if ((*i)->name == headerName)
            return (*i);
    }

    MetaHeader::Pointer meta = new MetaHeader(headerName);
    metaHeaders.push_back(meta);
    return meta;
}

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
                group->services.prune(service);
                debugs(93, 5, HERE << "adaptation service " << service <<
                       " removed from group " << group->id);
                break;
            }
        }
        if (services.empty()) {
            removeRule(group->id);
            AllGroups().prune(group);
        } else {
            ++i;
        }
    }
}

void
Adaptation::Config::removeRule(const String& id)
{
    typedef AccessRules::const_iterator ARI;
    const AccessRules& rules = AllRules();
    for (ARI it = rules.begin(); it != rules.end(); ++it) {
        AccessRule* rule = *it;
        if (rule->groupId == id) {
            debugs(93, 5, HERE << "removing access rules for:" << id);
            AllRules().prune(rule);
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
    serviceConfigs.clean();
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

    serviceConfigs.clean();

    FreeMetaHeader();
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
    serviceConfigs.clean();
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
Adaptation::Config::ParseMetaHeader(ConfigParser &parser)
{
    String name, value;
    const char *warnFor[] = {
        "Methods",
        "Service",
        "ISTag",
        "Encapsulated",
        "Opt-body-type",
        "Max-Connections",
        "Options-TTL",
        "Date",
        "Service-ID",
        "Allow",
        "Preview",
        "Transfer-Preview",
        "Transfer-Ignore",
        "Transfer-Complete",
        NULL
    };
    ConfigParser::ParseString(&name);
    ConfigParser::ParseQuotedString(&value);

    // TODO: Find a way to move this check to ICAP
    for (int i = 0; warnFor[i] != NULL; ++i) {
        if (name.caseCmp(warnFor[i]) == 0) {
            fatalf("%s:%d: meta name \"%s\" is a reserved ICAP header name",
                   cfg_filename, config_lineno, name.termedBuf());
        }
    }

    MetaHeader::Pointer meta = addMetaHeader(name);
    MetaHeader::Value::Pointer headValue = meta->addValue(value);
    aclParseAclList(parser, &headValue->aclList);
}

void
Adaptation::Config::DumpMetaHeader(StoreEntry *entry, const char *name)
{
    typedef MetaHeaders::iterator AMLI;
    for (AMLI m = metaHeaders.begin(); m != metaHeaders.end(); ++m) {
        typedef MetaHeader::Values::iterator VLI;
        for (VLI v =(*m)->values.begin(); v != (*m)->values.end(); ++v ) {
            storeAppendPrintf(entry, "%s " SQUIDSTRINGPH " %s",
                              name, SQUIDSTRINGPRINT((*m)->name), ConfigParser::QuoteString((*v)->value));
            dump_acl_list(entry, (*v)->aclList);
            storeAppendPrintf(entry, "\n");
        }
    }
}

void
Adaptation::Config::FreeMetaHeader()
{
    metaHeaders.clean();
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
