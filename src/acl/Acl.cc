/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Gadgets.h"
#include "acl/Options.h"
#include "anyp/PortCfg.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"
#include "profiler/Profiler.h"
#include "sbuf/List.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

#include <algorithm>
#include <map>

const char *AclMatchedName = NULL;

namespace Acl {

/// ACL type name comparison functor
class TypeNameCmp {
public:
    bool operator()(TypeName a, TypeName b) const { return strcmp(a, b) < 0; }
};

/// ACL makers indexed by ACL type name
typedef std::map<TypeName, Maker, TypeNameCmp> Makers;

/// registered ACL Makers
static Makers &
TheMakers()
{
    static Makers Registry;
    return Registry;
}

/// creates an ACL object of the named (and already registered) ACL child type
static
ACL *
Make(TypeName typeName)
{
    const auto pos = TheMakers().find(typeName);
    if (pos == TheMakers().end()) {
        debugs(28, DBG_CRITICAL, "FATAL: Invalid ACL type '" << typeName << "'");
        self_destruct();
        assert(false); // not reached
    }

    ACL *result = (pos->second)(pos->first);
    debugs(28, 4, typeName << '=' << result);
    assert(result);
    return result;
}

} // namespace Acl

void
Acl::RegisterMaker(TypeName typeName, Maker maker)
{
    assert(typeName);
    assert(*typeName);
    TheMakers().emplace(typeName, maker);
}

void *
ACL::operator new (size_t)
{
    fatal ("unusable ACL::new");
    return (void *)1;
}

void
ACL::operator delete (void *)
{
    fatal ("unusable ACL::delete");
}

ACL *
ACL::FindByName(const char *name)
{
    ACL *a;
    debugs(28, 9, "ACL::FindByName '" << name << "'");

    for (a = Config.aclList; a; a = a->next)
        if (!strcasecmp(a->name, name))
            return a;

    debugs(28, 9, "ACL::FindByName found no match");

    return NULL;
}

ACL::ACL() :
    cfgline(nullptr),
    next(nullptr),
    registered(false)
{
    *name = 0;
}

bool ACL::valid () const
{
    return true;
}

bool
ACL::matches(ACLChecklist *checklist) const
{
    PROF_start(ACL_matches);
    debugs(28, 5, "checking " << name);

    // XXX: AclMatchedName does not contain a matched ACL name when the acl
    // does not match. It contains the last (usually leaf) ACL name checked
    // (or is NULL if no ACLs were checked).
    AclMatchedName = name;

    int result = 0;
    if (!checklist->hasAle() && requiresAle()) {
        debugs(28, DBG_IMPORTANT, "WARNING: " << name << " ACL is used in " <<
               "context without an ALE state. Assuming mismatch.");
    } else if (!checklist->hasRequest() && requiresRequest()) {
        debugs(28, DBG_IMPORTANT, "WARNING: " << name << " ACL is used in " <<
               "context without an HTTP request. Assuming mismatch.");
    } else if (!checklist->hasReply() && requiresReply()) {
        debugs(28, DBG_IMPORTANT, "WARNING: " << name << " ACL is used in " <<
               "context without an HTTP response. Assuming mismatch.");
    } else {
        // make sure the ALE has as much data as possible
        if (requiresAle())
            checklist->verifyAle();

        // have to cast because old match() API is missing const
        result = const_cast<ACL*>(this)->match(checklist);
    }

    const char *extra = checklist->asyncInProgress() ? " async" : "";
    debugs(28, 3, "checked: " << name << " = " << result << extra);
    PROF_stop(ACL_matches);
    return result == 1; // true for match; false for everything else
}

void
ACL::context(const char *aName, const char *aCfgLine)
{
    name[0] = '\0';
    if (aName)
        xstrncpy(name, aName, ACL_NAME_SZ-1);
    safe_free(cfgline);
    if (aCfgLine)
        cfgline = xstrdup(aCfgLine);
}

void
ACL::ParseAclLine(ConfigParser &parser, ACL ** head)
{
    /* we're already using strtok() to grok the line */
    char *t = NULL;
    ACL *A = NULL;
    LOCAL_ARRAY(char, aclname, ACL_NAME_SZ);
    int new_acl = 0;

    /* snarf the ACL name */

    if ((t = ConfigParser::NextToken()) == NULL) {
        debugs(28, DBG_CRITICAL, "aclParseAclLine: missing ACL name.");
        parser.destruct();
        return;
    }

    if (strlen(t) >= ACL_NAME_SZ) {
        debugs(28, DBG_CRITICAL, "aclParseAclLine: aclParseAclLine: ACL name '" << t <<
               "' too long, max " << ACL_NAME_SZ - 1 << " characters supported");
        parser.destruct();
        return;
    }

    xstrncpy(aclname, t, ACL_NAME_SZ);
    /* snarf the ACL type */
    const char *theType;

    if ((theType = ConfigParser::NextToken()) == NULL) {
        debugs(28, DBG_CRITICAL, "aclParseAclLine: missing ACL type.");
        parser.destruct();
        return;
    }

    // Is this ACL going to work?
    if (strcmp(theType, "myip") == 0) {
        AnyP::PortCfgPointer p = HttpPortList;
        while (p != NULL) {
            // Bug 3239: not reliable when there is interception traffic coming
            if (p->flags.natIntercept)
                debugs(28, DBG_CRITICAL, "WARNING: 'myip' ACL is not reliable for interception proxies. Please use 'myportname' instead.");
            p = p->next;
        }
        debugs(28, DBG_IMPORTANT, "UPGRADE: ACL 'myip' type is has been renamed to 'localip' and matches the IP the client connected to.");
        theType = "localip";
    } else if (strcmp(theType, "myport") == 0) {
        AnyP::PortCfgPointer p = HttpPortList;
        while (p != NULL) {
            // Bug 3239: not reliable when there is interception traffic coming
            // Bug 3239: myport - not reliable (yet) when there is interception traffic coming
            if (p->flags.natIntercept)
                debugs(28, DBG_CRITICAL, "WARNING: 'myport' ACL is not reliable for interception proxies. Please use 'myportname' instead.");
            p = p->next;
        }
        theType = "localport";
        debugs(28, DBG_IMPORTANT, "UPGRADE: ACL 'myport' type is has been renamed to 'localport' and matches the port the client connected to.");
    } else if (strcmp(theType, "proto") == 0 && strcmp(aclname, "manager") == 0) {
        // ACL manager is now a built-in and has a different type.
        debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "UPGRADE: ACL 'manager' is now a built-in ACL. Remove it from your config file.");
        return; // ignore the line
    }

    if ((A = FindByName(aclname)) == NULL) {
        debugs(28, 3, "aclParseAclLine: Creating ACL '" << aclname << "'");
        A = Acl::Make(theType);
        A->context(aclname, config_input_line);
        new_acl = 1;
    } else {
        if (strcmp (A->typeString(),theType) ) {
            debugs(28, DBG_CRITICAL, "aclParseAclLine: ACL '" << A->name << "' already exists with different type.");
            parser.destruct();
            return;
        }

        debugs(28, 3, "aclParseAclLine: Appending to '" << aclname << "'");
        new_acl = 0;
    }

    /*
     * Here we set AclMatchedName in case we need to use it in a
     * warning message in aclDomainCompare().
     */
    AclMatchedName = A->name;   /* ugly */

    A->parseFlags();

    /*split the function here */
    A->parse();

    /*
     * Clear AclMatchedName from our temporary hack
     */
    AclMatchedName = NULL;  /* ugly */

    if (!new_acl)
        return;

    if (A->empty()) {
        debugs(28, DBG_CRITICAL, "Warning: empty ACL: " << A->cfgline);
    }

    if (!A->valid()) {
        fatalf("ERROR: Invalid ACL: %s\n",
               A->cfgline);
    }

    // add to the global list for searching explicit ACLs by name
    assert(head && *head == Config.aclList);
    A->next = *head;
    *head = A;

    // register for centralized cleanup
    aclRegister(A);
}

bool
ACL::isProxyAuth() const
{
    return false;
}

void
ACL::parseFlags()
{
    // ACL kids that carry ACLData which supports parameter flags override this
    Acl::ParseFlags(options(), Acl::NoFlags());
}

SBufList
ACL::dumpOptions()
{
    SBufList result;
    const auto &myOptions = options();
    // optimization: most ACLs do not have myOptions
    // this check also works around dump_SBufList() adding ' ' after empty items
    if (!myOptions.empty()) {
        SBufStream stream;
        stream << myOptions;
        const SBuf optionsImage = stream.buf();
        if (!optionsImage.isEmpty())
            result.push_back(optionsImage);
    }
    return result;
}

/* ACL result caching routines */

int
ACL::matchForCache(ACLChecklist *)
{
    /* This is a fatal to ensure that cacheMatchAcl calls are _only_
     * made for supported acl types */
    fatal("aclCacheMatchAcl: unknown or unexpected ACL type");
    return 0;       /* NOTREACHED */
}

/*
 * we lookup an acl's cached results, and if we cannot find the acl being
 * checked we check it and cache the result. This function is a template
 * method to support caching of multiple acl types.
 * Note that caching of time based acl's is not
 * wise in long lived caches (i.e. the auth_user proxy match cache)
 * RBC
 * TODO: does a dlink_list perform well enough? Kinkie
 */
int
ACL::cacheMatchAcl(dlink_list * cache, ACLChecklist *checklist)
{
    acl_proxy_auth_match_cache *auth_match;
    dlink_node *link;
    link = cache->head;

    while (link) {
        auth_match = (acl_proxy_auth_match_cache *)link->data;

        if (auth_match->acl_data == this) {
            debugs(28, 4, "ACL::cacheMatchAcl: cache hit on acl '" << name << "' (" << this << ")");
            return auth_match->matchrv;
        }

        link = link->next;
    }

    auth_match = new acl_proxy_auth_match_cache(matchForCache(checklist), this);
    dlinkAddTail(auth_match, &auth_match->link, cache);
    debugs(28, 4, "ACL::cacheMatchAcl: miss for '" << name << "'. Adding result " << auth_match->matchrv);
    return auth_match->matchrv;
}

void
aclCacheMatchFlush(dlink_list * cache)
{
    acl_proxy_auth_match_cache *auth_match;
    dlink_node *link, *tmplink;
    link = cache->head;

    debugs(28, 8, "aclCacheMatchFlush called for cache " << cache);

    while (link) {
        auth_match = (acl_proxy_auth_match_cache *)link->data;
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, cache);
        delete auth_match;
    }
}

bool
ACL::requiresAle() const
{
    return false;
}

bool
ACL::requiresReply() const
{
    return false;
}

bool
ACL::requiresRequest() const
{
    return false;
}

/*********************/
/* Destroy functions */
/*********************/

ACL::~ACL()
{
    debugs(28, 3, "freeing ACL " << name);
    safe_free(cfgline);
    AclMatchedName = NULL; // in case it was pointing to our name
}

void
ACL::Initialize()
{
    ACL *a = Config.aclList;
    debugs(53, 3, "ACL::Initialize");

    while (a) {
        a->prepareForUse();
        a = a->next;
    }
}

