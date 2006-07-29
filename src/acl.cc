/*
 * $Id: acl.cc,v 1.321 2006/07/29 13:46:05 hno Exp $
 *
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
 */

#include "squid.h"
#include "ACL.h"
#include "ACLChecklist.h"
#include "ConfigParser.h"
#include "HttpRequest.h"

const char *AclMatchedName = NULL;

void *
ACL::operator new (size_t byteCount)
{
    fatal ("unusable ACL::new");
    return (void *)1;
}

void
ACL::operator delete (void *address)
{
    fatal ("unusable ACL::delete");
}

ACL *
ACL::FindByName(const char *name)
{
    ACL *a;
    debug(28, 9) ("ACL::FindByName '%s'\n",name);

    for (a = Config.aclList; a; a = a->next)
        if (!strcasecmp(a->name, name))
            return a;

    debug(28,9) ("ACL::FindByName found no match\n");

    return NULL;
}

ACL *
ACL::Factory (char const *type)
{
    ACL *result = Prototype::Factory (type);

    if (!result)
        fatal ("Unknown acl type in ACL::Factory");

    return result;
}

ACL::ACL () :cfgline(NULL) {}

bool ACL::valid () const
{
    return true;
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

    if ((t = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("aclParseAclLine: missing ACL name.\n");
        parser.destruct();
        return;
    }

    if (strlen(t) >= ACL_NAME_SZ) {
        debug(28, 0) ("aclParseAclLine: aclParseAclLine: ACL name '%s' too long, max %d characters supported\n", t, ACL_NAME_SZ - 1);
        parser.destruct();
        return;
    }

    xstrncpy(aclname, t, ACL_NAME_SZ);
    /* snarf the ACL type */
    char *theType;

    if ((theType = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("aclParseAclLine: missing ACL type.\n");
        parser.destruct();
        return;
    }

    if (!Prototype::Registered (theType)) {
        debug(28, 0) ("aclParseAclLine: Invalid ACL type '%s'\n", theType);
        parser.destruct();
        return;
    }

    if ((A = FindByName(aclname)) == NULL) {
        debug(28, 3) ("aclParseAclLine: Creating ACL '%s'\n", aclname);
        A = ACL::Factory(theType);
        xstrncpy(A->name, aclname, ACL_NAME_SZ);
        A->cfgline = xstrdup(config_input_line);
        new_acl = 1;
    } else {
        if (strcmp (A->typeString(),theType) ) {
            debug(28, 0) ("aclParseAclLine: ACL '%s' already exists with different type.\n", A->name);
            parser.destruct();
            return;
        }

        debug(28, 3) ("aclParseAclLine: Appending to '%s'\n", aclname);
        new_acl = 0;
    }

    /*
     * Here we set AclMatchedName in case we need to use it in a
     * warning message in aclDomainCompare().
     */
    AclMatchedName = A->name;	/* ugly */

    /*split the function here */
    A->parse();

    /*
     * Clear AclMatchedName from our temporary hack
     */
    AclMatchedName = NULL;	/* ugly */

    if (!new_acl)
        return;

    if (A->empty()) {
        debug(28, 0) ("Warning: empty ACL: %s\n",
                      A->cfgline);
    }

    if (!A->valid()) {
        fatalf("ERROR: Invalid ACL: %s\n",
               A->cfgline);
    }

    /* append */
    while (*head)
        head = &(*head)->next;

    *head = A;
}

bool
ACL::isProxyAuth() const
{
    return false;
}


ACLList::ACLList() : op (1), _acl (NULL), next (NULL)
{}

void
ACLList::negated(bool isNegated)
{
    if (isNegated)
        op = 0;
    else
        op = 1;
}

/* ACL result caching routines */

int
ACL::matchForCache(ACLChecklist *checklist)
{
    /* This is a fatal to ensure that cacheMatchAcl calls are _only_
     * made for supported acl types */
    fatal("aclCacheMatchAcl: unknown or unexpected ACL type");
    return 0;		/* NOTREACHED */
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
            debug(28, 4) ("ACL::cacheMatchAcl: cache hit on acl '%s' (%p)\n", name, this);
            return auth_match->matchrv;
        }

        link = link->next;
    }

    auth_match = new acl_proxy_auth_match_cache();
    auth_match->matchrv = matchForCache (checklist);
    auth_match->acl_data = this;
    dlinkAddTail(auth_match, &auth_match->link, cache);
    debug(28,4)("ACL::cacheMatchAcl: miss for '%s'. Adding result %d\n",name,auth_match->matchrv);
    return auth_match->matchrv;
}

void
aclCacheMatchFlush(dlink_list * cache)
{
    acl_proxy_auth_match_cache *auth_match;
    dlink_node *link, *tmplink;
    link = cache->head;

    debug(28,8)("aclCacheMatchFlush called for cache %p\n",cache);

    while (link) {
        auth_match = (acl_proxy_auth_match_cache *)link->data;
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, cache);
        delete auth_match;
    }
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

int
ACL::checklistMatches(ACLChecklist *checklist)
{
    int rv;

    if (NULL == checklist->request && requiresRequest()) {
        debug(28, 1) ( "ACL::checklistMatches "
                       "WARNING: '%s' ACL is used but there is no"
                       " HTTP request -- not matching.\n", name);
        return 0;
    }

    if (NULL == checklist->reply && requiresReply()) {
        debug(28, 1) ( "ACL::checklistMatches "
                       "WARNING: '%s' ACL is used but there is no"
                       " HTTP reply -- not matching.\n", name);
        return 0;
    }

    debug(28, 3) ("ACL::checklistMatches: checking '%s'\n", name);
    rv= match(checklist);
    debug(28,3) ("ACL::ChecklistMatches: result for '%s' is %d\n",name,rv);
    return rv;
}

bool
ACLList::matches (ACLChecklist *checklist) const
{
    assert (_acl);
    AclMatchedName = _acl->name;
    debug(28, 3) ("ACLList::matches: checking %s%s\n",
                  op ? null_string : "!", _acl->name);

    if (_acl->checklistMatches(checklist) != op) {
        debug(28,4)("ACLList::matches: result is false\n");
        return checklist->lastACLResult(false);
    }

    debug(28,4)("ACLList::matches: result is true\n");
    return checklist->lastACLResult(true);
}


/*********************/
/* Destroy functions */
/*********************/

ACL::~ACL()
{
    debug(28, 3) ("ACL::~ACL: '%s'\n", cfgline);
    safe_free(cfgline);
}

#include "ACLStrategised.h"
bool
acl_access::containsPURGE() const
{
    acl_access const *a = this;
    acl_list *b;

    debug(28,6)("acl_access::containsPURGE: invoked for '%s'\n",cfgline);

    for (; a; a = a->next) {
        for (b = a->aclList; b; b = b->next) {
            ACLStrategised<method_t> *tempAcl = dynamic_cast<ACLStrategised<method_t> *>(b->_acl);

            if (!tempAcl) {
                debug(28,7)("acl_access::containsPURGE: can't create tempAcl\n");
                continue;
            }

            if (tempAcl->match(METHOD_PURGE)) {
                debug(28,6)("acl_access::containsPURGE:   returning true\n");
                return true;
            }
        }
    }

    debug(28,6)("acl_access::containsPURGE:   returning false\n");
    return false;
}

/* to be split into separate files in the future */

CBDATA_CLASS_INIT(acl_access);

void *
acl_access::operator new (size_t)
{
    CBDATA_INIT_TYPE(acl_access);
    acl_access *result = cbdataAlloc(acl_access);
    return result;
}

void
acl_access::operator delete (void *address)
{
    acl_access *t = static_cast<acl_access *>(address);
    cbdataFree(t);
}

ACL::Prototype::Prototype() : prototype (NULL), typeString (NULL) {}

ACL::Prototype::Prototype (ACL const *aPrototype, char const *aType) : prototype (aPrototype), typeString (aType)
{
    registerMe ();
}

Vector<ACL::Prototype const *> * ACL::Prototype::Registry;
void *ACL::Prototype::Initialized;

bool
ACL::Prototype::Registered(char const *aType)
{
    debug(28,7)("ACL::Prototype::Registered: invoked for type %s\n",aType);

    for (iterator i = Registry->begin(); i != Registry->end(); ++i)
        if (!strcmp (aType, (*i)->typeString)) {
            debug(28,7)("ACL::Prototype::Registered:    yes\n");
            return true;
        }

    debug(28,7)("ACL::Prototype::Registered:    no\n");
    return false;
}

void
ACL::Prototype::registerMe ()
{
    if (!Registry || (Initialized != ((char *)Registry - 5))  ) {
        /* TODO: extract this */
        /* Not initialised */
        Registry = new Vector <ACL::Prototype const *>;
        Initialized = (char *)Registry - 5;
    }

    if (Registered (typeString))
        fatalf ("Attempt to register %s twice", typeString);

    Registry->push_back (this);
}

ACL::Prototype::~Prototype()
{
    debug (28,2)("ACL::Prototype::~Prototype: TODO: unregister me\n");
}

ACL *
ACL::Prototype::Factory (char const *typeToClone)
{
    debug(28,4)("ACL::Prototype::Factory: cloning an object for type '%s'\n",typeToClone);

    for (iterator i = Registry->begin(); i != Registry->end(); ++i)
        if (!strcmp (typeToClone, (*i)->typeString))
            return (*i)->prototype->clone();

    debug(28,4)("ACL::Prototype::Factory: cloning failed, no type '%s' available\n",typeToClone);

    return NULL;
}

void
ACL::Initialize()
{
    ACL *a = Config.aclList;
    debug(53, 3) ("ACL::Initialize\n");

    while (a) {
        a->prepareForUse();
        a = a->next;
    }
}
