/*
 * $Id: acl.cc,v 1.307 2003/05/17 17:35:05 hno Exp $
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

acl *
ACL::FindByName(const char *name)
{
    acl *a;

    for (a = Config.aclList; a; a = a->next)
        if (!strcasecmp(a->name, name))
            return a;

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

ACL::ACL () {}

void
ACL::ParseAclLine(acl ** head)
{
    /* we're already using strtok() to grok the line */
    char *t = NULL;
    acl *A = NULL;
    LOCAL_ARRAY(char, aclname, ACL_NAME_SZ);
    int new_acl = 0;

    /* snarf the ACL name */

    if ((t = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAclLine: missing ACL name.\n");
        return;
    }

    xstrncpy(aclname, t, ACL_NAME_SZ);
    /* snarf the ACL type */
    char *theType;

    if ((theType = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAclLine: missing ACL type.\n");
        return;
    }

    if (!Prototype::Registered (theType)) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAclLine: Invalid ACL type '%s'\n", theType);
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
            debug(28, 0) ("aclParseAclLine: ACL '%s' already exists with different type, skipping.\n", A->name);
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

    if (!A->valid()) {
        debug(28, 0) ("aclParseAclLine: IGNORING invalid ACL: %s\n",
                      A->cfgline);
        A->deleteSelf();
        /* Do we need this? */
        A = NULL;
        return;
    }

    /* append */
    while (*head)
        head = &(*head)->next;

    *head = A;
}

/* does name lookup, returns page_id */
err_type
aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name)
{
    acl_deny_info_list *A = NULL;
    acl_name_list *L = NULL;

    A = *head;

    if (NULL == *head)		/* empty list */
        return ERR_NONE;

    while (A) {
        L = A->acl_list;

        if (NULL == L)		/* empty list should never happen, but in case */
            continue;

        while (L) {
            if (!strcmp(name, L->name))
                return A->err_page_id;

            L = L->next;
        }

        A = A->next;
    }

    return ERR_NONE;
}

/* does name lookup, returns if it is a proxy_auth acl */
int
aclIsProxyAuth(const char *name)
{
    if (NULL == name)
        return false;

    acl *a;

    if ((a = ACL::FindByName(name)))
        return a->isProxyAuth();

    return false;
}

bool
ACL::isProxyAuth() const
{
    return false;
}

/* maex@space.net (05.09.96)
 *    get the info for redirecting "access denied" to info pages
 *      TODO (probably ;-)
 *      currently there is no optimization for
 *      - more than one deny_info line with the same url
 *      - a check, whether the given acl really is defined
 *      - a check, whether an acl is added more than once for the same url
 */

void
aclParseDenyInfoLine(acl_deny_info_list ** head)
{
    char *t = NULL;
    acl_deny_info_list *A = NULL;
    acl_deny_info_list *B = NULL;
    acl_deny_info_list **T = NULL;
    acl_name_list *L = NULL;
    acl_name_list **Tail = NULL;

    /* first expect a page name */

    if ((t = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseDenyInfoLine: missing 'error page' parameter.\n");
        return;
    }

    A = (acl_deny_info_list *)memAllocate(MEM_ACL_DENY_INFO_LIST);
    A->err_page_id = errorReservePageId(t);
    A->err_page_name = xstrdup(t);
    A->next = (acl_deny_info_list *) NULL;
    /* next expect a list of ACL names */
    Tail = &A->acl_list;

    while ((t = strtok(NULL, w_space))) {
        L = (acl_name_list *)memAllocate(MEM_ACL_NAME_LIST);
        xstrncpy(L->name, t, ACL_NAME_SZ);
        *Tail = L;
        Tail = &L->next;
    }

    if (A->acl_list == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseDenyInfoLine: deny_info line contains no ACL's, skipping\n");
        memFree(A, MEM_ACL_DENY_INFO_LIST);
        return;
    }

    for (B = *head, T = head; B; T = &B->next, B = B->next)

        ;	/* find the tail */
    *T = A;
}

void
aclParseAccessLine(acl_access ** head)
{
    char *t = NULL;
    acl_access *A = NULL;
    acl_access *B = NULL;
    acl_access **T = NULL;

    /* first expect either 'allow' or 'deny' */

    if ((t = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAccessLine: missing 'allow' or 'deny'.\n");
        return;
    }

    A = new acl_access;

    if (!strcmp(t, "allow"))
        A->allow = ACCESS_ALLOWED;
    else if (!strcmp(t, "deny"))
        A->allow = ACCESS_DENIED;
    else {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAccessLine: expecting 'allow' or 'deny', got '%s'.\n", t);
        delete A;
        return;
    }

    aclParseAclList(&A->aclList);

    if (A->aclList == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAccessLine: Access line contains no ACL's, skipping\n");
        delete A;
        return;
    }

    A->cfgline = xstrdup(config_input_line);
    /* Append to the end of this list */

    for (B = *head, T = head; B; T = &B->next, B = B->next)

        ;
    *T = A;

    /* We lock _acl_access structures in ACLChecklist::check() */
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

void
aclParseAclList(acl_list ** head)
{
    acl_list **Tail = head;	/* sane name in the use below */
    acl *a = NULL;
    char *t;

    /* next expect a list of ACL names, possibly preceeded
     * by '!' for negation */

    while ((t = strtok(NULL, w_space))) {
        acl_list *L (new ACLList);

        if (*t == '!') {
            L->negated (true);
            t++;
        }

        debug(28, 3) ("aclParseAccessLine: looking for ACL name '%s'\n", t);
        a = ACL::FindByName(t);

        if (a == NULL) {
            debug(28, 0) ("%s line %d: %s\n",
                          cfg_filename, config_lineno, config_input_line);
            debug(28, 0) ("aclParseAccessLine: ACL name '%s' not found.\n", t);
            L->deleteSelf();
            continue;
        }

        L->_acl = a;
        *Tail = L;
        Tail = &L->next;
    }
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
 * wise in long lived caches (i.e. the auth_user proxy match cache.
 * RBC
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
            debug(28, 4) ("ACL::cacheMatchAcl: cache hit on acl '%p'\n", this);
            return auth_match->matchrv;
        }

        link = link->next;
    }

    auth_match = NULL;
    auth_match = (acl_proxy_auth_match_cache *)memAllocate(MEM_ACL_PROXY_AUTH_MATCH);
    auth_match->matchrv = matchForCache (checklist);
    auth_match->acl_data = this;
    dlinkAddTail(auth_match, &auth_match->link, cache);
    return auth_match->matchrv;
}

void
aclCacheMatchFlush(dlink_list * cache)
{
    acl_proxy_auth_match_cache *auth_match;
    dlink_node *link, *tmplink;
    link = cache->head;

    while (link) {
        auth_match = (acl_proxy_auth_match_cache *)link->data;
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, cache);
        memFree(auth_match, MEM_ACL_PROXY_AUTH_MATCH);
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
    if (NULL == checklist->request && requiresRequest()) {
        debug(28, 1) ("WARNING: '%s' ACL is used but there is no"
                      " HTTP request -- not matching.\n", name);
        return 0;
    }

    if (NULL == checklist->reply && requiresReply()) {
        debug(28, 1) ("WARNING: '%s' ACL is used but there is no"
                      " HTTP reply -- not matching.\n", name);
        return 0;
    }

    debug(28, 3) ("aclMatchAcl: checking '%s'\n", cfgline);
    return match(checklist);
}

bool
ACLList::matches (ACLChecklist *checklist) const
{
    assert (_acl);
    AclMatchedName = _acl->name;
    debug(28, 3) ("ACLList::matches: checking %s%s\n",
                  op ? null_string : "!", _acl->name);

    if (_acl->checklistMatches(checklist) != op) {
        return false;
    }

    return true;
}

/* Warning: do not cbdata lock checklist here - it
 * may be static or on the stack
 */
int
aclCheckFast(const acl_access * A, ACLChecklist * checklist)
{
    allow_t allow = ACCESS_DENIED;
    PROF_start(aclCheckFast);
    debug(28, 5) ("aclCheckFast: list: %p\n", A);

    while (A) {
        allow = A->allow;
        checklist->matchAclListFast(A->aclList);

        if (checklist->finished()) {
            PROF_stop(aclCheckFast);
            return allow == ACCESS_ALLOWED;
        }

        A = A->next;
    }

    debug(28, 5) ("aclCheckFast: no matches, returning: %d\n", allow == ACCESS_DENIED);
    PROF_stop(aclCheckFast);
    return allow == ACCESS_DENIED;
}

/*
 * Any ACLChecklist created by aclChecklistCreate() must eventually be
 * freed by ACLChecklist::operator delete().  There are two common cases:
 *
 * A) Using aclCheckFast():  The caller creates the ACLChecklist using
 *    aclChecklistCreate(), checks it using aclCheckFast(), and frees it
 *    using aclChecklistFree().
 *
 * B) Using aclNBCheck() and callbacks: The caller creates the
 *    ACLChecklist using aclChecklistCreate(), and passes it to
 *    aclNBCheck().  Control eventually passes to ACLChecklist::checkCallback(),
 *    which will invoke the callback function as requested by the
 *    original caller of aclNBCheck().  This callback function must
 *    *not* invoke aclChecklistFree().  After the callback function
 *    returns, ACLChecklist::checkCallback() will free the ACLChecklist using
 *    aclChecklistFree().
 */


ACLChecklist *
aclChecklistCreate(const acl_access * A, request_t * request, const char *ident)
{
    ACLChecklist *checklist = new ACLChecklist;

    if (A)
        checklist->accessList = cbdataReference(A);

    if (request != NULL) {
        checklist->request = requestLink(request);
        checklist->src_addr = request->client_addr;
        checklist->my_addr = request->my_addr;
        checklist->my_port = request->my_port;
    }

#if USE_IDENT
    if (ident)
        xstrncpy(checklist->rfc931, ident, USER_IDENT_SZ);

#endif

    checklist->auth_user_request = NULL;

    return checklist;
}

/*********************/
/* Destroy functions */
/*********************/

void
aclDestroyAcls(acl ** head)
{
    ACL *next = NULL;

    for (acl *a = *head; a; a = next) {
        next = a->next;
        a->deleteSelf();
    }

    *head = NULL;
}

ACL::~ACL()
{
    debug(28, 3) ("aclDestroyAcls: '%s'\n", cfgline);
    safe_free(cfgline);
}

void
aclDestroyAclList(acl_list ** head)
{
    acl_list *l;

    for (l = *head; l; l = *head) {
        *head = l->next;
        l->deleteSelf();
    }
}

void
aclDestroyAccessList(acl_access ** list)
{
    acl_access *l = NULL;
    acl_access *next = NULL;

    for (l = *list; l; l = next) {
        debug(28, 3) ("aclDestroyAccessList: '%s'\n", l->cfgline);
        next = l->next;
        aclDestroyAclList(&l->aclList);
        safe_free(l->cfgline);
        cbdataFree(l);
    }

    *list = NULL;
}

/* maex@space.net (06.09.1996)
 *    destroy an _acl_deny_info_list */

void
aclDestroyDenyInfoList(acl_deny_info_list ** list)
{
    acl_deny_info_list *a = NULL;
    acl_deny_info_list *a_next = NULL;
    acl_name_list *l = NULL;
    acl_name_list *l_next = NULL;

    for (a = *list; a; a = a_next) {
        for (l = a->acl_list; l; l = l_next) {
            l_next = l->next;
            safe_free(l);
        }

        a_next = a->next;
        xfree(a->err_page_name);
        memFree(a, MEM_ACL_DENY_INFO_LIST);
    }

    *list = NULL;
}

wordlist *
ACL::dumpGeneric () const
{
    debug(28, 3) ("ACL::dumpGeneric: %s type %s\n", name, typeString());
    return dump();
}

/*
 * This function traverses all ACL elements referenced
 * by an access list (presumably 'http_access').   If 
 * it finds a PURGE method ACL, then it returns TRUE,
 * otherwise FALSE.
 */
/* XXX: refactor this more sensibly. perhaps have the parser detect it ? */
int
aclPurgeMethodInUse(acl_access * a)
{
    return a->containsPURGE();
}

#include "ACLStrategised.h"
bool
acl_access::containsPURGE() const
{
    acl_access const *a = this;
    acl_list *b;

    for (; a; a = a->next) {
        for (b = a->aclList; b; b = b->next) {
            ACLStrategised<method_t> *tempAcl = dynamic_cast<ACLStrategised<method_t> *>(b->_acl);

            if (!tempAcl)
                continue;

            if (tempAcl->match(METHOD_PURGE))
                return true;
        }
    }

    return false;
}

/* to be split into separate files in the future */

MemPool *ACLList::Pool(NULL);
void *
ACLList::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ACLList));

    if (!Pool)
        Pool = memPoolCreate("ACLList", sizeof (ACLList));

    return memPoolAlloc(Pool);
}

void
ACLList::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
ACLList::deleteSelf() const
{
    delete this;
}

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

void
acl_access::deleteSelf () const
{
    delete this;
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
    for (iterator i = Registry->begin(); i != Registry->end(); ++i)
        if (!strcmp (aType, (*i)->typeString))
            return true;

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
    for (iterator i = Registry->begin(); i != Registry->end(); ++i)
        if (!strcmp (typeToClone, (*i)->typeString))
            return (*i)->prototype->clone();

    return NULL;
}

void
ACL::Initialize()
{
    acl *a = Config.aclList;
    debug(53, 3) ("ACL::Initialize\n");

    while (a) {
        a->prepareForUse();
        a = a->next;
    }
}
