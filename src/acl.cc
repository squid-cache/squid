/*
 * $Id: acl.cc,v 1.305 2003/02/21 22:50:06 robertc Exp $
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
#include "splay.h"
#include "HttpRequest.h"
#include "authenticate.h"
#include "fde.h"
#include "ExternalACL.h"
#include "ACLDestinationIP.h"

static void aclParseIntlist(void *curlist);
#if SQUID_SNMP
static void aclParseWordList(void *curlist);
#endif
static void aclParseProtoList(void *curlist);
static void aclParseMethodList(void *curlist);
static void aclParseIntRange(void *curlist);
static void aclDestroyIntRange(intrange *);
static int aclMatchIntegerRange(intrange * data, int i);
#if SQUID_SNMP
static int aclMatchWordList(wordlist *, const char *);
#endif
static void aclParseUserMaxIP(void *data);
static void aclDestroyUserMaxIP(void *data);
static wordlist *aclDumpUserMaxIP(void *data);

static int aclMatchUserMaxIP(void *, auth_user_request_t *, struct in_addr);
static squid_acl aclStrToType(const char *s);
static wordlist *aclDumpIntlistList(intlist * data);
static wordlist *aclDumpIntRangeList(intrange * data);
static wordlist *aclDumpProtoList(intlist * data);
static wordlist *aclDumpMethodList(intlist * data);


#if USE_ARP_ACL
static void aclParseArpList(void *curlist);
static int decode_eth(const char *asc, char *eth);

static int aclMatchArp(void *dataptr, struct in_addr c);
static wordlist *aclDumpArpList(void *);
static splayNode::SPLAYCMP aclArpCompare;
static splayNode::SPLAYWALKEE aclDumpArpListWalkee;
#endif

MemPool *ACL::Pool(NULL);
void *
ACL::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ACL));

    if (!Pool)
        Pool = memPoolCreate("ACL", sizeof (ACL));

    return memPoolAlloc(Pool);
}

void
ACL::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
ACL::deleteSelf() const
{
    delete this;
}

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

template<class T>
inline int
splaystrcmp (T&l, T&r)
{
    return strcmp ((char *)l,(char *)r);
}


static squid_acl
aclStrToType(const char *s)
{
    if (!strcmp(s, "port"))
        return ACL_URL_PORT;

    if (!strcmp(s, "myport"))
        return ACL_MY_PORT;

    if (!strcmp(s, "maxconn"))
        return ACL_MAXCONN;

    if (!strncmp(s, "proto", 5))
        return ACL_PROTO;

    if (!strcmp(s, "method"))
        return ACL_METHOD;

    if (!strcmp(s, "src_as"))
        return ACL_SRC_ASN;

    if (!strcmp(s, "dst_as"))
        return ACL_DST_ASN;

#if SQUID_SNMP

    if (!strcmp(s, "snmp_community"))
        return ACL_SNMP_COMMUNITY;

#endif
#if SRC_RTT_NOT_YET_FINISHED

    if (!strcmp(s, "src_rtt"))
        return ACL_NETDB_SRC_RTT;

#endif
#if USE_ARP_ACL

    if (!strcmp(s, "arp"))
        return ACL_SRC_ARP;

#endif

    if (!strcmp(s, "rep_mime_type"))
        return ACL_REP_MIME_TYPE;

    if (!strcmp(s, "max_user_ip"))
        return ACL_MAX_USER_IP;

    if (!strcmp(s, "external"))
        return ACL_EXTERNAL;

    return ACL_NONE;
}

static const char *aclTypeToStr(squid_acl);
const char *
aclTypeToStr(squid_acl type)
{
    if (type == ACL_URL_PORT)
        return "port";

    if (type == ACL_MY_PORT)
        return "myport";

    if (type == ACL_MAXCONN)
        return "maxconn";

    if (type == ACL_PROTO)
        return "proto";

    if (type == ACL_METHOD)
        return "method";

    if (type == ACL_SRC_ASN)
        return "src_as";

    if (type == ACL_DST_ASN)
        return "dst_as";

#if SQUID_SNMP

    if (type == ACL_SNMP_COMMUNITY)
        return "snmp_community";

#endif
#if SRC_RTT_NOT_YET_FINISHED

    if (type == ACL_NETDB_SRC_RTT)
        return "src_rtt";

#endif
#if USE_ARP_ACL

    if (type == ACL_SRC_ARP)
        return "arp";

#endif

    if (type == ACL_REP_MIME_TYPE)
        return "rep_mime_type";

    if (type == ACL_MAX_USER_IP)
        return "max_user_ip";

    if (type == ACL_EXTERNAL)
        return "external";

    return "ERROR";
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

static void
aclParseIntlist(void *curlist)
{
    intlist **Tail;
    intlist *q = NULL;
    char *t = NULL;

    for (Tail = (intlist **)curlist; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        q = (intlist *)memAllocate(MEM_INTLIST);
        q->i = atoi(t);
        *(Tail) = q;
        Tail = &q->next;
    }
}

static void
aclParseIntRange(void *curlist)
{
    intrange **Tail;
    intrange *q = NULL;
    char *t = NULL;

    for (Tail = (intrange **)curlist; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        q = (intrange *)xcalloc(1, sizeof(intrange));
        q->i = atoi(t);
        t = strchr(t, '-');

        if (t && *(++t))
            q->j = atoi(t);
        else
            q->j = q->i;

        *(Tail) = q;

        Tail = &q->next;
    }
}

static void
aclParseProtoList(void *curlist)
{
    intlist **Tail;
    intlist *q = NULL;
    char *t = NULL;
    protocol_t protocol;

    for (Tail = (intlist **)curlist; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        protocol = urlParseProtocol(t);
        q = (intlist *)memAllocate(MEM_INTLIST);
        q->i = (int) protocol;
        *(Tail) = q;
        Tail = &q->next;
    }
}

static void
aclParseMethodList(void *curlist)
{
    intlist **Tail;
    intlist *q = NULL;
    char *t = NULL;

    for (Tail = (intlist **)curlist; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        q = (intlist *)memAllocate(MEM_INTLIST);
        q->i = (int) urlParseMethod(t);
        *(Tail) = q;
        Tail = &q->next;
    }
}

void
aclParseRegexList(void *curlist)
{
    relist **Tail;
    relist *q = NULL;
    char *t = NULL;
    regex_t comp;
    int errcode;
    int flags = REG_EXTENDED | REG_NOSUB;

    for (Tail = (relist **)curlist; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        if (strcmp(t, "-i") == 0) {
            flags |= REG_ICASE;
            continue;
        }

        if (strcmp(t, "+i") == 0) {
            flags &= ~REG_ICASE;
            continue;
        }

        if ((errcode = regcomp(&comp, t, flags)) != 0) {
            char errbuf[256];
            regerror(errcode, &comp, errbuf, sizeof errbuf);
            debug(28, 0) ("%s line %d: %s\n",
                          cfg_filename, config_lineno, config_input_line);
            debug(28, 0) ("aclParseRegexList: Invalid regular expression '%s': %s\n",
                          t, errbuf);
            continue;
        }

        q = (relist *)memAllocate(MEM_RELIST);
        q->pattern = xstrdup(t);
        q->regex = comp;
        *(Tail) = q;
        Tail = &q->next;
    }
}

#if SQUID_SNMP
static void
aclParseWordList(void *curlist)
{
    char *t = NULL;

    while ((t = strtokFile()))
        wordlistAdd((wordlist **)curlist, t);
}

#endif

ACL *
ACL::Factory (char const *type)
{
    ACL *result = Prototype::Factory (type);

    if (result)
        return result;

    squid_acl const acltype = aclStrToType(type);

    switch (acltype) {

    case ACL_URL_PORT:

    case ACL_MY_PORT:

    case ACL_MAXCONN:

    case ACL_PROTO:

    case ACL_METHOD:

    case ACL_SRC_ASN:

    case ACL_DST_ASN:
#if SQUID_SNMP

    case ACL_SNMP_COMMUNITY:
#endif
#if SRC_RTT_NOT_YET_FINISHED

    case ACL_NETDB_SRC_RTT:
#endif
#if USE_ARP_ACL

    case ACL_SRC_ARP:
#endif

    case ACL_REP_MIME_TYPE:

    case ACL_MAX_USER_IP:

    case ACL_EXTERNAL:
        result = new ACL(acltype);
        break;

    case ACL_DERIVED:

    default:
        fatal ("Unknown acl type in ACL::Factory");
    };

    assert (result);

    return result;
}

ACL::ACL (squid_acl const acltype) : type (acltype)
{}

ACL::ACL () : type(ACL_NONE)
{}

char const *
ACL::typeString() const
{
    return aclTypeToStr(aclType());
}

void
ACL::ParseAclLine(acl ** head)
{
    /* we're already using strtok() to grok the line */
    char *t = NULL;
    acl *A = NULL;
    LOCAL_ARRAY(char, aclname, ACL_NAME_SZ);
    squid_acl acltype;
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

    if ((t = strtok(NULL, w_space)) == NULL) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAclLine: missing ACL type.\n");
        return;
    }

    if ((acltype = aclStrToType(t)) == ACL_NONE && !Prototype::Registered (t)) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseAclLine: Invalid ACL type '%s'\n", t);
        return;
    }

    if ((A = FindByName(aclname)) == NULL) {
        debug(28, 3) ("aclParseAclLine: Creating ACL '%s'\n", aclname);
        A = ACL::Factory(t);
        xstrncpy(A->name, aclname, ACL_NAME_SZ);
        A->cfgline = xstrdup(config_input_line);
        new_acl = 1;
    } else {
        /* FIXME: strcmp the registry typeString */

        if (acltype != ACL_NONE && acltype != A->aclType()) {
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

bool
ACL::valid () const
{
    return data != NULL;
}

void
ACL::parse()
{
    switch (aclType()) {

    case ACL_REP_MIME_TYPE:
        aclParseRegexList(&data);
        break;

    case ACL_SRC_ASN:

    case ACL_MAXCONN:

    case ACL_DST_ASN:
        aclParseIntlist(&data);
        break;

    case ACL_MAX_USER_IP:
        aclParseUserMaxIP(&data);
        break;
#if SRC_RTT_NOT_YET_FINISHED

    case ACL_NETDB_SRC_RTT:
        aclParseIntlist(&data);
        break;
#endif

    case ACL_URL_PORT:

    case ACL_MY_PORT:
        aclParseIntRange(&data);
        break;

    case ACL_PROTO:
        aclParseProtoList(&data);
        break;

    case ACL_METHOD:
        aclParseMethodList(&data);
        break;

    case ACL_DERIVED:
        fatal ("overriden");
        break;
#if SQUID_SNMP

    case ACL_SNMP_COMMUNITY:
        aclParseWordList(&data);
        break;
#endif
#if USE_ARP_ACL

    case ACL_SRC_ARP:
        aclParseArpList(&data);
        break;
#endif

    case ACL_EXTERNAL:
        aclParseExternal(&data);
        break;

    case ACL_NONE:

    case ACL_ENUM_MAX:
        fatal("Bad ACL type");
        break;
    }
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

int
aclMatchRegex(relist * data, const char *word)
{
    relist *first, *prev;

    if (word == NULL)
        return 0;

    debug(28, 3) ("aclMatchRegex: checking '%s'\n", word);

    first = data;

    prev = NULL;

    while (data) {
        debug(28, 3) ("aclMatchRegex: looking for '%s'\n", data->pattern);

        if (regexec(&data->regex, word, 0, 0, 0) == 0) {
            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = data->next;
                data->next = first->next;
                first->next = data;
            }

            return 1;
        }

        prev = data;
        data = data->next;
    }

    return 0;
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


CBDATA_TYPE(acl_user_ip_data);

void
aclParseUserMaxIP(void *data)
{
    acl_user_ip_data **acldata = (acl_user_ip_data **)data;
    char *t = NULL;
    CBDATA_INIT_TYPE(acl_user_ip_data);

    if (*acldata) {
        debug(28, 1) ("Attempting to alter already set User max IP acl\n");
        return;
    }

    *acldata = cbdataAlloc(acl_user_ip_data);
    t = strtokFile();

    if (!t)
        goto error;

    debug(28, 5) ("aclParseUserMaxIP: First token is %s\n", t);

    if (strcmp("-s", t) == 0) {
        debug(28, 5) ("aclParseUserMaxIP: Going strict\n");
        (*acldata)->flags.strict = 1;
        t = strtokFile();

        if (!t)
            goto error;
    }

    (*acldata)->max = atoi(t);
    debug(28, 5) ("aclParseUserMaxIP: Max IP address's %d\n", (int) (*acldata)->max);
    return;

error:
    fatal("aclParseUserMaxIP: Malformed ACL %d\n");
}

void
aclDestroyUserMaxIP(void *data)
{
    acl_user_ip_data **acldata = (acl_user_ip_data **)data;

    if (*acldata)
        cbdataFree(*acldata);

    *acldata = NULL;
}

wordlist *
aclDumpUserMaxIP(void *data)
{
    acl_user_ip_data *acldata = (acl_user_ip_data *)data;
    wordlist *W = NULL;
    char buf[128];

    if (acldata->flags.strict)
        wordlistAdd(&W, "-s");

    snprintf(buf, sizeof(buf), "%lu", (unsigned long int) acldata->max);

    wordlistAdd(&W, buf);

    return W;
}

/*
 * aclMatchUserMaxIP - check for users logging in from multiple IP's 
 * 0 : No match
 * 1 : Match 
 */
int
aclMatchUserMaxIP(void *data, auth_user_request_t * auth_user_request,

                  struct in_addr src_addr)
{
    /*
     * the logic for flush the ip list when the limit is hit vs keep
     * it sorted in most recent access order and just drop the oldest
     * one off is currently undecided
     */
    acl_user_ip_data *acldata = (acl_user_ip_data *)data;

    if (authenticateAuthUserRequestIPCount(auth_user_request) <= acldata->max)
        return 0;

    /* this is a match */
    if (acldata->flags.strict)
    {
        /*
         * simply deny access - the user name is already associated with
         * the request 
         */
        /* remove _this_ ip, as it is the culprit for going over the limit */
        authenticateAuthUserRequestRemoveIp(auth_user_request, src_addr);
        debug(28, 4) ("aclMatchUserMaxIP: Denying access in strict mode\n");
    } else
    {
        /*
         * non-strict - remove some/all of the cached entries 
         * ie to allow the user to move machines easily
         */
        authenticateAuthUserRequestClearIp(auth_user_request);
        debug(28, 4) ("aclMatchUserMaxIP: Denying access in non-strict mode - flushing the user ip cache\n");
    }

    return 1;
}

static int
aclMatchInteger(intlist * data, int i)
{
    intlist *first, *prev;
    first = data;
    prev = NULL;

    while (data) {
        if (data->i == i) {
            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = data->next;
                data->next = first->next;
                first->next = data;
            }

            return 1;
        }

        prev = data;
        data = data->next;
    }

    return 0;
}

static int
aclMatchIntegerRange(intrange * data, int i)
{
    intrange *first, *prev;
    first = data;
    prev = NULL;

    while (data) {
        if (i < data->i) {
            (void) 0;
        } else if (i > data->j) {
            (void) 0;
        } else {
            /* matched */

            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = data->next;
                data->next = first->next;
                first->next = data;
            }

            return 1;
        }

        prev = data;
        data = data->next;
    }

    return 0;
}

#if SQUID_SNMP
static int
aclMatchWordList(wordlist * w, const char *word)
{
    debug(28, 3) ("aclMatchWordList: looking for '%s'\n", word);

    while (w != NULL) {
        debug(28, 3) ("aclMatchWordList: checking '%s'\n", w->key);

        if (!strcmp(w->key, word))
            return 1;

        w = w->next;
    }

    return 0;
}

#endif


bool
ACL::requiresRequest() const
{
    switch (aclType()) {

    case ACL_DST_ASN:

    case ACL_MAX_USER_IP:

    case ACL_METHOD:

    case ACL_PROTO:

    case ACL_REP_MIME_TYPE:

    case ACL_URL_PORT:
        /* These ACL types require checklist->request */
        return true;

    default:
        return false;
    }
}

int
ACL::checklistMatches(ACLChecklist *checklist)
{
    if (NULL == checklist->request && requiresRequest()) {
        debug(28, 1) ("WARNING: '%s' ACL is used but there is no"
                      " HTTP request -- access denied.\n", name);
        return 0;
    }

    debug(28, 3) ("aclMatchAcl: checking '%s'\n", cfgline);
    return match(checklist);
}

int
ACL::match(ACLChecklist * checklist)
{
    request_t *r = checklist->request;
    const ipcache_addrs *ia = NULL;
    const char *header;
    int k, ti;

    switch (aclType()) {

    case ACL_MAXCONN:
        k = clientdbEstablished(checklist->src_addr, 0);
        return ((k > ((intlist *) data)->i) ? 1 : 0);
        /* NOTREACHED */

    case ACL_URL_PORT:
        return aclMatchIntegerRange((intrange *)data, (int) r->port);
        /* NOTREACHED */

    case ACL_MY_PORT:
        return aclMatchIntegerRange((intrange *)data, (int) checklist->my_port);
        /* NOTREACHED */

    case ACL_PROTO:
        return aclMatchInteger((intlist *)data, r->protocol);
        /* NOTREACHED */

    case ACL_METHOD:
        return aclMatchInteger((intlist *)data, r->method);
        /* NOTREACHED */

    case ACL_MAX_USER_IP:

        if ((ti = checklist->authenticated()) != 1)
            return ti;

        ti = aclMatchUserMaxIP(data, checklist->auth_user_request,
                               checklist->src_addr);

        checklist->auth_user_request = NULL;

        return ti;

        /* NOTREACHED */
#if SQUID_SNMP

    case ACL_SNMP_COMMUNITY:
        return aclMatchWordList((wordlist *)data, checklist->snmp_community);

        /* NOTREACHED */
#endif

    case ACL_SRC_ASN:
        return asnMatchIp(data, checklist->src_addr);

        /* NOTREACHED */

    case ACL_DST_ASN:
        ia = ipcache_gethostbyname(r->host, IP_LOOKUP_IF_MISS);

        if (ia) {
            for (k = 0; k < (int) ia->count; k++) {
                if (asnMatchIp(data, ia->in_addrs[k]))
                    return 1;
            }

            return 0;
        } else if (checklist->state[ACL_DST_ASN] == ACL_LOOKUP_NONE) {
            debug(28, 3) ("asnMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
                          name, r->host);
            checklist->changeState (DestinationIPLookup::Instance());
        } else {
            return asnMatchIp(data, no_addr);
        }

        return 0;
        /* NOTREACHED */
#if USE_ARP_ACL

    case ACL_SRC_ARP:
        return aclMatchArp(&data, checklist->src_addr);
        /* NOTREACHED */
#endif

    case ACL_REP_MIME_TYPE:

        if (!checklist->reply)
            return 0;

        header = httpHeaderGetStr(&checklist->reply->header, HDR_CONTENT_TYPE);

        if (NULL == header)
            header = "";

        return aclMatchRegex((relist *)data, header);

        /* NOTREACHED */

    case ACL_EXTERNAL:
        return aclMatchExternal(data, checklist);

        /* NOTREACHED */

    case ACL_NONE:

    case ACL_ENUM_MAX:
        break;

    case ACL_DERIVED:
        fatal ("overridden");
    }

    debug(28, 0) ("aclMatchAcl: '%s' has bad type %d\n",
                  name, aclType());
    return 0;
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

        if (checklist->matchAclList(A->aclList, true)) {
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
    int i;
    ACLChecklist *checklist = new ACLChecklist;
    checklist->accessList = cbdataReference(A);

    if (request != NULL) {
        checklist->request = requestLink(request);
        checklist->src_addr = request->client_addr;
        checklist->my_addr = request->my_addr;
        checklist->my_port = request->my_port;
    }

    for (i = 0; i < ACL_ENUM_MAX; i++)
        checklist->state[i] = ACL_LOOKUP_NONE;

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
aclDestroyRegexList(relist * data)
{
    relist *next = NULL;

    for (; data; data = next) {
        next = data->next;
        regfree(&data->regex);
        safe_free(data->pattern);
        memFree(data, MEM_RELIST);
    }
}

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

    switch (aclType()) {
#if USE_ARP_ACL

    case ACL_SRC_ARP:
#endif
#if SQUID_SNMP

    case ACL_SNMP_COMMUNITY:
        wordlistDestroy((wordlist **) & data);
        break;
#endif
        /* Destroyed in the children */

    case ACL_DERIVED:
        break;

    case ACL_REP_MIME_TYPE:
        aclDestroyRegexList((relist *)data);
        break;

    case ACL_PROTO:

    case ACL_METHOD:

    case ACL_SRC_ASN:

    case ACL_DST_ASN:
#if SRC_RTT_NOT_YET_FINISHED

    case ACL_NETDB_SRC_RTT:
#endif

    case ACL_MAXCONN:
        intlistDestroy((intlist **) & data);
        break;

    case ACL_MAX_USER_IP:
        aclDestroyUserMaxIP(&data);
        break;

    case ACL_URL_PORT:

    case ACL_MY_PORT:
        aclDestroyIntRange((intrange *)data);
        break;

    case ACL_EXTERNAL:
        aclDestroyExternal(&data);
        break;

    case ACL_NONE:

    case ACL_ENUM_MAX:
        debug(28, 1) ("aclDestroyAcls: no case for ACL type %d\n", aclType());
        break;
    }

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

static void
aclDestroyIntRange(intrange * list)
{
    intrange *w = NULL;
    intrange *n = NULL;

    for (w = list; w; w = n) {
        n = w->next;
        safe_free(w);
    }
}

wordlist *
aclDumpRegexList(relist * data)
{
    wordlist *W = NULL;

    while (data != NULL) {
        wordlistAdd(&W, data->pattern);
        data = data->next;
    }

    return W;
}

static wordlist *
aclDumpIntlistList(intlist * data)
{
    wordlist *W = NULL;
    char buf[32];

    while (data != NULL) {
        snprintf(buf, sizeof(buf), "%d", data->i);
        wordlistAdd(&W, buf);
        data = data->next;
    }

    return W;
}

static wordlist *
aclDumpIntRangeList(intrange * data)
{
    wordlist *W = NULL;
    char buf[32];

    while (data != NULL) {
        if (data->i == data->j)
            snprintf(buf, sizeof(buf), "%d", data->i);
        else
            snprintf(buf, sizeof(buf), "%d-%d", data->i, data->j);

        wordlistAdd(&W, buf);

        data = data->next;
    }

    return W;
}

static wordlist *
aclDumpProtoList(intlist * data)
{
    wordlist *W = NULL;

    while (data != NULL) {
        wordlistAdd(&W, ProtocolStr[data->i]);
        data = data->next;
    }

    return W;
}

static wordlist *
aclDumpMethodList(intlist * data)
{
    wordlist *W = NULL;

    while (data != NULL) {
        wordlistAdd(&W, RequestMethodStr[data->i]);
        data = data->next;
    }

    return W;
}

wordlist *
ACL::dumpGeneric () const
{
    debug(28, 3) ("ACL::dumpGeneric: %s type %d\n", name, aclType());
    return dump();
}

wordlist *
ACL::dump() const
{
    switch (aclType()) {
#if SQUID_SNMP

    case ACL_SNMP_COMMUNITY:
        return wordlistDup((wordlist *)data);
#endif

    case ACL_DERIVED:
        fatal ("unused");

    case ACL_REP_MIME_TYPE:
        return aclDumpRegexList((relist *)data);

    case ACL_SRC_ASN:

    case ACL_MAXCONN:

    case ACL_DST_ASN:
        return aclDumpIntlistList((intlist *)data);

    case ACL_MAX_USER_IP:
        return aclDumpUserMaxIP(data);

    case ACL_URL_PORT:

    case ACL_MY_PORT:
        return aclDumpIntRangeList((intrange *)data);

    case ACL_PROTO:
        return aclDumpProtoList((intlist *)data);

    case ACL_METHOD:
        return aclDumpMethodList((intlist *)data);
#if USE_ARP_ACL

    case ACL_SRC_ARP:
        return aclDumpArpList(data);
#endif

    case ACL_EXTERNAL:
        return aclDumpExternal(data);

    case ACL_NONE:

    case ACL_ENUM_MAX:
        break;
    }

    debug(28, 1) ("ACL::dumpGeneric: no case for ACL type %d\n", aclType());
    return NULL;
}

/*
 * This function traverses all ACL elements referenced
 * by an access list (presumably 'http_access').   If 
 * it finds a PURGE method ACL, then it returns TRUE,
 * otherwise FALSE.
 */
int
aclPurgeMethodInUse(acl_access * a)
{
    return a->containsPURGE();
}

bool
acl_access::containsPURGE() const
{
    acl_access const *a = this;
    acl_list *b;

    for (; a; a = a->next) {
        for (b = a->aclList; b; b = b->next) {
            if (ACL_METHOD != b->_acl->aclType())
                continue;

            if (b->_acl->containsPURGE())
                return true;
        }
    }

    return false;
}

bool
ACL::containsPURGE() const
{
    if (aclMatchInteger((intlist *)data, METHOD_PURGE))
        return true;

    return false;
}


#if USE_ARP_ACL
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

#ifdef _SQUID_SOLARIS_
#include <sys/sockio.h>
#else
#include <sys/sysctl.h>
#endif
#ifdef _SQUID_LINUX_
#include <net/if_arp.h>
#include <sys/ioctl.h>
#else
#include <net/if_dl.h>
#endif
#include <net/route.h>
#include <net/if.h>
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

/*
 * Decode an ascii representation (asc) of an ethernet adress, and place
 * it in eth[6].
 */
static int
decode_eth(const char *asc, char *eth)
{
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;

    if (sscanf(asc, "%x:%x:%x:%x:%x:%x", &a1, &a2, &a3, &a4, &a5, &a6) != 6) {
        debug(28, 0) ("decode_eth: Invalid ethernet address '%s'\n", asc);
        return 0;		/* This is not valid address */
    }

    eth[0] = (u_char) a1;
    eth[1] = (u_char) a2;
    eth[2] = (u_char) a3;
    eth[3] = (u_char) a4;
    eth[4] = (u_char) a5;
    eth[5] = (u_char) a6;
    return 1;
}

static acl_arp_data *
aclParseArpData(const char *t)
{
    LOCAL_ARRAY(char, eth, 256);
    acl_arp_data *q = (acl_arp_data *)xcalloc(1, sizeof(acl_arp_data));
    debug(28, 5) ("aclParseArpData: %s\n", t);

    if (sscanf(t, "%[0-9a-fA-F:]", eth) != 1) {
        debug(28, 0) ("aclParseArpData: Bad ethernet address: '%s'\n", t);
        safe_free(q);
        return NULL;
    }

    if (!decode_eth(eth, q->eth)) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseArpData: Ignoring invalid ARP acl entry: can't parse '%s'\n", eth);
        safe_free(q);
        return NULL;
    }

    return q;
}


/*******************/
/* aclParseArpList */
/*******************/
static void
aclParseArpList(void *curlist)
{
    char *t = NULL;
    splayNode **Top = (splayNode **)curlist;
    acl_arp_data *q = NULL;

    while ((t = strtokFile())) {
        if ((q = aclParseArpData(t)) == NULL)
            continue;

        *Top = splay_insert(q, *Top, aclArpCompare);
    }
}

/***************/
/* aclMatchArp */
/***************/
static int

aclMatchArp(void *dataptr, struct in_addr c)
{
#if defined(_SQUID_LINUX_)

    struct arpreq arpReq;

    struct sockaddr_in ipAddr;

    unsigned char ifbuffer[sizeof(struct ifreq) * 64];

    struct ifconf ifc;

    struct ifreq *ifr;
    int offset;
    splayNode **Top = (splayNode **)dataptr;
    /*
     * The linux kernel 2.2 maintains per interface ARP caches and
     * thus requires an interface name when doing ARP queries.
     * 
     * The older 2.0 kernels appear to use a unified ARP cache,
     * and require an empty interface name
     * 
     * To support both, we attempt the lookup with a blank interface
     * name first. If that does not succeed, the try each interface
     * in turn
     */
    /*
     * Set up structures for ARP lookup with blank interface name
     */
    ipAddr.sin_family = AF_INET;
    ipAddr.sin_port = 0;
    ipAddr.sin_addr = c;
    memset(&arpReq, '\0', sizeof(arpReq));

    xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));
    /* Query ARP table */

    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) != -1)
    {
        /* Skip non-ethernet interfaces */

        if (arpReq.arp_ha.sa_family != ARPHRD_ETHER) {
            return 0;
        }

        debug(28, 4) ("Got address %02x:%02x:%02x:%02x:%02x:%02x\n",
                      arpReq.arp_ha.sa_data[0] & 0xff, arpReq.arp_ha.sa_data[1] & 0xff,
                      arpReq.arp_ha.sa_data[2] & 0xff, arpReq.arp_ha.sa_data[3] & 0xff,
                      arpReq.arp_ha.sa_data[4] & 0xff, arpReq.arp_ha.sa_data[5] & 0xff);
        /* Do lookup */
        const void *X = arpReq.arp_ha.sa_data;
        *Top = splay_splay(&X, *Top, aclArpCompare);
        debug(28, 3) ("aclMatchArp: '%s' %s\n",
                      inet_ntoa(c), splayLastResult ? "NOT found" : "found");
        return (0 == splayLastResult);
    }

    /* lookup list of interface names */
    ifc.ifc_len = sizeof(ifbuffer);

    ifc.ifc_buf = (char *)ifbuffer;

    if (ioctl(HttpSockets[0], SIOCGIFCONF, &ifc) < 0)
    {
        debug(28, 1) ("Attempt to retrieve interface list failed: %s\n",
                      xstrerror());
        return 0;
    }

    if (ifc.ifc_len > (int)sizeof(ifbuffer))
    {
        debug(28, 1) ("Interface list too long - %d\n", ifc.ifc_len);
        return 0;
    }

    /* Attempt ARP lookup on each interface */
    offset = 0;

    while (offset < ifc.ifc_len)
    {

        ifr = (struct ifreq *) (ifbuffer + offset);
        offset += sizeof(*ifr);
        /* Skip loopback and aliased interfaces */

        if (0 == strncmp(ifr->ifr_name, "lo", 2))
            continue;

        if (NULL != strchr(ifr->ifr_name, ':'))
            continue;

        debug(28, 4) ("Looking up ARP address for %s on %s\n", inet_ntoa(c),
                      ifr->ifr_name);

        /* Set up structures for ARP lookup */
        ipAddr.sin_family = AF_INET;

        ipAddr.sin_port = 0;

        ipAddr.sin_addr = c;

        memset(&arpReq, '\0', sizeof(arpReq));

        xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));

        strncpy(arpReq.arp_dev, ifr->ifr_name, sizeof(arpReq.arp_dev) - 1);

        arpReq.arp_dev[sizeof(arpReq.arp_dev) - 1] = '\0';

        /* Query ARP table */
        if (-1 == ioctl(HttpSockets[0], SIOCGARP, &arpReq)) {
            /*
             * Query failed.  Do not log failed lookups or "device
             * not supported"
             */

            if (ENXIO == errno)
                (void) 0;
            else if (ENODEV == errno)
                (void) 0;
            else
                debug(28, 1) ("ARP query failed: %s: %s\n",
                              ifr->ifr_name, xstrerror());

            continue;
        }

        /* Skip non-ethernet interfaces */
        if (arpReq.arp_ha.sa_family != ARPHRD_ETHER)
            continue;

        debug(28, 4) ("Got address %02x:%02x:%02x:%02x:%02x:%02x on %s\n",
                      arpReq.arp_ha.sa_data[0] & 0xff,
                      arpReq.arp_ha.sa_data[1] & 0xff,
                      arpReq.arp_ha.sa_data[2] & 0xff,
                      arpReq.arp_ha.sa_data[3] & 0xff,
                      arpReq.arp_ha.sa_data[4] & 0xff,
                      arpReq.arp_ha.sa_data[5] & 0xff, ifr->ifr_name);

        /* Do lookup */
        const void *X = arpReq.arp_ha.sa_data;

        *Top = splay_splay(&X, *Top, aclArpCompare);

        /* Return if match, otherwise continue to other interfaces */
        if (0 == splayLastResult) {
            debug(28, 3) ("aclMatchArp: %s found on %s\n",
                          inet_ntoa(c), ifr->ifr_name);
            return 1;
        }

        /*
         * Should we stop looking here? Can the same IP address
         * exist on multiple interfaces?
         */
    }

#elif defined(_SQUID_SOLARIS_)

    struct arpreq arpReq;

    struct sockaddr_in ipAddr;

    unsigned char ifbuffer[sizeof(struct ifreq) * 64];

    struct ifconf ifc;

    struct ifreq *ifr;

    int offset;

    splayNode **Top = dataptr;

    /*
    * Set up structures for ARP lookup with blank interface name
    */
    ipAddr.sin_family = AF_INET;

    ipAddr.sin_port = 0;

    ipAddr.sin_addr = c;

    memset(&arpReq, '\0', sizeof(arpReq));

    xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));

    /* Query ARP table */
    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) != -1)
    {
        /*
        *  Solaris (at least 2.6/x86) does not use arp_ha.sa_family -
        * it returns 00:00:00:00:00:00 for non-ethernet media
        */

        if (arpReq.arp_ha.sa_data[0] == 0 &&
                arpReq.arp_ha.sa_data[1] == 0 &&
                arpReq.arp_ha.sa_data[2] == 0 &&
                arpReq.arp_ha.sa_data[3] == 0 &&
                arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0)
            return 0;

        debug(28, 4) ("Got address %02x:%02x:%02x:%02x:%02x:%02x\n",
                      arpReq.arp_ha.sa_data[0] & 0xff, arpReq.arp_ha.sa_data[1] & 0xff,
                      arpReq.arp_ha.sa_data[2] & 0xff, arpReq.arp_ha.sa_data[3] & 0xff,
                      arpReq.arp_ha.sa_data[4] & 0xff, arpReq.arp_ha.sa_data[5] & 0xff);

        /* Do lookup */
        *Top = splay_splay(&arpReq.arp_ha.sa_data, *Top, aclArpCompare);

        debug(28, 3) ("aclMatchArp: '%s' %s\n",
                      inet_ntoa(c), splayLastResult ? "NOT found" : "found");

        return (0 == splayLastResult);
    }

#else
    WRITE ME;

#endif
    /*
     * Address was not found on any interface
     */
    debug(28, 3) ("aclMatchArp: %s NOT found\n", inet_ntoa(c));

    return 0;
}

static int
aclArpCompare(void * const &a, void * const &b)
{
    return memcmp(a, b, 6);
}

#if UNUSED_CODE
/**********************************************************************
* This is from the pre-splay-tree code for BSD
* I suspect the Linux approach will work on most O/S and be much
* better - <luyer@ucs.uwa.edu.au>
***********************************************************************
static int
checkARP(u_long ip, char *eth)
{
    int mib[6] =
    {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
    size_t needed;
    char *buf, *next, *lim;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
	debug(28, 0) ("Can't estimate ARP table size!\n");
	return 0;
    }
    if ((buf = xmalloc(needed)) == NULL) {
	debug(28, 0) ("Can't allocate temporary ARP table!\n");
	return 0;
    }
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
	debug(28, 0) ("Can't retrieve ARP table!\n");
	xfree(buf);
	return 0;
    }
    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
	rtm = (struct rt_msghdr *) next;
	sin = (struct sockaddr_inarp *) (rtm + 1);
	sdl = (struct sockaddr_dl *) (sin + 1);
	if (sin->sin_addr.s_addr == ip) {
	    if (sdl->sdl_alen)
		if (!memcmp(LLADDR(sdl), eth, 6)) {
		    xfree(buf);
		    return 1;
		}
	    break;
	}
    }
    xfree(buf);
    return 0;
}
**********************************************************************/
#endif

static void
aclDumpArpListWalkee(void * const &node, void *state)
{
    acl_arp_data *arp = (acl_arp_data *)node;
    static char buf[24];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->eth[0], arp->eth[1], arp->eth[2], arp->eth[3],
             arp->eth[4], arp->eth[5]);
    wordlistAdd((wordlist **)state, buf);
}

static wordlist *
aclDumpArpList(void *data)
{
    wordlist *w = NULL;
    splay_walk((splayNode *)data, aclDumpArpListWalkee, &w);
    return w;
}

/* ==== END ARP ACL SUPPORT =============================================== */
#endif /* USE_ARP_ACL */

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

ACL *
ACL::clone()const
{
    fatal ("Cannot clone base class");
    return NULL;
}
