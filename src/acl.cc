/*
 * $Id: acl.cc,v 1.301 2003/02/12 06:10:58 robertc Exp $
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
#include "ACLProxyAuth.h"
#if USE_IDENT
#include "ACLIdent.h"
#endif
#include "ACLUserData.h"

static void aclParseDomainList(void *curlist);
static void aclParseIntlist(void *curlist);
#if SQUID_SNMP
static void aclParseWordList(void *curlist);
#endif
static void aclParseProtoList(void *curlist);
static void aclParseMethodList(void *curlist);
static void aclParseTimeSpec(void *curlist);
static void aclParseIntRange(void *curlist);
static void aclDestroyTimeList(acl_time_data * data);
static void aclDestroyIntRange(intrange *);
static void aclLookupProxyAuthStart(ACLChecklist * checklist);
static void aclLookupProxyAuthDone(void *data, char *result);
static acl*aclFindByName(const char *name);
static int aclMatchTime(acl_time_data * data, time_t when);
static int aclMatchDomainList(void *dataptr, const char *);
static int aclMatchIntegerRange(intrange * data, int i);
#if SQUID_SNMP
static int aclMatchWordList(wordlist *, const char *);
#endif
static void aclParseUserMaxIP(void *data);
static void aclDestroyUserMaxIP(void *data);
static wordlist *aclDumpUserMaxIP(void *data);
static int aclMatchUserMaxIP(void *, auth_user_request_t *, struct in_addr);
static squid_acl aclStrToType(const char *s);
#if USE_IDENT
static IDCB aclLookupIdentDone;
#endif
static IPH aclLookupDstIPforASNDone;
static FQDNH aclLookupSrcFQDNDone;
static FQDNH aclLookupDstFQDNDone;
static EAH aclLookupExternalDone;
static wordlist *aclDumpDomainList(void *data);
static wordlist *aclDumpTimeSpecList(acl_time_data *);
static wordlist *aclDumpRegexList(relist * data);
static wordlist *aclDumpIntlistList(intlist * data);
static wordlist *aclDumpIntRangeList(intrange * data);
static wordlist *aclDumpProtoList(intlist * data);
static wordlist *aclDumpMethodList(intlist * data);
static splayNode::SPLAYCMP aclHostDomainCompare;
template<class T> int aclDomainCompare(T const &a, T const &b);
static splayNode::SPLAYWALKEE aclDumpDomainListWalkee;


#if USE_ARP_ACL
static void aclParseArpList(void *curlist);
static int decode_eth(const char *asc, char *eth);
static int aclMatchArp(void *dataptr, struct in_addr c);
static wordlist *aclDumpArpList(void *);
static splayNode::SPLAYCMP aclArpCompare;
static splayNode::SPLAYWALKEE aclDumpArpListWalkee;
#endif
static int aclCacheMatchAcl(dlink_list * cache, squid_acl acltype, void *data, char const *MatchParam);
#if USE_SSL
static void aclParseCertList(void *curlist);
static int aclMatchUserCert(void *data, ACLChecklist *);
static int aclMatchCACert(void *data, ACLChecklist *);
static wordlist *aclDumpCertList(void *data);
static void aclDestroyCertList(void *data);
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
    if (!strcmp(s, "domain"))
	return ACL_DST_DOMAIN;
    if (!strcmp(s, "dstdomain"))
	return ACL_DST_DOMAIN;
    if (!strcmp(s, "srcdomain"))
	return ACL_SRC_DOMAIN;
    if (!strcmp(s, "dstdom_regex"))
	return ACL_DST_DOM_REGEX;
    if (!strcmp(s, "srcdom_regex"))
	return ACL_SRC_DOM_REGEX;
    if (!strcmp(s, "time"))
	return ACL_TIME;
    if (!strcmp(s, "pattern"))
	return ACL_URLPATH_REGEX;
    if (!strcmp(s, "urlpath_regex"))
	return ACL_URLPATH_REGEX;
    if (!strcmp(s, "url_regex"))
	return ACL_URL_REGEX;
    if (!strcmp(s, "port"))
	return ACL_URL_PORT;
    if (!strcmp(s, "myport"))
	return ACL_MY_PORT;
    if (!strcmp(s, "maxconn"))
	return ACL_MAXCONN;
#if USE_IDENT
    if (!strcmp(s, "ident"))
	return ACL_IDENT;
    if (!strcmp(s, "ident_regex"))
	return ACL_IDENT_REGEX;
#endif
    if (!strncmp(s, "proto", 5))
	return ACL_PROTO;
    if (!strcmp(s, "method"))
	return ACL_METHOD;
    if (!strcmp(s, "browser"))
	return ACL_BROWSER;
    if (!strcmp(s, "referer_regex"))
	return ACL_REFERER_REGEX;
    if (!strcmp(s, "proxy_auth"))
	return ACL_PROXY_AUTH;
    if (!strcmp(s, "proxy_auth_regex"))
	return ACL_PROXY_AUTH_REGEX;
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
    if (!strcmp(s, "req_mime_type"))
	return ACL_REQ_MIME_TYPE;
    if (!strcmp(s, "rep_mime_type"))
	return ACL_REP_MIME_TYPE;
    if (!strcmp(s, "max_user_ip"))
	return ACL_MAX_USER_IP;
    if (!strcmp(s, "external"))
	return ACL_EXTERNAL;
#if USE_SSL
    if (!strcmp(s, "user_cert"))
	return ACL_USER_CERT;
    if (!strcmp(s, "ca_cert"))
	return ACL_CA_CERT;
#endif
    return ACL_NONE;
}

static const char *aclTypeToStr(squid_acl);
const char *
aclTypeToStr(squid_acl type)
{
    if (type == ACL_DST_DOMAIN)
	return "dstdomain";
    if (type == ACL_SRC_DOMAIN)
	return "srcdomain";
    if (type == ACL_DST_DOM_REGEX)
	return "dstdom_regex";
    if (type == ACL_SRC_DOM_REGEX)
	return "srcdom_regex";
    if (type == ACL_TIME)
	return "time";
    if (type == ACL_URLPATH_REGEX)
	return "urlpath_regex";
    if (type == ACL_URL_REGEX)
	return "url_regex";
    if (type == ACL_URL_PORT)
	return "port";
    if (type == ACL_MY_PORT)
	return "myport";
    if (type == ACL_MAXCONN)
	return "maxconn";
#if USE_IDENT
    if (type == ACL_IDENT_REGEX)
	return "ident_regex";
#endif
    if (type == ACL_PROTO)
	return "proto";
    if (type == ACL_METHOD)
	return "method";
    if (type == ACL_BROWSER)
	return "browser";
    if (type == ACL_REFERER_REGEX)
	return "referer_regex";
    if (type == ACL_PROXY_AUTH_REGEX)
	return "proxy_auth_regex";
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
    if (type == ACL_REQ_MIME_TYPE)
	return "req_mime_type";
    if (type == ACL_REP_MIME_TYPE)
	return "rep_mime_type";
    if (type == ACL_MAX_USER_IP)
	return "max_user_ip";
    if (type == ACL_EXTERNAL)
	return "external";
#if USE_SSL
    if (type == ACL_USER_CERT)
	return "user_cert";
    if (type == ACL_CA_CERT)
	return "ca_cert";
#endif
    return "ERROR";
}

static acl *
aclFindByName(const char *name)
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
    for (Tail = (intlist **)curlist; *Tail; Tail = &((*Tail)->next));
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
    for (Tail = (intrange **)curlist; *Tail; Tail = &((*Tail)->next));
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
    for (Tail = (intlist **)curlist; *Tail; Tail = &((*Tail)->next));
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
    for (Tail = (intlist **)curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	q = (intlist *)memAllocate(MEM_INTLIST);
	q->i = (int) urlParseMethod(t);
	*(Tail) = q;
	Tail = &q->next;
    }
}

static void
aclParseTimeSpec(void *curlist)
{
    acl_time_data *q = NULL;
    acl_time_data **Tail;
    int h1, m1, h2, m2;
    char *t = NULL;
    for (Tail = (acl_time_data **)curlist; *Tail; Tail = &((*Tail)->next));
    q = (acl_time_data *)memAllocate(MEM_ACL_TIME_DATA);
    while ((t = strtokFile())) {
	if (*t < '0' || *t > '9') {
	    /* assume its day-of-week spec */
	    while (*t) {
		switch (*t++) {
		case 'S':
		    q->weekbits |= ACL_SUNDAY;
		    break;
		case 'M':
		    q->weekbits |= ACL_MONDAY;
		    break;
		case 'T':
		    q->weekbits |= ACL_TUESDAY;
		    break;
		case 'W':
		    q->weekbits |= ACL_WEDNESDAY;
		    break;
		case 'H':
		    q->weekbits |= ACL_THURSDAY;
		    break;
		case 'F':
		    q->weekbits |= ACL_FRIDAY;
		    break;
		case 'A':
		    q->weekbits |= ACL_SATURDAY;
		    break;
		case 'D':
		    q->weekbits |= ACL_WEEKDAYS;
		    break;
		case '-':
		    /* ignore placeholder */
		    break;
		default:
		    debug(28, 0) ("%s line %d: %s\n",
			cfg_filename, config_lineno, config_input_line);
		    debug(28, 0) ("aclParseTimeSpec: Bad Day '%c'\n", *t);
		    break;
		}
	    }
	} else {
	    /* assume its time-of-day spec */
	    if (sscanf(t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4) {
		debug(28, 0) ("%s line %d: %s\n",
		    cfg_filename, config_lineno, config_input_line);
		debug(28, 0) ("aclParseTimeSpec: IGNORING Bad time range\n");
		memFree(q, MEM_ACL_TIME_DATA);
		return;
	    }
	    q->start = h1 * 60 + m1;
	    q->stop = h2 * 60 + m2;
	    if (q->start > q->stop) {
		debug(28, 0) ("%s line %d: %s\n",
		    cfg_filename, config_lineno, config_input_line);
		debug(28, 0) ("aclParseTimeSpec: IGNORING Reversed time range\n");
		memFree(q, MEM_ACL_TIME_DATA);
		return;
	    }
	}
    }
    if (q->start == 0 && q->stop == 0)
	q->stop = 23 * 60 + 59;
    if (q->weekbits == 0)
	q->weekbits = ACL_ALLWEEK;
    *(Tail) = q;
    Tail = &q->next;
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
    for (Tail = (relist **)curlist; *Tail; Tail = &((*Tail)->next));
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

/**********************/
/* aclParseDomainList */
/**********************/

static void
aclParseDomainList(void *curlist)
{
    char *t = NULL;
    splayNode **Top = (splayNode **)curlist;
    while ((t = strtokFile())) {
	Tolower(t);
	*Top = splay_insert(xstrdup(t), *Top, aclDomainCompare);
    }
}

#if USE_SSL
static void
aclParseCertList(void *curlist)
{
    acl_cert_data **datap = (acl_cert_data **)curlist;
    SplayNode<char *> **Top;
    char *t;
    char *attribute = strtokFile();
    if (!attribute)
	self_destruct();
    if (*datap) {
	if (strcasecmp((*datap)->attribute, attribute) != 0)
	    self_destruct();
    } else {
	*datap = new acl_cert_data;
	(*datap)->attribute = xstrdup(attribute);
    }
    Top = &(*datap)->values;
    while ((t = strtokFile())) {
	*Top = (*Top)->insert(xstrdup(t), aclDomainCompare);
    }
}

static int
aclMatchUserCert(void *data, ACLChecklist * checklist)
{
    acl_cert_data *cert_data = (acl_cert_data *)data;
    const char *value;
    SSL *ssl = fd_table[checklist->conn()->fd].ssl;

    if (!ssl)
	return 0;
    value = sslGetUserAttribute(ssl, cert_data->attribute);
    if (!value)
	return 0;
    cert_data->values = cert_data->values->splay(const_cast<char *>(value), splaystrcmp);
    return !splayLastResult;
}

static int
aclMatchCACert(void *data, ACLChecklist * checklist)
{
    acl_cert_data *cert_data = (acl_cert_data *)data;
    const char *value;
    SSL *ssl = fd_table[checklist->conn()->fd].ssl;

    if (!ssl)
	return 0;
    value = sslGetCAAttribute(ssl, cert_data->attribute);
    if (!value)
	return 0;
    cert_data->values = cert_data->values->splay(const_cast<char *>(value), splaystrcmp);
    return !splayLastResult;
}

static void
aclDestroyCertList(void *curlist)
{
    acl_cert_data **datap = (acl_cert_data **)curlist;
    if (!*datap)
	return;
    (*datap)->values->destroy(xRefFree);
    delete *datap;
    *datap = NULL;
}

static void
aclDumpCertListWalkee(char *const&node_data, void *outlist)
{
    wordlist **wl = (wordlist **)outlist;
    wordlistAdd(wl, node_data);
}

static wordlist *
aclDumpCertList(void *curlist)
{
    acl_cert_data *data = (acl_cert_data *)curlist;
    wordlist *wl = NULL;
    wordlistAdd(&wl, data->attribute);
    data->values->walk(aclDumpCertListWalkee, &wl);
    return wl;
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
#if USE_IDENT
      case ACL_IDENT:
        result = new ACLIdent;
	break;
#endif
      case ACL_PROXY_AUTH:
        result = new ACLProxyAuth;
	break;
      case ACL_DST_DOMAIN:
      case ACL_SRC_DOMAIN:
      case ACL_DST_DOM_REGEX:
      case ACL_SRC_DOM_REGEX:
      case ACL_TIME:
      case ACL_URLPATH_REGEX:
      case ACL_URL_REGEX:
      case ACL_URL_PORT:
      case ACL_MY_PORT:
      case ACL_MAXCONN:
#if USE_IDENT
      case ACL_IDENT_REGEX:
#endif
      case ACL_PROTO:
      case ACL_METHOD:
      case ACL_BROWSER:
      case ACL_REFERER_REGEX:
      case ACL_PROXY_AUTH_REGEX:
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
      case ACL_REQ_MIME_TYPE:
      case ACL_REP_MIME_TYPE:
      case ACL_MAX_USER_IP:
      case ACL_EXTERNAL:
#if USE_SSL
      case ACL_USER_CERT:
      case ACL_CA_CERT:
#endif
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
{
}

ACL::ACL () : type(ACL_NONE)
{
}

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
    if ((A = aclFindByName(aclname)) == NULL) {
	debug(28, 3) ("aclParseAclLine: Creating ACL '%s'\n", aclname);
	A = ACL::Factory(t);
	xstrncpy(A->name, aclname, ACL_NAME_SZ);
	A->cfgline = xstrdup(config_input_line);
	new_acl = 1;
    } else {
	if (acltype != A->aclType()) {
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
    case ACL_SRC_DOMAIN:
    case ACL_DST_DOMAIN:
	aclParseDomainList(&data);
	break;
    case ACL_TIME:
	aclParseTimeSpec(&data);
	break;
    case ACL_URL_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_BROWSER:
    case ACL_REFERER_REGEX:
    case ACL_SRC_DOM_REGEX:
    case ACL_DST_DOM_REGEX:
    case ACL_REQ_MIME_TYPE:
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
#if USE_IDENT
    case ACL_IDENT_REGEX:
	aclParseRegexList(&data);
	break;
#endif
    case ACL_PROTO:
	aclParseProtoList(&data);
	break;
    case ACL_METHOD:
	aclParseMethodList(&data);
	break;
#if USE_IDENT
    case ACL_IDENT: 
#endif
    case ACL_DERIVED:
    case ACL_PROXY_AUTH:
	fatal ("unused");
	break;
    case ACL_PROXY_AUTH_REGEX:
	if (authenticateSchemeCount() == 0) {
	    debug(28, 0) ("aclParseAclLine: IGNORING: Proxy Auth ACL '%s' \
because no authentication schemes were compiled.\n", cfgline);
	} else if (authenticateActiveSchemeCount() == 0) {
	    debug(28, 0) ("aclParseAclLine: IGNORING: Proxy Auth ACL '%s' \
because no authentication schemes are fully configured.\n", cfgline);
	} else {
	    aclParseRegexList(&data);
	}
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
#if USE_SSL
    case ACL_USER_CERT:
    case ACL_CA_CERT:
	aclParseCertList(&data);
	break;
#endif
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
    if ((a = aclFindByName(name)))
	return a->isProxyAuth();
    return false;
}

bool
ACL::isProxyAuth() const
{
    return aclType() == ACL_PROXY_AUTH_REGEX;
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
    for (B = *head, T = head; B; T = &B->next, B = B->next);	/* find the tail */
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
    for (B = *head, T = head; B; T = &B->next, B = B->next);
    *T = A;
    /* We lock _acl_access structures in ACLChecklist::check() */
}

ACLList::ACLList() : op (1), _acl (NULL), next (NULL)
{
}

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
	a = aclFindByName(t);
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

/**********************/
/* aclMatchDomainList */
/**********************/

static int
aclMatchDomainList(void *dataptr, const char *host)
{
    splayNode **Top = (splayNode **)dataptr;
    if (host == NULL)
	return 0;
    debug(28, 3) ("aclMatchDomainList: checking '%s'\n", host);
    const void * __host = host;
    *Top = splay_splay(&__host, *Top, aclHostDomainCompare);
    debug(28, 3) ("aclMatchDomainList: '%s' %s\n",
	host, splayLastResult ? "NOT found" : "found");
    return !splayLastResult;
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

/*
 * we lookup an acl's cached results, and if we cannot find the acl being 
 * checked we check it and cache the result. This function is deliberatly 
 * generic to support caching of multiple acl types (but it needs to be more
 * generic still....
 * The Match Param and the cache MUST be tied together by the calling routine.
 * You have been warned :-]
 * Also only Matchxxx that are of the form (void *, void *) can be used.
 * probably some ugly overloading _could_ be done but I'll leave that as an
 * exercise for the reader. Note that caching of time based acl's is not
 * wise due to no expiry occuring to the cache entries until the user expires
 * or a reconfigure takes place. 
 * RBC
 */
static int
aclCacheMatchAcl(dlink_list * cache, squid_acl acltype, void *data,
    char const *MatchParam)
{
    int matchrv;
    acl_proxy_auth_match_cache *auth_match;
    dlink_node *link;
    link = cache->head;
    while (link) {
	auth_match = (acl_proxy_auth_match_cache *)link->data;
	if (auth_match->acl_data == data) {
	    debug(28, 4) ("aclCacheMatchAcl: cache hit on acl '%p'\n", data);
	    return auth_match->matchrv;
	}
	link = link->next;
    }
    auth_match = NULL;
    /* match the user in the acl. They are not cached. */
    switch (acltype) {
    case ACL_PROXY_AUTH:
	matchrv = ((ACLUserData *)data)->match(MatchParam);
	break;
    case ACL_PROXY_AUTH_REGEX:
	matchrv = aclMatchRegex((relist *)data, MatchParam);
	break;
    default:
	/* This is a fatal to ensure that aclCacheMatchAcl calls are _only_
	 * made for supported acl types */
	fatal("aclCacheMatchAcl: unknown or unexpected ACL type");
	return 0;		/* NOTREACHED */
    }
    auth_match = (acl_proxy_auth_match_cache *)memAllocate(MEM_ACL_PROXY_AUTH_MATCH);
    auth_match->matchrv = matchrv;
    auth_match->acl_data = data;
    dlinkAddTail(auth_match, &auth_match->link, cache);
    return matchrv;
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

/* aclMatchProxyAuth can return two exit codes:
 * 0 : Authorisation for this ACL failed. (Did not match)
 * 1 : Authorisation OK. (Matched)
 */
int
aclMatchProxyAuth(void *data, auth_user_request_t * auth_user_request,
    ACLChecklist * checklist, squid_acl acltype)
{
    /* checklist is used to register user name when identified, nothing else */
    /* General program flow in proxy_auth acls
     * 1. Consistency checks: are we getting sensible data
     * 2. Call the authenticate* functions to establish a authenticated user
     * 4. look up the username in acltype (and cache the result against the 
     *     username
     */

    /* for completeness */
    authenticateAuthUserRequestLock(auth_user_request);

    /* consistent parameters ? */
    assert(authenticateUserAuthenticated(auth_user_request));
    /* this ACL check completed */
    authenticateAuthUserRequestUnlock(auth_user_request);
    /* check to see if we have matched the user-acl before */
    return aclCacheMatchAcl(&auth_user_request->auth_user->
	proxy_match_cache, acltype, data,
	authenticateUserRequestUsername(auth_user_request));
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
    if (acldata->flags.strict) {
	/* 
	 * simply deny access - the user name is already associated with
	 * the request 
	 */
	/* remove _this_ ip, as it is the culprit for going over the limit */
	authenticateAuthUserRequestRemoveIp(auth_user_request, src_addr);
	debug(28, 4) ("aclMatchUserMaxIP: Denying access in strict mode\n");
    } else {
	/* 
	 * non-strict - remove some/all of the cached entries 
	 * ie to allow the user to move machines easily
	 */
	authenticateAuthUserRequestClearIp(auth_user_request);
	debug(28, 4) ("aclMatchUserMaxIP: Denying access in non-strict mode - flushing the user ip cache\n");
    }

    return 1;
}

static void
aclLookupProxyAuthStart(ACLChecklist * checklist)
{
    auth_user_request_t *auth_user_request;
    /* make sure someone created auth_user_request for us */
    assert(checklist->auth_user_request != NULL);
    auth_user_request = checklist->auth_user_request;

    assert(authenticateValidateUser(auth_user_request));
    authenticateStart(auth_user_request, aclLookupProxyAuthDone, checklist);
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

static int
aclMatchTime(acl_time_data * data, time_t when)
{
    static time_t last_when = 0;
    static struct tm tm;
    time_t t;
    assert(data != NULL);
    if (when != last_when) {
	last_when = when;
	xmemcpy(&tm, localtime(&when), sizeof(struct tm));
    }
    t = (time_t) (tm.tm_hour * 60 + tm.tm_min);
    debug(28, 3) ("aclMatchTime: checking %d in %d-%d, weekbits=%x\n",
	(int) t, (int) data->start, (int) data->stop, data->weekbits);

    while (data) {
	if (t >= data->start && t <= data->stop && (data->weekbits & (1 << tm.tm_wday)))
	    return 1;
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

int
aclAuthenticated(ACLChecklist * checklist)
{
    request_t *r = checklist->request;
    http_hdr_type headertype;
    if (NULL == r) {
	return -1;
    } else if (!r->flags.accelerated) {
	/* Proxy authorization on proxy requests */
	headertype = HDR_PROXY_AUTHORIZATION;
    } else if (r->flags.internal) {
	/* WWW authorization on accelerated internal requests */
	headertype = HDR_AUTHORIZATION;
    } else {
#if AUTH_ON_ACCELERATION
	/* WWW authorization on accelerated requests */
	headertype = HDR_AUTHORIZATION;
#else
	debug(28, 1) ("aclAuthenticated: authentication not applicable on accelerated requests.\n");
	return -1;
#endif
    }
    /* get authed here */
    /* Note: this fills in checklist->auth_user_request when applicable */
    switch (authenticateTryToAuthenticateAndSetAuthUser(&checklist->auth_user_request, headertype, checklist->request, checklist->conn(), checklist->src_addr)) {
    case AUTH_ACL_CANNOT_AUTHENTICATE:
	debug(28, 4) ("aclMatchAcl: returning  0 user authenticated but not authorised.\n");
	return 0;
    case AUTH_AUTHENTICATED:
	return 1;
	break;
    case AUTH_ACL_HELPER:
	debug(28, 4) ("aclMatchAcl: returning 0 sending credentials to helper.\n");
	checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_NEEDED;
	return 0;
    case AUTH_ACL_CHALLENGE:
	debug(28, 4) ("aclMatchAcl: returning 0 sending authentication challenge.\n");
	checklist->state[ACL_PROXY_AUTH] = ACL_PROXY_AUTH_NEEDED;
	return 0;
    default:
	fatal("unexpected authenticateAuthenticate reply\n");
	return -1;
    }
}

bool
ACL::requiresRequest() const
{
    switch (aclType()) {
    case ACL_BROWSER:
    case ACL_REFERER_REGEX:
    case ACL_DST_ASN:
    case ACL_DST_DOMAIN:
    case ACL_DST_DOM_REGEX:
    case ACL_MAX_USER_IP:
    case ACL_METHOD:
    case ACL_PROTO:
    case ACL_PROXY_AUTH:
    case ACL_PROXY_AUTH_REGEX:
    case ACL_REP_MIME_TYPE:
    case ACL_REQ_MIME_TYPE:
    case ACL_URLPATH_REGEX:
    case ACL_URL_PORT:
    case ACL_URL_REGEX:
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
    const char *fqdn = NULL;
    char *esc_buf;
    const char *header;
    const char *browser;
    int k, ti;

    switch (aclType()) {
    case ACL_DST_DOMAIN:
	if ((ia = ipcacheCheckNumeric(r->host)) == NULL)
	    return aclMatchDomainList(&data, r->host);
	fqdn = fqdncache_gethostbyaddr(ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
	if (fqdn)
	    return aclMatchDomainList(&data, fqdn);
	if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		name, inet_ntoa(ia->in_addrs[0]));
	    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchDomainList(&data, "none");
	/* NOTREACHED */
    case ACL_SRC_DOMAIN:
	fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);
	if (fqdn) {
	    return aclMatchDomainList(&data, fqdn);
	} else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		name, inet_ntoa(checklist->src_addr));
	    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchDomainList(&data, "none");
	/* NOTREACHED */
    case ACL_DST_DOM_REGEX:
	if ((ia = ipcacheCheckNumeric(r->host)) == NULL)
	    return aclMatchRegex((relist *)data, r->host);
	fqdn = fqdncache_gethostbyaddr(ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
	if (fqdn)
	    return aclMatchRegex((relist *)data, fqdn);
	if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		name, inet_ntoa(ia->in_addrs[0]));
	    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchRegex((relist *)data, "none");
	/* NOTREACHED */
    case ACL_SRC_DOM_REGEX:
	fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);
	if (fqdn) {
	    return aclMatchRegex((relist *)data, fqdn);
	} else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		name, inet_ntoa(checklist->src_addr));
	    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchRegex((relist *)data, "none");
	/* NOTREACHED */
    case ACL_TIME:
	return aclMatchTime((acl_time_data *)data, squid_curtime);
	/* NOTREACHED */
    case ACL_URLPATH_REGEX:
	esc_buf = xstrdup(r->urlpath.buf());
	rfc1738_unescape(esc_buf);
	k = aclMatchRegex((relist *)data, esc_buf);
	safe_free(esc_buf);
	return k;
	/* NOTREACHED */
    case ACL_URL_REGEX:
	esc_buf = xstrdup(urlCanonical(r));
	rfc1738_unescape(esc_buf);
	k = aclMatchRegex((relist *)data, esc_buf);
	safe_free(esc_buf);
	return k;
	/* NOTREACHED */
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
#if USE_IDENT
    case ACL_IDENT_REGEX:
	if (checklist->rfc931[0]) {
	    return aclMatchRegex((relist *)data, checklist->rfc931);
	} else {
	    checklist->state[ACL_IDENT] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	/* NOTREACHED */
#endif
    case ACL_PROTO:
	return aclMatchInteger((intlist *)data, r->protocol);
	/* NOTREACHED */
    case ACL_METHOD:
	return aclMatchInteger((intlist *)data, r->method);
	/* NOTREACHED */
    case ACL_BROWSER:
	browser = httpHeaderGetStr(&checklist->request->header, HDR_USER_AGENT);
	if (NULL == browser)
	    return 0;
	return aclMatchRegex((relist *)data, browser);
	/* NOTREACHED */
    case ACL_REFERER_REGEX:
	header = httpHeaderGetStr(&checklist->request->header, HDR_REFERER);
	if (NULL == header)
	    return 0;
	return aclMatchRegex((relist *)data, header);
	/* NOTREACHED */
    case ACL_PROXY_AUTH_REGEX:
	if ((ti = aclAuthenticated(checklist)) != 1)
	    return ti;
	ti = aclMatchProxyAuth(data, checklist->auth_user_request,
	    checklist, aclType());
	checklist->auth_user_request = NULL;
	return ti;
	/* NOTREACHED */
    case ACL_MAX_USER_IP:
	if ((ti = aclAuthenticated(checklist)) != 1)
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
	    checklist->state[ACL_DST_ASN] = ACL_LOOKUP_NEEDED;
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
    case ACL_REQ_MIME_TYPE:
	header = httpHeaderGetStr(&checklist->request->header,
	    HDR_CONTENT_TYPE);
	if (NULL == header)
	    header = "";
	return aclMatchRegex((relist *)data, header);
	/* NOTREACHED */
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
#if USE_SSL
    case ACL_USER_CERT:
	return aclMatchUserCert(data, checklist);
	/* NOTREACHED */
    case ACL_CA_CERT:
	return aclMatchCACert(data, checklist);
	/* NOTREACHED */
#endif
    case ACL_NONE:
    case ACL_ENUM_MAX:
	break;
#if USE_IDENT
    case ACL_IDENT:
#endif
    case ACL_DERIVED:
    case ACL_PROXY_AUTH:
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

int
ACLChecklist::matchAclList(const acl_list * head)
{
    PROF_start(aclMatchAclList);
    const acl_list *node = head;
    while (node) {
	if (!node->matches(this)) {
	    debug(28, 3) ("aclmatchAclList: returning 0 (AND list entry failed to match)\n");
	    PROF_stop(aclMatchAclList);
	    return 0;
	}
	node = node->next;
    }
    debug(28, 3) ("aclmatchAclList: returning 1 (AND list satisfied)\n");
    PROF_stop(aclMatchAclList);
    return 1;
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
	if (checklist->matchAclList(A->aclList)) {
	    PROF_stop(aclCheckFast);
	    return allow == ACCESS_ALLOWED;
	}
	A = A->next;
    }
    debug(28, 5) ("aclCheckFast: no matches, returning: %d\n", allow == ACCESS_DENIED);
    PROF_stop(aclCheckFast);
    return allow == ACCESS_DENIED;
}

allow_t const &
ACLChecklist::currentAnswer() const
{
    return allow_;
}

void
ACLChecklist::currentAnswer(allow_t const newAnswer)
{
    allow_ = newAnswer;
}
    
void
ACLChecklist::check()
{
    /* deny if no rules present */
    currentAnswer(ACCESS_DENIED);
    /* NOTE: This holds a cbdata reference to the current access_list
     * entry, not the whole list.
     */
    while (accessList != NULL) {
	/*
	 * If the _acl_access is no longer valid (i.e. its been
	 * freed because of a reconfigure), then bail on this
	 * access check.  For now, return ACCESS_DENIED.
	 */
	if (!cbdataReferenceValid(accessList)) {
	    cbdataReferenceDone(accessList);
	    break;
	}

	checkAccessList();
	if (asyncInProgress())
	    return;

	if (finished()) {
	    /*
	     * We are done.  Either the request
	     * is allowed, denied, requires authentication.
	     */
	    debug(28, 3) ("ACLChecklist::check: match found, returning %d\n", currentAnswer());
	    cbdataReferenceDone(accessList); /* A */
	    checkCallback(currentAnswer());
	    /* From here on in, this may be invalid */
	    return;
	}
	/*
	 * Reference the next access entry
	 */
	const acl_access *A = accessList;
	accessList = cbdataReference(accessList->next);
	cbdataReferenceDone(A);
    }
    /* dropped off the end of the list */
    debug(28, 3) ("ACLChecklist::check: NO match found, returning %d\n", 
		  currentAnswer() != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED);
    checkCallback(currentAnswer() != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED);
}

bool
ACLChecklist::asyncInProgress() const
{
    return async_;
}

void
ACLChecklist::asyncInProgress(bool const newAsync)
{
    assert (!finished());
    async_ = newAsync;
    debug (28,3)("ACLChecklist::asyncInProgress: async set to %d\n",async_);
}

bool
ACLChecklist::finished() const
{
    return finished_;
}

void
ACLChecklist::markFinished()
{
    assert (!finished());
    finished_ = true;
    debug (28,3)("checklist processing finished\n");
}

void
ACLChecklist::checkAccessList()
{
    debug(28, 3) ("ACLChecklist::checkAccessList: checking '%s'\n", accessList->cfgline);
    /* what is our result on a match? */
    currentAnswer(accessList->allow);
    /* does the current AND clause match */
    int match = matchAclList(accessList->aclList);
    if (match)
	markFinished();
    /* Should be else, but keep the exact same flow as before */
    checkForAsync();
}

void
ACLChecklist::checkForAsync()
{
    /* TODO: introduce a state object, with states:
     * synccheck -- null op
     * asyncneeded -- async lookup needed
     * finished -- answer set.
     */
    /* check for async lookups needed. */
    if (asyncState() != NullState::Instance()) {
	/* If a state object is here, use it.
	 * When all cases are converted, the if goes away and it
	 * becomes unconditional.
	 * RBC 02 2003
	 */
	asyncState()->checkForAsync(this);
    } else if (state[ACL_DST_ASN] == ACL_LOOKUP_NEEDED) {
	state[ACL_DST_ASN] = ACL_LOOKUP_PENDING;
	ipcache_nbgethostbyname(request->host,
				aclLookupDstIPforASNDone, this);
    } else if (state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NEEDED) {
	state[ACL_SRC_DOMAIN] = ACL_LOOKUP_PENDING;
	fqdncache_nbgethostbyaddr(src_addr,
				  aclLookupSrcFQDNDone, this);
    } else if (state[ACL_DST_DOMAIN] == ACL_LOOKUP_NEEDED) {
	ipcache_addrs *ia;
	ia = ipcacheCheckNumeric(request->host);
	if (ia == NULL) {
	    state[ACL_DST_DOMAIN] = ACL_LOOKUP_DONE;
	} else {
	    dst_addr = ia->in_addrs[0];
	    state[ACL_DST_DOMAIN] = ACL_LOOKUP_PENDING;
	    fqdncache_nbgethostbyaddr(dst_addr,
				      aclLookupDstFQDNDone, this);
	}
    } else if (state[ACL_PROXY_AUTH] == ACL_LOOKUP_NEEDED) {
	debug(28, 3)
	  ("ACLChecklist::checkForAsync: checking password via authenticator\n");
	aclLookupProxyAuthStart(this);
	state[ACL_PROXY_AUTH] = ACL_LOOKUP_PENDING;
    } else if (state[ACL_PROXY_AUTH] == ACL_PROXY_AUTH_NEEDED) {
	/* Client is required to resend the request with correct authentication
	 * credentials. (This may be part of a stateful auth protocol.
	 * The request is denied.
	 */
	debug(28, 6) ("ACLChecklist::checkForAsync: requiring Proxy Auth header.\n");
	currentAnswer(ACCESS_REQ_PROXY_AUTH);
	markFinished();
	return;
#if USE_IDENT
    } else if (state[ACL_IDENT] == ACL_LOOKUP_NEEDED) {
	debug(28, 3) ("ACLChecklist::checkForAsync: Doing ident lookup\n");
	if (conn() && cbdataReferenceValid(conn())) {
	    identStart(&conn()->me, &conn()->peer,
		       aclLookupIdentDone, this);
	    state[ACL_IDENT] = ACL_LOOKUP_PENDING;
	} else {
	    debug(28, 1) ("ACLChecklist::checkForAsync: Can't start ident lookup. No client connection\n");
	    currentAnswer(ACCESS_DENIED);
	    markFinished();
	    return;
	}
#endif
    } else if (state[ACL_EXTERNAL] == ACL_LOOKUP_NEEDED) {
	acl *acl = aclFindByName(AclMatchedName);
	assert (acl->aclType() == ACL_EXTERNAL);
	acl->startExternal(this);
    } else {
	return;
    }
    asyncInProgress(true);
}

void
ACL::startExternal(ACLChecklist *checklist)
{
    externalAclLookup(checklist, data, aclLookupExternalDone, checklist);
}

void
ACLChecklist::checkCallback(allow_t answer)
{
    PF *callback_;
    void *cbdata_;
    debug(28, 3) ("ACLChecklist::checkCallback: answer=%d\n", answer);
    /* During reconfigure, we can end up not finishing call
     * sequences into the auth code */
    if (auth_user_request) {
	/* the checklist lock */
	authenticateAuthUserRequestUnlock(auth_user_request);
	/* it might have been connection based */
	assert(conn());
	conn()->auth_user_request = NULL;
	conn()->auth_type = AUTH_BROKEN;
	auth_user_request = NULL;
    }
    callback_ = callback;
    callback = NULL;
    if (cbdataReferenceValidDone(callback_data, &cbdata_))
	callback_(answer, cbdata_);
    delete this;
}

#if USE_IDENT
static void
aclLookupIdentDone(const char *ident, void *data)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    if (ident) {
	xstrncpy(checklist->rfc931, ident, USER_IDENT_SZ);
#if DONT
	xstrncpy(checklist->request->authuser, ident, USER_IDENT_SZ);
#endif
    } else {
	xstrncpy(checklist->rfc931, dash_str, USER_IDENT_SZ);
    }
    /*
     * Cache the ident result in the connection, to avoid redoing ident lookup
     * over and over on persistent connections
     */
    if (cbdataReferenceValid(checklist->conn()) && !checklist->conn()->rfc931[0])
	xstrncpy(checklist->conn()->rfc931, checklist->rfc931, USER_IDENT_SZ);
    checklist->asyncInProgress(false);
    checklist->check();
}
#endif

static void
aclLookupDstIPforASNDone(const ipcache_addrs * ia, void *data)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    checklist->state[ACL_DST_ASN] = ACL_LOOKUP_DONE;
    checklist->asyncInProgress(false);
    checklist->check();
}

static void
aclLookupSrcFQDNDone(const char *fqdn, void *data)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_DONE;
    checklist->asyncInProgress(false);
    checklist->check();
}

static void
aclLookupDstFQDNDone(const char *fqdn, void *data)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_DONE;
    checklist->asyncInProgress(false);
    checklist->check();
}

static void
aclLookupProxyAuthDone(void *data, char *result)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_DONE;
    if (result != NULL)
	fatal("AclLookupProxyAuthDone: Old code floating around somewhere.\nMake clean and if that doesn't work, report a bug to the squid developers.\n");
    if (!authenticateValidateUser(checklist->auth_user_request) || checklist->conn() == NULL) {
	/* credentials could not be checked either way
	 * restart the whole process */
	/* OR the connection was closed, there's no way to continue */
	authenticateAuthUserRequestUnlock(checklist->auth_user_request);
	if (checklist->conn()) {
	    checklist->conn()->auth_user_request = NULL;
	    checklist->conn()->auth_type = AUTH_BROKEN;
	}
	checklist->auth_user_request = NULL;
    }
    checklist->asyncInProgress(false);
    checklist->check();
}

static void
aclLookupExternalDone(void *data, void *result)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    checklist->state[ACL_EXTERNAL] = ACL_LOOKUP_DONE;
    checklist->extacl_entry = cbdataReference((external_acl_entry *)result);
    checklist->asyncInProgress(false);
    checklist->check();
}

CBDATA_CLASS_INIT(ACLChecklist);

void *
ACLChecklist::operator new (size_t size)
{
    assert (size == sizeof(ACLChecklist));
    CBDATA_INIT_TYPE(ACLChecklist);
    ACLChecklist *result = cbdataAlloc(ACLChecklist);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    return result;
}
 
void
ACLChecklist::operator delete (void *address)
{
    ACLChecklist *t = static_cast<ACLChecklist *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}

void
ACLChecklist::deleteSelf() const
{
    delete this;
}

ACLChecklist::ACLChecklist() : accessList (NULL), my_port (0), request (NULL),
  reply (NULL),
  auth_user_request (NULL)
#if SQUID_SNMP
    ,snmp_community(NULL)
#endif
  , callback (NULL),
  callback_data (NULL),
  extacl_entry (NULL),
  conn_(NULL),
  async_(false),
  finished_(false),
  allow_(ACCESS_DENIED),
  state_(NullState::Instance())
{
    memset (&src_addr, '\0', sizeof (struct in_addr));
    memset (&dst_addr, '\0', sizeof (struct in_addr));
    memset (&my_addr, '\0', sizeof (struct in_addr));
    rfc931[0] = '\0';
    memset (&state, '\0', sizeof (state));
}

ACLChecklist::~ACLChecklist()
{
    assert (!asyncInProgress());
    if (extacl_entry)
	cbdataReferenceDone(extacl_entry);
    if (request)
	requestUnlink(request);
    request = NULL;
    cbdataReferenceDone(conn_);
    cbdataReferenceDone(accessList);
}

ConnStateData *
ACLChecklist::conn()
{
    return  conn_;
}

void
ACLChecklist::conn(ConnStateData *aConn)
{
    assert (conn() == NULL);
    conn_ = aConn;
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

void
aclNBCheck(ACLChecklist * checklist, PF * callback, void *callback_data)
{
    checklist->callback = callback;
    checklist->callback_data = cbdataReference(callback_data);
    checklist->check();
}

/*********************/
/* Destroy functions */
/*********************/

static void
aclDestroyTimeList(acl_time_data * data)
{
    acl_time_data *next = NULL;
    for (; data; data = next) {
	next = data->next;
	memFree(data, MEM_ACL_TIME_DATA);
    }
}

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
	case ACL_DST_DOMAIN:
	case ACL_SRC_DOMAIN:
	    splay_destroy((splayNode *)data, xRefFree);
	    break;
#if SQUID_SNMP
	case ACL_SNMP_COMMUNITY:
	    wordlistDestroy((wordlist **) & data);
	    break;
#endif
	/* Destroyed in the children */
#if USE_IDENT
	case ACL_IDENT:
#endif
	case ACL_DERIVED:
	case ACL_PROXY_AUTH:
	    break;
	case ACL_TIME:
	    aclDestroyTimeList((acl_time_data *)data);
	    break;
#if USE_IDENT
	case ACL_IDENT_REGEX:
#endif
	case ACL_PROXY_AUTH_REGEX:
	case ACL_URL_REGEX:
	case ACL_URLPATH_REGEX:
	case ACL_BROWSER:
	case ACL_REFERER_REGEX:
	case ACL_SRC_DOM_REGEX:
	case ACL_DST_DOM_REGEX:
	case ACL_REP_MIME_TYPE:
	case ACL_REQ_MIME_TYPE:
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
#if USE_SSL
	case ACL_USER_CERT:
	case ACL_CA_CERT:
	    aclDestroyCertList(&data);
	    break;
#endif
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

/* general compare functions, these are used for tree search algorithms
 * so they return <0, 0 or >0 */

/* compare two domains */

template<class T>
int
aclDomainCompare(T const &a, T const &b)
{
    char * const d1 = (char *const)b;
    char * const d2 = (char *const )a;
    int ret;
    ret = aclHostDomainCompare(d1, d2);
    if (ret != 0) {
	char *const d3 = d2;
	char *const d4 = d1;
	ret = aclHostDomainCompare(d3, d4);
    }
    /* FIXME this warning may display d1 and d2 when it should display d3 and d4 */
    if (ret == 0) {
	debug(28, 0) ("WARNING: '%s' is a subdomain of '%s'\n", d1, d2);
	debug(28, 0) ("WARNING: because of this '%s' is ignored to keep splay tree searching predictable\n", (char *) a);
	debug(28, 0) ("WARNING: You should probably remove '%s' from the ACL named '%s'\n", d1, AclMatchedName);
    }
    return ret;
}

/* compare a host and a domain */

static int
aclHostDomainCompare( void *const &a, void * const &b)
{
    const char *h = (const char *)a;
    const char *d = (const char *)b;
    return matchDomainName(h, d);
}

static void
aclDumpDomainListWalkee(void * const &node, void *state)
{
    char *domain = (char *)node;
    wordlistAdd((wordlist **)state, domain);
}

static wordlist *
aclDumpDomainList(void *data)
{
    wordlist *w = NULL;
    splay_walk((splayNode *)data, aclDumpDomainListWalkee, &w);
    return w;
}

static wordlist *
aclDumpTimeSpecList(acl_time_data * t)
{
    wordlist *W = NULL;
    char buf[128];
    while (t != NULL) {
	snprintf(buf, sizeof(buf), "%c%c%c%c%c%c%c %02d:%02d-%02d:%02d",
	    t->weekbits & ACL_SUNDAY ? 'S' : '-',
	    t->weekbits & ACL_MONDAY ? 'M' : '-',
	    t->weekbits & ACL_TUESDAY ? 'T' : '-',
	    t->weekbits & ACL_WEDNESDAY ? 'W' : '-',
	    t->weekbits & ACL_THURSDAY ? 'H' : '-',
	    t->weekbits & ACL_FRIDAY ? 'F' : '-',
	    t->weekbits & ACL_SATURDAY ? 'A' : '-',
	    t->start / 60, t->start % 60, t->stop / 60, t->stop % 60);
	wordlistAdd(&W, buf);
	t = t->next;
    }
    return W;
}

static wordlist *
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
    case ACL_SRC_DOMAIN:
    case ACL_DST_DOMAIN:
	return aclDumpDomainList(data);
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
	return wordlistDup((wordlist *)data);
#endif
#if USE_IDENT
    case ACL_IDENT_REGEX:
	return aclDumpRegexList((relist *)data);
#endif
#if USE_IDENT
    case ACL_IDENT:
#endif
    case ACL_DERIVED:
    case ACL_PROXY_AUTH:
	fatal ("unused");
    case ACL_TIME:
	return aclDumpTimeSpecList((acl_time_data *)data);
    case ACL_PROXY_AUTH_REGEX:
    case ACL_URL_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_BROWSER:
    case ACL_REFERER_REGEX:
    case ACL_SRC_DOM_REGEX:
    case ACL_DST_DOM_REGEX:
    case ACL_REQ_MIME_TYPE:
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
#if USE_SSL
    case ACL_USER_CERT:
    case ACL_CA_CERT:
	return aclDumpCertList(data);
#endif
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
    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) != -1) {
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
    if (ioctl(HttpSockets[0], SIOCGIFCONF, &ifc) < 0) {
	debug(28, 1) ("Attempt to retrieve interface list failed: %s\n",
	    xstrerror());
	return 0;
    }
    if (ifc.ifc_len > (int)sizeof(ifbuffer)) {
	debug(28, 1) ("Interface list too long - %d\n", ifc.ifc_len);
	return 0;
    }
    /* Attempt ARP lookup on each interface */
    offset = 0;
    while (offset < ifc.ifc_len) {
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
    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) != -1) {
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

#if USE_SSL
MemPool *acl_cert_data::Pool(NULL);
void *
acl_cert_data::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (acl_cert_data));
    if (!Pool)
	Pool = memPoolCreate("acl_cert_data", sizeof (acl_cert_data));
    return memPoolAlloc(Pool);
}

void
acl_cert_data::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
acl_cert_data::deleteSelf() const
{
    delete this;
}
#endif /* USE_SSL */

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

void
ACLChecklist::AsyncState::changeState (ACLChecklist *checklist, AsyncState *newState) const
{
    checklist->changeState(newState);
}

ACLChecklist::NullState *
ACLChecklist::NullState::Instance()
{
    return &_instance;
}

void
ACLChecklist::NullState::checkForAsync(ACLChecklist *) const
{
}

ACLChecklist::NullState ACLChecklist::NullState::_instance;

void
ACLChecklist::changeState (AsyncState *newState)
{
    /* only change from null to active and back again,
     * not active to active.
     * relax this once conversion to states is complete
     * RBC 02 2003
     */
    assert (state_ == NullState::Instance() || newState == NullState::Instance());
    state_ = newState;
}

ACLChecklist::AsyncState *
ACLChecklist::asyncState() const
{
    return state_;
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
