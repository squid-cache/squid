
/*
 * $Id: acl.cc,v 1.197 1999/01/29 21:28:06 wessels Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
#include "splay.h"

static int aclFromFile = 0;
static FILE *aclFile;
static hash_table *proxy_auth_cache = NULL;

static void aclParseDomainList(void *curlist);
static void aclParseIpList(void *curlist);
static void aclParseIntlist(void *curlist);
static void aclParseWordList(void *curlist);
static void aclParseProtoList(void *curlist);
static void aclParseMethodList(void *curlist);
static void aclParseTimeSpec(void *curlist);
static void aclParseIntRange(void *curlist);
static char *strtokFile(void);
static void aclDestroyAclList(acl_list * list);
static void aclDestroyTimeList(acl_time_data * data);
static void aclDestroyIntRange(intrange *);
static FREE aclFreeProxyAuthUser;
static struct _acl *aclFindByName(const char *name);
static int aclMatchAcl(struct _acl *, aclCheck_t *);
static int aclMatchIntegerRange(intrange * data, int i);
static int aclMatchTime(acl_time_data * data, time_t when);
static int aclMatchUser(wordlist * data, const char *ident);
static int aclMatchIp(void *dataptr, struct in_addr c);
static int aclMatchDomainList(void *dataptr, const char *);
static int aclMatchIntegerRange(intrange * data, int i);
#if SQUID_SNMP
static int aclMatchWordList(wordlist *, const char *);
#endif
static squid_acl aclStrToType(const char *s);
static int decode_addr(const char *, struct in_addr *, struct in_addr *);
static void aclCheck(aclCheck_t * checklist);
static void aclCheckCallback(aclCheck_t * checklist, allow_t answer);
#if USE_IDENT
static IDCB aclLookupIdentDone;
#endif
static IPH aclLookupDstIPDone;
static IPH aclLookupDstIPforASNDone;
static FQDNH aclLookupSrcFQDNDone;
static FQDNH aclLookupDstFQDNDone;
static void aclLookupProxyAuthStart(aclCheck_t * checklist);
static void aclLookupProxyAuthDone(void *data, char *result);
static wordlist *aclDumpIpList(void *);
static wordlist *aclDumpDomainList(void *data);
static wordlist *aclDumpTimeSpecList(acl_time_data *);
static wordlist *aclDumpRegexList(relist * data);
static wordlist *aclDumpIntlistList(intlist * data);
static wordlist *aclDumpIntRangeList(intrange * data);
static wordlist *aclDumpProtoList(intlist * data);
static wordlist *aclDumpMethodList(intlist * data);
static SPLAYCMP aclIpNetworkCompare;
static SPLAYCMP aclHostDomainCompare;
static SPLAYCMP aclDomainCompare;
static SPLAYWALKEE aclDumpIpListWalkee;
static SPLAYWALKEE aclDumpDomainListWalkee;
static SPLAYFREE aclFreeIpData;

#if USE_ARP_ACL
static void aclParseArpList(void *curlist);
static int decode_eth(const char *asc, char *eth);
static int aclMatchArp(void *dataptr, struct in_addr c);
static wordlist *aclDumpArpList(void *);
static SPLAYCMP aclArpCompare;
static SPLAYWALKEE aclDumpArpListWalkee;
#endif

static char *
strtokFile(void)
{
    char *t, *fn;
    LOCAL_ARRAY(char, buf, 256);

  strtok_again:
    if (!aclFromFile) {
	t = (strtok(NULL, w_space));
	if (t && (*t == '\"' || *t == '\'')) {
	    /* quote found, start reading from file */
	    fn = ++t;
	    while (*t && *t != '\"' && *t != '\'')
		t++;
	    *t = '\0';
	    if ((aclFile = fopen(fn, "r")) == NULL) {
		debug(28, 0) ("strtokFile: %s not found\n", fn);
		return (NULL);
	    }
	    aclFromFile = 1;
	} else {
	    return t;
	}
    }
    /* aclFromFile */
    if (fgets(buf, 256, aclFile) == NULL) {
	/* stop reading from file */
	fclose(aclFile);
	aclFromFile = 0;
	goto strtok_again;
    } else {
	t = buf;
	/* skip leading and trailing white space */
	t += strspn(buf, w_space);
	t[strcspn(t, w_space)] = '\0';
	/* skip comments */
	if (*t == '#')
	    goto strtok_again;
	/* skip blank lines */
	if (!*t)
	    goto strtok_again;
	return t;
    }
}

static squid_acl
aclStrToType(const char *s)
{
    if (!strcmp(s, "src"))
	return ACL_SRC_IP;
    if (!strcmp(s, "dst"))
	return ACL_DST_IP;
    if (!strcmp(s, "myip"))
	return ACL_MY_IP;
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
#if USE_IDENT
    if (!strcmp(s, "ident"))
	return ACL_IDENT;
#endif
    if (!strncmp(s, "proto", 5))
	return ACL_PROTO;
    if (!strcmp(s, "method"))
	return ACL_METHOD;
    if (!strcmp(s, "browser"))
	return ACL_BROWSER;
    if (!strcmp(s, "proxy_auth"))
	return ACL_PROXY_AUTH;
    if (!strcmp(s, "src_as"))
	return ACL_SRC_ASN;
    if (!strcmp(s, "dst_as"))
	return ACL_DST_ASN;
#if SQUID_SNMP
    if (!strcmp(s, "snmp_community"))
	return ACL_SNMP_COMMUNITY;
#endif
    if (!strcmp(s, "src_rtt"))
	return ACL_NETDB_SRC_RTT;
#if USE_ARP_ACL
    if (!strcmp(s, "arp"))
	return ACL_SRC_ARP;
#endif
    return ACL_NONE;
}

const char *
aclTypeToStr(squid_acl type)
{
    if (type == ACL_SRC_IP)
	return "src";
    if (type == ACL_DST_IP)
	return "dst";
    if (type == ACL_MY_IP)
	return "myip";
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
#if USE_IDENT
    if (type == ACL_IDENT)
	return "ident";
#endif
    if (type == ACL_PROTO)
	return "proto";
    if (type == ACL_METHOD)
	return "method";
    if (type == ACL_BROWSER)
	return "browser";
    if (type == ACL_PROXY_AUTH)
	return "proxy_auth";
    if (type == ACL_SRC_ASN)
	return "src_as";
    if (type == ACL_DST_ASN)
	return "dst_as";
#if SQUID_SNMP
    if (type == ACL_SNMP_COMMUNITY)
	return "snmp_community";
#endif
    if (type == ACL_NETDB_SRC_RTT)
	return "src_rtt";
#if USE_ARP_ACL
    if (type == ACL_SRC_ARP)
	return "arp";
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
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	q = memAllocate(MEM_INTLIST);
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
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	q = xcalloc(1, sizeof(intrange));
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
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	q = memAllocate(MEM_INTLIST);
	q->i = (int) urlParseProtocol(t);
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
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	q = memAllocate(MEM_INTLIST);
	q->i = (int) urlParseMethod(t);
	if (q->i == METHOD_PURGE)
	    Config.onoff.enable_purge = 1;
	*(Tail) = q;
	Tail = &q->next;
    }
}

/*
 * Decode a ascii representation (asc) of a IP adress, and place
 * adress and netmask information in addr and mask.
 * This function should NOT be called if 'asc' is a hostname!
 */
static int
decode_addr(const char *asc, struct in_addr *addr, struct in_addr *mask)
{
    u_num32 a;
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0;

    switch (sscanf(asc, "%d.%d.%d.%d", &a1, &a2, &a3, &a4)) {
    case 4:			/* a dotted quad */
	if (!safe_inet_addr(asc, addr)) {
	    debug(28, 0) ("decode_addr: unsafe IP address: '%s'\n", asc);
	    fatal("decode_addr: unsafe IP address");
	}
	break;
    case 1:			/* a significant bits value for a mask */
	if (a1 >= 0 && a1 < 33) {
	    addr->s_addr = a1 ? htonl(0xfffffffful << (32 - a1)) : 0;
	    break;
	}
    default:
	debug(28, 0) ("decode_addr: Invalid IP address '%s'\n", asc);
	return 0;		/* This is not valid address */
    }

    if (mask != NULL) {		/* mask == NULL if called to decode a netmask */

	/* Guess netmask */
	a = (u_num32) ntohl(addr->s_addr);
	if (!(a & 0xFFFFFFFFul))
	    mask->s_addr = htonl(0x00000000ul);
	else if (!(a & 0x00FFFFFF))
	    mask->s_addr = htonl(0xFF000000ul);
	else if (!(a & 0x0000FFFF))
	    mask->s_addr = htonl(0xFFFF0000ul);
	else if (!(a & 0x000000FF))
	    mask->s_addr = htonl(0xFFFFFF00ul);
	else
	    mask->s_addr = htonl(0xFFFFFFFFul);
    }
    return 1;
}


#define SCAN_ACL1       "%[0123456789.]-%[0123456789.]/%[0123456789.]"
#define SCAN_ACL2       "%[0123456789.]-%[0123456789.]"
#define SCAN_ACL3       "%[0123456789.]/%[0123456789.]"
#define SCAN_ACL4       "%[0123456789.]"

static acl_ip_data *
aclParseIpData(const char *t)
{
    LOCAL_ARRAY(char, addr1, 256);
    LOCAL_ARRAY(char, addr2, 256);
    LOCAL_ARRAY(char, mask, 256);
    acl_ip_data *q = memAllocate(MEM_ACL_IP_DATA);
    acl_ip_data *r;
    acl_ip_data **Q;
    struct hostent *hp;
    char **x;
    debug(28, 5) ("aclParseIpData: %s\n", t);
    if (!strcasecmp(t, "all")) {
	q->addr1.s_addr = 0;
	q->addr2.s_addr = 0;
	q->mask.s_addr = 0;
	return q;
    }
    if (sscanf(t, SCAN_ACL1, addr1, addr2, mask) == 3) {
	(void) 0;
    } else if (sscanf(t, SCAN_ACL2, addr1, addr2) == 2) {
	mask[0] = '\0';
    } else if (sscanf(t, SCAN_ACL3, addr1, mask) == 2) {
	addr2[0] = '\0';
    } else if (sscanf(t, SCAN_ACL4, addr1) == 1) {
	addr2[0] = '\0';
	mask[0] = '\0';
    } else if (sscanf(t, "%[^/]/%s", addr1, mask) == 2) {
	addr2[0] = '\0';
    } else if (sscanf(t, "%s", addr1) == 1) {
	/*
	 * Note, must use plain gethostbyname() here because at startup
	 * ipcache hasn't been initialized
	 */
	if ((hp = gethostbyname(addr1)) == NULL) {
	    debug(28, 0) ("aclParseIpData: Bad host/IP: '%s'\n", t);
	    safe_free(q);
	    return NULL;
	}
	Q = &q;
	for (x = hp->h_addr_list; x != NULL && *x != NULL; x++) {
	    if ((r = *Q) == NULL)
		r = *Q = memAllocate(MEM_ACL_IP_DATA);
	    xmemcpy(&r->addr1.s_addr, *x, sizeof(r->addr1.s_addr));
	    r->addr2.s_addr = 0;
	    r->mask.s_addr = no_addr.s_addr;	/* 255.255.255.255 */
	    Q = &r->next;
	    debug(28, 3) ("%s --> %s\n", addr1, inet_ntoa(r->addr1));
	}
	return q;
    } else {
	debug(28, 0) ("aclParseIpData: Bad host/IP: '%s'\n", t);
	safe_free(q);
	return NULL;
    }
    /* Decode addr1 */
    if (!decode_addr(addr1, &q->addr1, &q->mask)) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown first address '%s'\n", addr1);
	safe_free(q);
	return NULL;
    }
    /* Decode addr2 */
    if (*addr2 && !decode_addr(addr2, &q->addr2, &q->mask)) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown second address '%s'\n", addr2);
	safe_free(q);
	return NULL;
    }
    /* Decode mask */
    if (*mask && !decode_addr(mask, &q->mask, NULL)) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown netmask '%s'\n", mask);
	safe_free(q);
	return NULL;
    }
    q->addr1.s_addr &= q->mask.s_addr;
    q->addr2.s_addr &= q->mask.s_addr;
    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
    return q;
}

/******************/
/* aclParseIpList */
/******************/

static void
aclParseIpList(void *curlist)
{
    char *t = NULL;
    splayNode **Top = curlist;
    acl_ip_data *q = NULL;
    while ((t = strtokFile())) {
	q = aclParseIpData(t);
	while (q != NULL) {
	    *Top = splay_insert(q, *Top, aclIpNetworkCompare);
	    q = q->next;
	}
    }
}

static void
aclParseTimeSpec(void *curlist)
{
    acl_time_data *q = NULL;
    acl_time_data **Tail;
    int h1, m1, h2, m2;
    char *t = NULL;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    q = memAllocate(MEM_ACL_TIME_DATA);
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
		    debug(28, 0) ("aclParseTimeSpec: Bad Day '%c'\n",
			*t);
		    break;
		}
	    }
	} else {
	    /* assume its time-of-day spec */
	    if (sscanf(t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4) {
		debug(28, 0) ("%s line %d: %s\n",
		    cfg_filename, config_lineno, config_input_line);
		debug(28, 0) ("aclParseTimeSpec: IGNORING Bad time range\n");
		xfree(q);
		return;
	    }
	    q->start = h1 * 60 + m1;
	    q->stop = h2 * 60 + m2;
	    if (q->start > q->stop) {
		debug(28, 0) ("%s line %d: %s\n",
		    cfg_filename, config_lineno, config_input_line);
		debug(28, 0) ("aclParseTimeSpec: IGNORING Reversed time range\n");
		xfree(q);
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
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
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
	q = memAllocate(MEM_RELIST);
	q->pattern = xstrdup(t);
	q->regex = comp;
	*(Tail) = q;
	Tail = &q->next;
    }
}

static void
aclParseWordList(void *curlist)
{
    char *t = NULL;
    while ((t = strtokFile()))
	wordlistAdd(curlist, t);
}

/**********************/
/* aclParseDomainList */
/**********************/

static void
aclParseDomainList(void *curlist)
{
    char *t = NULL;
    splayNode **Top = curlist;
    while ((t = strtokFile())) {
	Tolower(t);
	*Top = splay_insert(xstrdup(t), *Top, aclDomainCompare);
    }
}

void
aclParseAclLine(acl ** head)
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
    if ((acltype = aclStrToType(t)) == ACL_NONE) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseAclLine: Invalid ACL type '%s'\n", t);
	return;
    }
    if ((A = aclFindByName(aclname)) == NULL) {
	debug(28, 3) ("aclParseAclLine: Creating ACL '%s'\n", aclname);
	A = memAllocate(MEM_ACL);
	xstrncpy(A->name, aclname, ACL_NAME_SZ);
	A->type = acltype;
	A->cfgline = xstrdup(config_input_line);
	new_acl = 1;
    } else {
	if (acltype != A->type) {
	    debug(28, 0) ("aclParseAclLine: ACL '%s' already exists with different type, skipping.\n", A->name);
	    return;
	}
	debug(28, 3) ("aclParseAclLine: Appending to '%s'\n", aclname);
	new_acl = 0;
    }
    switch (A->type) {
    case ACL_SRC_IP:
    case ACL_DST_IP:
    case ACL_MY_IP:
	aclParseIpList(&A->data);
	break;
    case ACL_SRC_DOMAIN:
    case ACL_DST_DOMAIN:
	aclParseDomainList(&A->data);
	break;
    case ACL_TIME:
	aclParseTimeSpec(&A->data);
	break;
    case ACL_URL_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_SRC_DOM_REGEX:
    case ACL_DST_DOM_REGEX:
	aclParseRegexList(&A->data);
	break;
    case ACL_SRC_ASN:
    case ACL_DST_ASN:
    case ACL_NETDB_SRC_RTT:
	aclParseIntlist(&A->data);
	break;
    case ACL_URL_PORT:
	aclParseIntRange(&A->data);
	break;
#if USE_IDENT
    case ACL_IDENT:
	aclParseWordList(&A->data);
	break;
#endif
    case ACL_PROTO:
	aclParseProtoList(&A->data);
	break;
    case ACL_METHOD:
	aclParseMethodList(&A->data);
	break;
    case ACL_BROWSER:
	aclParseRegexList(&A->data);
	break;
    case ACL_PROXY_AUTH:
	aclParseWordList(&A->data);
	if (!proxy_auth_cache) {
	    /* First time around, 7921 should be big enough */
	    proxy_auth_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
	    assert(proxy_auth_cache);
	}
	break;
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
	aclParseWordList(&A->data);
	break;
#endif
#if USE_ARP_ACL
    case ACL_SRC_ARP:
	aclParseArpList(&A->data);
	break;
#endif
    case ACL_NONE:
    default:
	fatal("Bad ACL type");
	break;
    }
    if (!new_acl)
	return;
    if (A->data == NULL) {
	debug(28, 0) ("aclParseAclLine: IGNORING invalid ACL: %s\n",
	    A->cfgline);
	xfree(A);
	return;
    }
    /* append */
    while (*head)
	head = &(*head)->next;
    *head = A;
}

/* does name lookup, returns page_id */
int
aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name)
{
    acl_deny_info_list *A = NULL;
    acl_name_list *L = NULL;

    A = *head;
    if (NULL == *head)		/* empty list */
	return -1;
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
    return -1;
}

/* does name lookup, returns if it is a proxy_auth acl */
int
aclIsProxyAuth(const char *name)
{
    acl *a = aclFindByName(name);
    if (a)
	return a->type == ACL_PROXY_AUTH;
    return 0;
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
    A = xcalloc(1, sizeof(acl_deny_info_list));
    A->err_page_id = errorReservePageId(t);
    A->err_page_name = xstrdup(t);
    A->next = (acl_deny_info_list *) NULL;
    /* next expect a list of ACL names */
    Tail = &A->acl_list;
    while ((t = strtok(NULL, w_space))) {
	L = xcalloc(1, sizeof(acl_name_list));
	xstrncpy(L->name, t, ACL_NAME_SZ);
	*Tail = L;
	Tail = &L->next;
    }
    if (A->acl_list == NULL) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseDenyInfoLine: deny_info line contains no ACL's, skipping\n");
	xfree(A);
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
    acl_list *L = NULL;
    acl_list **Tail = NULL;
    acl *a = NULL;

    /* first expect either 'allow' or 'deny' */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseAccessLine: missing 'allow' or 'deny'.\n");
	return;
    }
    A = memAllocate(MEM_ACL_ACCESS);

    if (!strcmp(t, "allow"))
	A->allow = 1;
    else if (!strcmp(t, "deny"))
	A->allow = 0;
    else {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseAccessLine: expecting 'allow' or 'deny', got '%s'.\n", t);
	xfree(A);
	return;
    }

    /* next expect a list of ACL names, possibly preceeded
     * by '!' for negation */
    Tail = &A->acl_list;
    while ((t = strtok(NULL, w_space))) {
	L = memAllocate(MEM_ACL_LIST);
	L->op = 1;		/* defaults to non-negated */
	if (*t == '!') {
	    /* negated ACL */
	    L->op = 0;
	    t++;
	}
	debug(28, 3) ("aclParseAccessLine: looking for ACL name '%s'\n", t);
	a = aclFindByName(t);
	if (a == NULL) {
	    debug(28, 0) ("%s line %d: %s\n",
		cfg_filename, config_lineno, config_input_line);
	    debug(28, 0) ("aclParseAccessLine: ACL name '%s' not found.\n", t);
	    xfree(L);
	    continue;
	}
	L->acl = a;
	*Tail = L;
	Tail = &L->next;
    }
    if (A->acl_list == NULL) {
	debug(28, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0) ("aclParseAccessLine: Access line contains no ACL's, skipping\n");
	xfree(A);
	return;
    }
    A->cfgline = xstrdup(config_input_line);
    /* Append to the end of this list */
    for (B = *head, T = head; B; T = &B->next, B = B->next);
    *T = A;
    /* We lock _acl_access structures in aclCheck() */
    cbdataAdd(A, memFree, MEM_ACL_ACCESS);
}

/**************/
/* aclMatchIp */
/**************/

static int
aclMatchIp(void *dataptr, struct in_addr c)
{
    splayNode **Top = dataptr;
    *Top = splay_splay(&c, *Top, aclIpNetworkCompare);
    debug(28, 3) ("aclMatchIp: '%s' %s\n",
	inet_ntoa(c), splayLastResult ? "NOT found" : "found");
    return !splayLastResult;
}

/**********************/
/* aclMatchDomainList */
/**********************/

static int
aclMatchDomainList(void *dataptr, const char *host)
{
    splayNode **Top = dataptr;
    if (host == NULL)
	return 0;
    debug(28, 3) ("aclMatchDomainList: checking '%s'\n", host);
    *Top = splay_splay(host, *Top, aclHostDomainCompare);
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

static int
aclMatchUser(wordlist * data, const char *user)
{
    if (user == NULL)
	return 0;
    debug(28, 3) ("aclMatchUser: checking '%s'\n", user);
    while (data) {
	debug(28, 3) ("aclMatchUser: looking for '%s'\n", data->key);
	if (strcmp(data->key, "REQUIRED") == 0 && *user != '\0' && strcmp(user, "-") != 0)
	    return 1;
	if (strcmp(data->key, user) == 0)
	    return 1;
	data = data->next;
    }
    return 0;
}

static int
aclDecodeProxyAuth(const char *proxy_auth, char **user, char **password, char *buf, size_t bufsize)
{
    char *sent_auth;
    char *cleartext;

    if (proxy_auth == NULL)
	return 0;
    if (strlen(proxy_auth) < SKIP_BASIC_SZ)
	return 0;
    proxy_auth += SKIP_BASIC_SZ;
    sent_auth = xstrdup(proxy_auth);	/* username and password */
    /* Trim trailing \n before decoding */
    strtok(sent_auth, "\n");
    /* Trim leading whitespace before decoding */
    while (isspace(*proxy_auth))
	proxy_auth++;
    cleartext = uudecode(sent_auth);
    xfree(sent_auth);
    debug(28, 6) ("aclDecodeProxyAuth: cleartext = '%s'\n", cleartext);
    xstrncpy(buf, cleartext, bufsize);
    xfree(cleartext);
    *user = buf;
    if ((*password = strchr(*user, ':')) != NULL)
	*(*password)++ = '\0';
    if (*password == NULL) {
	debug(28, 1) ("aclDecodeProxyAuth: no password in proxy authorization header\n");
	return 0;
    }
    return 1;
}

/* aclMatchProxyAuth can return three exit codes:
 * 0 : user denied access
 * 1 : user validated OK
 * -1 : check the password for this user via an external authenticator
 * -2 : invalid Proxy-authorization: header;
 * ask for Proxy-Authorization: header
 */

static int
aclMatchProxyAuth(wordlist * data, const char *proxy_auth, acl_proxy_auth_user * auth_user, aclCheck_t * checklist)
{
    /* checklist is used to register user name when identified, nothing else */
    LOCAL_ARRAY(char, login_buf, USER_IDENT_SZ);
    char *user, *password;

    if (!aclDecodeProxyAuth(proxy_auth, &user, &password, login_buf, sizeof(login_buf)))
	/* No or invalid Proxy-Auth header */
	return -2;

    debug(28, 5) ("aclMatchProxyAuth: checking user '%s'\n", user);

    if (auth_user) {
	/* This should be optimized to a boolean argument indicating that the
	 * password is invalid, instead of passing full acl_proxy_auth_user
	 * structures, and all messing with checklist->proxy_auth should
	 * be restricted the functions that deal with the authenticator.
	 */
	assert(auth_user == checklist->auth_user);
	checklist->auth_user = NULL;	/* get rid of that special reference */
	/* Check result from external validation */
	if (auth_user->passwd_ok != 1) {
	    /* password was checked but did not match */
	    assert(auth_user->passwd_ok == 0);
	    debug(28, 4) ("aclMatchProxyAuth: authentication failed for user '%s'\n",
		user);
	    aclFreeProxyAuthUser(auth_user);
	    /* copy username to request for logging on client-side unless ident
	     * is known (do not override ident with false proxy auth names) */
	    if (!*checklist->request->user_ident)
		xstrncpy(checklist->request->user_ident, user, USER_IDENT_SZ);
	    return -2;
	} else {
	    /* password was checked and did match */
	    debug(28, 4) ("aclMatchProxyAuth: user '%s' validated OK\n", user);
	    /* store validated user in hash, after filling in expiretime */
	    xstrncpy(checklist->request->user_ident, user, USER_IDENT_SZ);
	    auth_user->expiretime = current_time.tv_sec + Config.authenticateTTL;
	    hash_join(proxy_auth_cache, (hash_link *) auth_user);
	    /* Continue checking below, as normal */
	}
    }
    /* see if we already know this user */
    auth_user = hash_lookup(proxy_auth_cache, user);

    if (!auth_user) {
	/* user not yet known, ask external authenticator */
	debug(28, 4) ("aclMatchProxyAuth: user '%s' not yet known\n", user);
	return -1;
    } else if ((0 == strcmp(auth_user->passwd, password)) &&
	(auth_user->expiretime > current_time.tv_sec)) {
	/* user already known and valid */
	debug(28, 5) ("aclMatchProxyAuth: user '%s' previously validated\n",
	    user);
	/* copy username to request for logging on client-side */
	xstrncpy(checklist->request->user_ident, user, USER_IDENT_SZ);
	return aclMatchUser(data, user);
    } else {
	/* password mismatch/timeout */
	debug(28, 4) ("aclMatchProxyAuth: user '%s' password mismatch/timeout\n",
	    user);
	/* remove this user from the hash, making him unknown */
	hash_remove_link(proxy_auth_cache, (hash_link *) auth_user);
	aclFreeProxyAuthUser(auth_user);
	/* ask the external authenticator in case the password is changed */
	/* wrong password will be trapped above so this does not loop */
	return -1;
    }
    /* NOTREACHED */

}

static void
aclLookupProxyAuthStart(aclCheck_t * checklist)
{
    LOCAL_ARRAY(char, login_buf, USER_IDENT_SZ);
    const char *proxy_auth;
    char *user, *password;
    int ok;
    acl_proxy_auth_user *auth_user;
    assert(!checklist->auth_user);
    if (!checklist->request->flags.accelerated) {
	/* Proxy auth on proxy requests */
	proxy_auth = httpHeaderGetStr(&checklist->request->header,
	    HDR_PROXY_AUTHORIZATION);
    } else {
	/* WWW auth on accelerated requests */
	proxy_auth = httpHeaderGetStr(&checklist->request->header,
	    HDR_AUTHORIZATION);
    }
    ok = aclDecodeProxyAuth(proxy_auth, &user, &password, login_buf,
	sizeof(login_buf));
    /*
     * if aclDecodeProxyAuth() fails, the same call should have failed
     * in aclMatchProxyAuth, and we should never get this far.
     */
    assert(ok);
    debug(28, 4) ("aclLookupProxyAuthStart: going to ask authenticator on %s\n", user);
    /* we must still check this user's password */
    auth_user = memAllocate(MEM_ACL_PROXY_AUTH_USER);
    auth_user->user = xstrdup(user);
    auth_user->passwd = xstrdup(password);
    auth_user->passwd_ok = -1;
    auth_user->expiretime = -1;
    checklist->auth_user = auth_user;
    authenticateStart(checklist->auth_user, aclLookupProxyAuthDone,
	checklist);
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

    if (t < data->start || t > data->stop)
	return 0;
    return data->weekbits & (1 << tm.tm_wday) ? 1 : 0;
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

static int
aclMatchAcl(acl * ae, aclCheck_t * checklist)
{
    request_t *r = checklist->request;
    const ipcache_addrs *ia = NULL;
    const char *fqdn = NULL;
    char *esc_buf;
    const char *header;
    int k;
    if (!ae)
	return 0;
    debug(28, 3) ("aclMatchAcl: checking '%s'\n", ae->cfgline);
    switch (ae->type) {
    case ACL_SRC_IP:
	return aclMatchIp(&ae->data, checklist->src_addr);
	/* NOTREACHED */
    case ACL_MY_IP:
	return aclMatchIp(&ae->data, checklist->my_addr);
	/* NOTREACHED */
    case ACL_DST_IP:
	ia = ipcache_gethostbyname(r->host, IP_LOOKUP_IF_MISS);
	if (ia) {
	    for (k = 0; k < (int) ia->count; k++) {
		if (aclMatchIp(&ae->data, ia->in_addrs[k]))
		    return 1;
	    }
	    return 0;
	} else if (checklist->state[ACL_DST_IP] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		ae->name, r->host);
	    checklist->state[ACL_DST_IP] = ACL_LOOKUP_NEEDED;
	    return 0;
	} else {
	    return aclMatchIp(&ae->data, no_addr);
	}
	/* NOTREACHED */
    case ACL_DST_DOMAIN:
	if ((ia = ipcacheCheckNumeric(r->host)) == NULL)
	    return aclMatchDomainList(&ae->data, r->host);
	fqdn = fqdncache_gethostbyaddr(ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
	if (fqdn)
	    return aclMatchDomainList(&ae->data, fqdn);
	if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		ae->name, inet_ntoa(ia->in_addrs[0]));
	    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchDomainList(&ae->data, "none");
	/* NOTREACHED */
    case ACL_SRC_DOMAIN:
	fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);
	if (fqdn) {
	    return aclMatchDomainList(&ae->data, fqdn);
	} else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		ae->name, inet_ntoa(checklist->src_addr));
	    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchDomainList(&ae->data, "none");
	/* NOTREACHED */
    case ACL_DST_DOM_REGEX:
	if ((ia = ipcacheCheckNumeric(r->host)) == NULL)
	    return aclMatchRegex(ae->data, r->host);
	fqdn = fqdncache_gethostbyaddr(ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
	if (fqdn)
	    return aclMatchRegex(ae->data, fqdn);
	if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		ae->name, inet_ntoa(ia->in_addrs[0]));
	    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchRegex(ae->data, "none");
	/* NOTREACHED */
    case ACL_SRC_DOM_REGEX:
	fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);
	if (fqdn) {
	    return aclMatchRegex(ae->data, fqdn);
	} else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		ae->name, inet_ntoa(checklist->src_addr));
	    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	return aclMatchRegex(ae->data, "none");
	/* NOTREACHED */
    case ACL_TIME:
	return aclMatchTime(ae->data, squid_curtime);
	/* NOTREACHED */
    case ACL_URLPATH_REGEX:
	esc_buf = xstrdup(strBuf(r->urlpath));
	rfc1738_unescape(esc_buf);
	k = aclMatchRegex(ae->data, esc_buf);
	safe_free(esc_buf);
	return k;
	/* NOTREACHED */
    case ACL_URL_REGEX:
	esc_buf = xstrdup(urlCanonical(r));
	rfc1738_unescape(esc_buf);
	k = aclMatchRegex(ae->data, esc_buf);
	safe_free(esc_buf);
	return k;
	/* NOTREACHED */
    case ACL_URL_PORT:
	return aclMatchIntegerRange(ae->data, r->port);
	/* NOTREACHED */
#if USE_IDENT
    case ACL_IDENT:
	if (checklist->ident[0]) {
	    return aclMatchUser(ae->data, checklist->ident);
	} else {
	    checklist->state[ACL_IDENT] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	/* NOTREACHED */
#endif
    case ACL_PROTO:
	return aclMatchInteger(ae->data, r->protocol);
	/* NOTREACHED */
    case ACL_METHOD:
	return aclMatchInteger(ae->data, r->method);
	/* NOTREACHED */
    case ACL_BROWSER:
	return aclMatchRegex(ae->data, checklist->browser);
	/* NOTREACHED */
    case ACL_PROXY_AUTH:
	if (!r->flags.accelerated) {
	    /* Proxy authorization on proxy requests */
	    header = httpHeaderGetStr(&checklist->request->header,
		HDR_PROXY_AUTHORIZATION);
	} else if (r->flags.internal) {
	    /* WWW authorization on accelerated internal requests */
	    header = httpHeaderGetStr(&checklist->request->header,
		HDR_AUTHORIZATION);
	} else {
#if AUTH_ON_ACCELERATION
	    /* WWW authorization on accelerated requests */
	    header = httpHeaderGetStr(&checklist->request->header,
		HDR_AUTHORIZATION);
#else
	    debug(28, 1) ("aclMatchAcl: proxy_auth %s not applicable on accelerated requests.\n", ae->name);
	    return -1;
#endif
	}
	/*
	 * Register that we used the proxy authentication header so that
	 * it is not forwarded to the next proxy
	 */
	r->flags.used_proxy_auth = 1;
	/* Check the password */
	switch (aclMatchProxyAuth(ae->data,
		header,
		checklist->auth_user,
		checklist)) {
	case 0:
	    /* Correct password, but was not allowed in this ACL */
	    return 0;
	case 1:
	    /* user validated OK */
	    return 1;
	case -2:
	    /* no such user OR we need a proxy authentication header */
	    checklist->state[ACL_PROXY_AUTH] = ACL_PROXY_AUTH_NEEDED;
	    /*
	     * XXX This is a bit oddly done.. should perhaps use different
	     * return codes here
	     */
	    return 0;
	case -1:
	    /*
	     * we need to validate the password
	     */
	    checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_NEEDED;
	    return 0;
	}
	/* NOTREACHED */
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
	return aclMatchWordList(ae->data, checklist->snmp_community);
#endif
    case ACL_SRC_ASN:
	return asnMatchIp(ae->data, checklist->src_addr);
    case ACL_DST_ASN:
	ia = ipcache_gethostbyname(r->host, IP_LOOKUP_IF_MISS);
	if (ia) {
	    for (k = 0; k < (int) ia->count; k++) {
		if (asnMatchIp(ae->data, ia->in_addrs[k]))
		    return 1;
	    }
	    return 0;
	} else if (checklist->state[ACL_DST_ASN] == ACL_LOOKUP_NONE) {
	    debug(28, 3) ("asnMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		ae->name, r->host);
	    checklist->state[ACL_DST_ASN] = ACL_LOOKUP_NEEDED;
	} else {
	    return asnMatchIp(ae->data, no_addr);
	}
	return 0;
#if USE_ARP_ACL
    case ACL_SRC_ARP:
	return aclMatchArp(&ae->data, checklist->src_addr);
#endif
    case ACL_NONE:
    default:
	debug(28, 0) ("aclMatchAcl: '%s' has bad type %d\n",
	    ae->name, ae->type);
	return 0;
    }
    /* NOTREACHED */
}

int
aclMatchAclList(const acl_list * list, aclCheck_t * checklist)
{
    while (list) {
	AclMatchedName = list->acl->name;
	debug(28, 3) ("aclMatchAclList: checking %s%s\n",
	    list->op ? null_string : "!", list->acl->name);
	if (aclMatchAcl(list->acl, checklist) != list->op) {
	    debug(28, 3) ("aclMatchAclList: returning 0\n");
	    return 0;
	}
	list = list->next;
    }
    debug(28, 3) ("aclMatchAclList: returning 1\n");
    return 1;
}

int
aclCheckFast(const acl_access * A, aclCheck_t * checklist)
{
    int allow = 0;
    debug(28, 5) ("aclCheckFast: list: %p\n", A);
    while (A) {
	allow = A->allow;
	if (aclMatchAclList(A->acl_list, checklist))
	    return allow;
	A = A->next;
    }
    debug(28, 5) ("aclCheckFast: no matches, returning: %d\n", !allow);
    return !allow;
}

static void
aclCheck(aclCheck_t * checklist)
{
    allow_t allow = ACCESS_DENIED;
    const acl_access *A;
    int match;
    ipcache_addrs *ia;
    while ((A = checklist->access_list) != NULL) {
	/*
	 * If the _acl_access is no longer valid (i.e. its been
	 * freed because of a reconfigure), then bail on this
	 * access check.  For now, return ACCESS_DENIED.
	 */
	if (!cbdataValid(A)) {
	    cbdataUnlock(A);
	    break;
	}
	debug(28, 3) ("aclCheck: checking '%s'\n", A->cfgline);
	allow = A->allow;
	match = aclMatchAclList(A->acl_list, checklist);
	if (checklist->state[ACL_DST_IP] == ACL_LOOKUP_NEEDED) {
	    checklist->state[ACL_DST_IP] = ACL_LOOKUP_PENDING;
	    ipcache_nbgethostbyname(checklist->request->host,
		aclLookupDstIPDone,
		checklist);
	    return;
	} else if (checklist->state[ACL_DST_ASN] == ACL_LOOKUP_NEEDED) {
	    checklist->state[ACL_DST_ASN] = ACL_LOOKUP_PENDING;
	    ipcache_nbgethostbyname(checklist->request->host,
		aclLookupDstIPforASNDone,
		checklist);
	    return;
	} else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NEEDED) {
	    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_PENDING;
	    fqdncache_nbgethostbyaddr(checklist->src_addr,
		aclLookupSrcFQDNDone,
		checklist);
	    return;
	} else if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NEEDED) {
	    ia = ipcacheCheckNumeric(checklist->request->host);
	    if (ia == NULL) {
		checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_DONE;
		return;
	    }
	    checklist->dst_addr = ia->in_addrs[0];
	    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_PENDING;
	    fqdncache_nbgethostbyaddr(checklist->dst_addr,
		aclLookupDstFQDNDone,
		checklist);
	    return;
	} else if (checklist->state[ACL_PROXY_AUTH] == ACL_LOOKUP_NEEDED) {
	    debug(28, 3) ("aclCheck: checking password via authenticator\n");
	    aclLookupProxyAuthStart(checklist);
	    checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_PENDING;
	    return;
	} else if (checklist->state[ACL_PROXY_AUTH] == ACL_PROXY_AUTH_NEEDED) {
	    /* Special case. Client is required to resend the request
	     * with authentication. The request is denied.
	     */
	    allow = ACCESS_REQ_PROXY_AUTH;
	    match = -1;
	}
#if USE_IDENT
	else if (checklist->state[ACL_IDENT] == ACL_LOOKUP_NEEDED) {
	    debug(28, 3) ("aclCheck: Doing ident lookup\n");
	    if (cbdataValid(checklist->conn)) {
		identStart(&checklist->conn->me, &checklist->conn->peer,
		    aclLookupIdentDone, checklist);
		checklist->state[ACL_IDENT] = ACL_LOOKUP_PENDING;
		return;
	    } else {
		debug(28, 1) ("aclCheck: Can't start ident lookup. No client connection\n");
		cbdataUnlock(checklist->conn);
		checklist->conn = NULL;
		allow = 0;
		match = -1;
	    }
	}
#endif
	/*
	 * We are done with this _acl_access entry.  Either the request
	 * is allowed, denied, requires authentication, or we move on to
	 * the next entry.
	 */
	cbdataUnlock(A);
	if (match) {
	    debug(28, 3) ("aclCheck: match found, returning %d\n", allow);
	    aclCheckCallback(checklist, allow);
	    return;
	}
	checklist->access_list = A->next;
	/*
	 * Lock the next _acl_access entry
	 */
	if (A->next)
	    cbdataLock(A->next);
    }
    debug(28, 3) ("aclCheck: NO match found, returning %d\n", !allow);
    aclCheckCallback(checklist, !allow);
}

void
aclChecklistFree(aclCheck_t * checklist)
{
    if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_PENDING)
	fqdncacheUnregister(checklist->src_addr, checklist);
    if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_PENDING)
	fqdncacheUnregister(checklist->dst_addr, checklist);
    if (checklist->state[ACL_DST_IP] == ACL_LOOKUP_PENDING)
	ipcacheUnregister(checklist->request->host, checklist);
    if (checklist->request)
	requestUnlink(checklist->request);
    checklist->request = NULL;
#if USE_IDENT
    if (checklist->conn) {
	cbdataUnlock(checklist->conn);
	checklist->conn = NULL;
    }
#endif
    cbdataFree(checklist);
}

static void
aclCheckCallback(aclCheck_t * checklist, allow_t answer)
{
    debug(28, 3) ("aclCheckCallback: answer=%d\n", answer);
    if (cbdataValid(checklist->callback_data))
	checklist->callback(answer, checklist->callback_data);
    cbdataUnlock(checklist->callback_data);
    checklist->callback = NULL;
    checklist->callback_data = NULL;
    aclChecklistFree(checklist);
}

#if USE_IDENT
static void
aclLookupIdentDone(const char *ident, void *data)
{
    aclCheck_t *checklist = data;
    if (ident) {
	xstrncpy(checklist->ident, ident, sizeof(checklist->ident));
	xstrncpy(checklist->request->user_ident, ident, sizeof(checklist->request->user_ident));
    } else {
	xstrncpy(checklist->ident, "-", sizeof(checklist->ident));
    }
    /*
     * Cache the ident result in the connection, to avoid redoing ident lookup
     * over and over on persistent connections
     */
    if (cbdataValid(checklist->conn) && !checklist->conn->ident[0])
	xstrncpy(checklist->conn->ident, checklist->ident, sizeof(checklist->conn->ident));
    aclCheck(checklist);
}
#endif

static void
aclLookupDstIPDone(const ipcache_addrs * ia, void *data)
{
    aclCheck_t *checklist = data;
    checklist->state[ACL_DST_IP] = ACL_LOOKUP_DONE;
    aclCheck(checklist);
}

static void
aclLookupDstIPforASNDone(const ipcache_addrs * ia, void *data)
{
    aclCheck_t *checklist = data;
    checklist->state[ACL_DST_ASN] = ACL_LOOKUP_DONE;
    aclCheck(checklist);
}

static void
aclLookupSrcFQDNDone(const char *fqdn, void *data)
{
    aclCheck_t *checklist = data;
    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_DONE;
    aclCheck(checklist);
}

static void
aclLookupDstFQDNDone(const char *fqdn, void *data)
{
    aclCheck_t *checklist = data;
    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_DONE;
    aclCheck(checklist);
}

static void
aclLookupProxyAuthDone(void *data, char *result)
{
    aclCheck_t *checklist = data;
    checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_DONE;
    debug(28, 4) ("aclLookupProxyAuthDone: result = %s\n",
	result ? result : "NULL");
    if (result && (strncasecmp(result, "OK", 2) == 0))
	checklist->auth_user->passwd_ok = 1;
    else
	checklist->auth_user->passwd_ok = 0;
    aclCheck(checklist);
}

aclCheck_t *
aclChecklistCreate(const acl_access * A,
    request_t * request,
    struct in_addr src_addr,
    struct in_addr my_addr,
    const char *user_agent,
    const char *ident)
{
    int i;
    aclCheck_t *checklist = memAllocate(MEM_ACLCHECK_T);
    cbdataAdd(checklist, memFree, MEM_ACLCHECK_T);
    checklist->access_list = A;
    /*
     * aclCheck() makes sure checklist->access_list is a valid
     * pointer, so lock it.
     */
    cbdataLock(A);
    if (request != NULL)
	checklist->request = requestLink(request);
    checklist->src_addr = src_addr;
    checklist->my_addr = my_addr;
    for (i = 0; i < ACL_ENUM_MAX; i++)
	checklist->state[i] = ACL_LOOKUP_NONE;
    if (user_agent)
	xstrncpy(checklist->browser, user_agent, BROWSERNAMELEN);
#if USE_IDENT
    if (ident)
	xstrncpy(checklist->ident, ident, USER_IDENT_SZ);
#endif
    checklist->auth_user = NULL;	/* init to NULL */
    return checklist;
}

void
aclNBCheck(aclCheck_t * checklist, PF callback, void *callback_data)
{
    checklist->callback = callback;
    checklist->callback_data = callback_data;
    cbdataLock(callback_data);
    aclCheck(checklist);
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

static void
aclFreeProxyAuthUser(void *data)
{
    acl_proxy_auth_user *u = data;
    xfree(u->user);
    xfree(u->passwd);
    memFree(u, MEM_ACL_PROXY_AUTH_USER);
}

static void
aclFreeIpData(void *p)
{
    memFree(p, MEM_ACL_IP_DATA);
}

void
aclDestroyAcls(acl ** head)
{
    acl *a = NULL;
    acl *next = NULL;
    for (a = *head; a; a = next) {
	next = a->next;
	debug(28, 3) ("aclDestroyAcls: '%s'\n", a->cfgline);
	switch (a->type) {
	case ACL_SRC_IP:
	case ACL_DST_IP:
	case ACL_MY_IP:
	    splay_destroy(a->data, aclFreeIpData);
	    break;
	case ACL_SRC_ARP:
	case ACL_DST_DOMAIN:
	case ACL_SRC_DOMAIN:
	    splay_destroy(a->data, xfree);
	    break;
#if SQUID_SNMP
	case ACL_SNMP_COMMUNITY:
#endif
#if USE_IDENT
	case ACL_IDENT:
#endif
	case ACL_PROXY_AUTH:
	    wordlistDestroy((wordlist **) & a->data);
	    break;
	case ACL_TIME:
	    aclDestroyTimeList(a->data);
	    break;
	case ACL_URL_REGEX:
	case ACL_URLPATH_REGEX:
	case ACL_BROWSER:
	    aclDestroyRegexList(a->data);
	    break;
	case ACL_PROTO:
	case ACL_METHOD:
	case ACL_SRC_ASN:
	case ACL_DST_ASN:
	    intlistDestroy((intlist **) & a->data);
	    break;
	case ACL_URL_PORT:
	    aclDestroyIntRange(a->data);
	    break;
	case ACL_NONE:
	default:
	    assert(0);
	    break;
	}
	safe_free(a->cfgline);
	memFree(a, MEM_ACL);
    }
    *head = NULL;
}

static void
aclDestroyAclList(acl_list * list)
{
    acl_list *next = NULL;
    for (; list; list = next) {
	next = list->next;
	memFree(list, MEM_ACL_LIST);
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
	aclDestroyAclList(l->acl_list);
	l->acl_list = NULL;
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
	safe_free(a);
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

static int
aclDomainCompare(const void *data, splayNode * n)
{
    const char *d1 = data;
    const char *d2 = n->data;
    int l1 = strlen(d1);
    int l2 = strlen(d2);
    while (d1[l1] == d2[l2]) {
	if ((l1 == 0) && (l2 == 0))
	    return 0;		/* d1 == d2 */
	if (l1-- == 0)
	    return -1;		/* d1 < d2 */
	if (l2-- == 0)
	    return 1;		/* d1 > d2 */
    }
    return (d1[l1] - d2[l2]);
}

/* compare a host and a domain */

static int
aclHostDomainCompare(const void *data, splayNode * n)
{
    const char *h = data;
    char *d = n->data;
    int l1;
    int l2;
    if (matchDomainName(d, h))
	return 0;
    l1 = strlen(h);
    l2 = strlen(d);
    /* h != d */
    while (h[l1] == d[l2]) {
	if (l1 == 0)
	    break;
	if (l2 == 0)
	    break;
	l1--;
	l2--;
    }
    /* a '.' is a special case */
    if ((h[l1] == '.') || (l1 == 0))
	return -1;		/* domain(h) < d */
    if ((d[l2] == '.') || (l2 == 0))
	return 1;		/* domain(h) > d */
    return (h[l1] - d[l2]);
}

/* compare two network specs
 * 
 * NOTE: this is very similar to aclIpNetworkCompare and it's not yet
 * clear whether this OK. The problem could be with when a network
 * is a subset of the other networks:
 * 
 * 128.1.2.0/255.255.255.128 == 128.1.2.0/255.255.255.0 ?
 * 
 * Currently only the first address of the first network is used.
 */

/* compare an address and a network spec */

static int
aclIpNetworkCompare(const void *a, splayNode * n)
{
    struct in_addr A = *(struct in_addr *) a;
    acl_ip_data *q = n->data;
    struct in_addr B = q->addr1;
    struct in_addr C = q->addr2;
    int rc = 0;
    A.s_addr &= q->mask.s_addr;	/* apply netmask */
    if (C.s_addr == 0) {	/* single address check */
	if (ntohl(A.s_addr) > ntohl(B.s_addr))
	    rc = 1;
	else if (ntohl(A.s_addr) < ntohl(B.s_addr))
	    rc = -1;
	else
	    rc = 0;
    } else {			/* range address check */
	if (ntohl(A.s_addr) > ntohl(C.s_addr))
	    rc = 1;
	else if (ntohl(A.s_addr) < ntohl(B.s_addr))
	    rc = -1;
	else
	    rc = 0;
    }
    return rc;
}

static void
aclDumpIpListWalkee(void *node, void *state)
{
    acl_ip_data *ip = node;
    MemBuf mb;
    wordlist **W = state;
    memBufDefInit(&mb);
    memBufPrintf(&mb, "%s", inet_ntoa(ip->addr1));
    if (ip->addr2.s_addr != any_addr.s_addr)
	memBufPrintf(&mb, "-%s", inet_ntoa(ip->addr2));
    if (ip->mask.s_addr != no_addr.s_addr)
	memBufPrintf(&mb, "/%s", inet_ntoa(ip->mask));
    wordlistAdd(W, mb.buf);
    memBufClean(&mb);
}

static wordlist *
aclDumpIpList(void *data)
{
    wordlist *w = NULL;
    splay_walk(data, aclDumpIpListWalkee, &w);
    return w;
}

static void
aclDumpDomainListWalkee(void *node, void *state)
{
    char *domain = node;
    wordlistAdd(state, domain);
}

static wordlist *
aclDumpDomainList(void *data)
{
    wordlist *w = NULL;
    splay_walk(data, aclDumpDomainListWalkee, &w);
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
	    t->start / 60,
	    t->start % 60,
	    t->stop / 60,
	    t->stop % 60);
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
aclDumpGeneric(const acl * a)
{
    debug(28, 3) ("aclDumpGeneric: %s type %d\n", a->name, a->type);
    switch (a->type) {
    case ACL_SRC_IP:
    case ACL_DST_IP:
    case ACL_MY_IP:
	return aclDumpIpList(a->data);
	break;
    case ACL_SRC_DOMAIN:
    case ACL_DST_DOMAIN:
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
#endif
#if USE_IDENT
    case ACL_IDENT:
#endif
    case ACL_PROXY_AUTH:
	return aclDumpDomainList(a->data);
	break;
    case ACL_TIME:
	return aclDumpTimeSpecList(a->data);
	break;
    case ACL_URL_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_BROWSER:
	return aclDumpRegexList(a->data);
	break;
    case ACL_SRC_ASN:
    case ACL_DST_ASN:
	return aclDumpIntlistList(a->data);
	break;
    case ACL_URL_PORT:
	return aclDumpIntRangeList(a->data);
	break;
    case ACL_PROTO:
	return aclDumpProtoList(a->data);
	break;
    case ACL_METHOD:
	return aclDumpMethodList(a->data);
	break;
#if USE_ARP_ACL
    case ACL_SRC_ARP:
	return aclDumpArpList(a->data);
	break;
#endif
    case ACL_NONE:
    default:
	break;
    }
    return NULL;
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
 */

#include <sys/sysctl.h>
#ifdef _SQUID_LINUX_
#include <net/if_arp.h>
#include <sys/ioctl.h>
#else
#include <net/if_dl.h>
#endif
#include <net/route.h>
#include <net/if.h>
#include <netinet/if_ether.h>

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
    acl_arp_data *q = xcalloc(1, sizeof(acl_arp_data));
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
    splayNode **Top = curlist;
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
#ifdef _SQUID_LINUX_
static int
aclMatchArp(void *dataptr, struct in_addr c)
{
    struct arpreq arpReq;
    struct sockaddr_in ipAddr;
    splayNode **Top = dataptr;
    ipAddr.sin_family = AF_INET;
    ipAddr.sin_port = 0;
    ipAddr.sin_addr = c;
    memcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));
    arpReq.arp_dev[0] = '\0';
    arpReq.arp_flags = 0;
    /* any AF_INET socket will do... gives back hardware type, device, etc */
    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) == -1) {
	debug(28, 1) ("ARP query failed - %d", errno);
	return 0;
    } else if (arpReq.arp_ha.sa_family != ARPHRD_ETHER) {
	debug(28, 1) ("Non-ethernet interface returned from ARP query - %d",
	    arpReq.arp_ha.sa_family);
	/* update here and MAC address parsing to handle non-ethernet */
	return 0;
    } else
	*Top = splay_splay(&arpReq.arp_ha.sa_data, *Top, aclArpCompare);
    debug(28, 3) ("aclMatchArp: '%s' %s\n",
	inet_ntoa(c), splayLastResult ? "NOT found" : "found");
    return !splayLastResult;
}

static int
aclArpCompare(const void *data, splayNode * n)
{
    const unsigned short *d1 = data;
    const unsigned short *d2 = n->data;
    if (d1[0] != d2[0])
	return (d1[0] > d2[0]) ? 1 : -1;
    if (d1[1] != d2[1])
	return (d1[1] > d2[1]) ? 1 : -1;
    if (d1[2] != d2[2])
	return (d1[2] > d2[2]) ? 1 : -1;
    return 0;
}
#else

static int
aclMatchArp(void *dataptr, struct in_addr c)
{
    WRITE ME;
}

static int
aclArpCompare(const void *data, splayNode * n)
{
    WRITE ME;
}

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
aclDumpArpListWalkee(void *node, void *state)
{
    acl_arp_data *arp = node;
    wordlist **W = state;
    static char buf[24];
    while (*W != NULL)
	W = &(*W)->next;
    snprintf(buf, sizeof(buf), "%02x:%02x:02x:02x:02x:02x",
	arp->eth[0], arp->eth[1], arp->eth[2], arp->eth[3],
	arp->eth[4], arp->eth[5]);
    wordlistAdd(state, buf);
}

static wordlist *
aclDumpArpList(void *data)
{
    wordlist *w = NULL;
    splay_walk(data, aclDumpArpListWalkee, &w);
    return w;
}

/* ==== END ARP ACL SUPPORT =============================================== */
#endif /* USE_ARP_ACL */
