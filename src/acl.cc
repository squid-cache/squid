/*
 * $Id: acl.cc,v 1.83 1997/02/06 19:59:53 wessels Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

/* Global */
const char *AclMatchedName = NULL;

/* for reading ACL's from files */
int aclFromFile = 0;
FILE *aclFile;

/* These three should never be referenced directly in this file! */
struct _acl_deny_info_list *DenyInfoList = NULL;
struct _acl_access *HTTPAccessList = NULL;
struct _acl_access *ICPAccessList = NULL;
struct _acl_access *MISSAccessList = NULL;
#if DELAY_HACK
struct _acl_access *DelayAccessList = NULL;
#endif

static struct _acl *AclList = NULL;
static struct _acl **AclListTail = &AclList;
static const char *const w_space = " \t\n\r";	/* Jasper sez so */


#ifdef USE_SPLAY_TREE
int aclCompIpResult = 0;
static struct _acl_ip_data *aclSplayInsertIp
             _PARAMS((struct _acl_ip_data *, struct _acl_ip_data *));
static struct _acl_ip_data *aclSplayIp
             _PARAMS((struct in_addr, struct _acl_ip_data *));
static int aclSplayIpCompare
    _PARAMS((struct in_addr addr, struct _acl_ip_data * data));
static int aclMatchIp _PARAMS((void *dataptr, struct in_addr c));
#else
static int aclMatchIp _PARAMS((struct _acl_ip_data * data, struct in_addr c));
#endif /* USE_SPLAY_TREE */

static void aclDestroyAclList _PARAMS((struct _acl_list * list));
static void aclDestroyIpList _PARAMS((struct _acl_ip_data * data));
static void aclDestroyTimeList _PARAMS((struct _acl_time_data * data));
static int aclMatchDomainList _PARAMS((wordlist *, const char *));
static int aclMatchAclList _PARAMS((const struct _acl_list *, aclCheck_t *));
static int aclMatchInteger _PARAMS((intlist * data, int i));
static int aclMatchTime _PARAMS((struct _acl_time_data * data, time_t when));
static int aclMatchIdent _PARAMS((wordlist * data, const char *ident));
static squid_acl aclType _PARAMS((const char *s));
static int decode_addr _PARAMS((const char *, struct in_addr *, struct in_addr *));
static void aclParseIpList _PARAMS((void *curlist));
static void aclParseDomainList _PARAMS((void *curlist));
static void aclParseIntlist _PARAMS((void *curlist));
static void aclParseWordList _PARAMS((void *curlist));
static void aclParseProtoList _PARAMS((void *curlist));
static void aclParseMethodList _PARAMS((void *curlist));
static void aclParseTimeSpec _PARAMS((void *curlist));

char *
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
		debug(28, 0, "strtokFile: %s not found\n", fn);
		return (NULL);
	    }
	    aclFromFile = 1;
	} else {
	    return (t);
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
	return (t);
    }
}

static squid_acl
aclType(const char *s)
{
    if (!strcmp(s, "src"))
	return ACL_SRC_IP;
    if (!strcmp(s, "dst"))
	return ACL_DST_IP;
    if (!strcmp(s, "domain"))
	return ACL_DST_DOMAIN;
    if (!strcmp(s, "dstdomain"))
	return ACL_DST_DOMAIN;
    if (!strcmp(s, "srcdomain"))
	return ACL_SRC_DOMAIN;
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
    if (!strcmp(s, "user"))
	return ACL_USER;
    if (!strncmp(s, "proto", 5))
	return ACL_PROTO;
    if (!strcmp(s, "method"))
	return ACL_METHOD;
    if (!strcmp(s, "browser"))
	return ACL_BROWSER;
    return ACL_NONE;
}

struct _acl *
aclFindByName(const char *name)
{
    struct _acl *a;
    for (a = AclList; a; a = a->next)
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
	q = xcalloc(1, sizeof(intlist));
	q->i = atoi(t);
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
	q = xcalloc(1, sizeof(intlist));
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
	q = xcalloc(1, sizeof(intlist));
	q->i = (int) urlParseMethod(t);
	if (q->i == METHOD_PURGE)
	    Config.Options.enable_purge = 1;
	*(Tail) = q;
	Tail = &q->next;
    }
}

/* Decode a ascii representation (asc) of a IP adress, and place
 * adress and netmask information in addr and mask.
 */
static int
decode_addr(const char *asc, struct in_addr *addr, struct in_addr *mask)
{
    u_num32 a = 0;
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0;
    struct hostent *hp = NULL;

    switch (sscanf(asc, "%d.%d.%d.%d", &a1, &a2, &a3, &a4)) {
    case 4:			/* a dotted quad */
	if ((a = (u_num32) inet_addr(asc)) != inaddr_none ||
	    !strcmp(asc, "255.255.255.255")) {
	    addr->s_addr = a;
	    /* inet_addr() outputs in network byte order */
	}
	break;
    case 1:			/* a significant bits value for a mask */
	if (a1 >= 0 && a1 < 33) {
	    addr->s_addr = a1 ? htonl(0xfffffffful << (32 - a1)) : 0;
	    break;
	}
    default:
	/* Note, must use plain gethostbyname() here because at startup
	 * ipcache hasn't been initialized */
	if ((hp = gethostbyname(asc)) != NULL) {
	    *addr = inaddrFromHostent(hp);
	} else {
	    /* XXX: Here we could use getnetbyname */
	    debug(28, 0, "decode_addr: Invalid IP address or hostname '%s'\n", asc);
	    return 0;		/* This is not valid address */
	}
	break;
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

static struct _acl_ip_data *
aclParseIpData(const char *t)
{
    LOCAL_ARRAY(char, addr1, 256);
    LOCAL_ARRAY(char, addr2, 256);
    LOCAL_ARRAY(char, mask, 256);
    struct _acl_ip_data *q = xcalloc(1, sizeof(struct _acl_ip_data));
    if (!strcasecmp(t, "all")) {
	q->addr1.s_addr = 0;
	q->addr2.s_addr = 0;
	q->mask.s_addr = 0;
	return q;
    }
    if (sscanf(t, "%[0-9.]-%[0-9.]/%[0-9.]", addr1, addr2, mask) == 3) {
	(void) 0;
    } else if (sscanf(t, "%[0-9.]-%[0-9.]", addr1, addr2) == 2) {
	mask[0] = '\0';
    } else if (sscanf(t, "%[0-9.]/%[0-9.]", addr1, mask) == 2) {
	addr2[0] = '\0';
    } else if (sscanf(t, "%[0-9.]", addr1) == 1) {
	addr2[0] = '\0';
	mask[0] = '\0';
    } else if (sscanf(t, "%[^/]/%s", addr1, mask) == 2) {
	addr2[0] = '\0';
    } else if (sscanf(t, "%s", addr1) == 1) {
	addr2[0] = '\0';
	mask[0] = '\0';
    } else {
	debug(28, 0, "aclParseIpData: Bad host/IP: '%s'\n", t);
	safe_free(q);
	return NULL;
    }
    /* Decode addr1 */
    if (!decode_addr(addr1, &q->addr1, &q->mask)) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseIpData: Ignoring invalid IP acl entry: unknown first address '%s'\n", addr1);
	safe_free(q);
	return NULL;
    }
    /* Decode addr2 */
    if (*addr2 && !decode_addr(addr2, &q->addr2, &q->mask)) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseIpData: Ignoring invalid IP acl entry: unknown second address '%s'\n", addr2);
	safe_free(q);
	return NULL;
    }
    /* Decode mask */
    if (*mask && !decode_addr(mask, &q->mask, NULL)) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseIpData: Ignoring invalid IP acl entry: unknown netmask '%s'\n", mask);
	safe_free(q);
	return NULL;
    }
    q->addr1.s_addr &= q->mask.s_addr;
    q->addr2.s_addr &= q->mask.s_addr;
    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
    return q;
}

#ifdef USE_SPLAY_TREE

static void
aclParseIpList(void *curlist)
{
    char *t = NULL;
    struct _acl_ip_data **ip_data = curlist;
    struct _acl_ip_data *q = NULL;
    while ((t = strtokFile())) {
	if ((q = aclParseIpData(t)) == NULL)
	    continue;
	*ip_data = aclSplayInsertIp(q, *ip_data);
    }
}

#else

static void
aclParseIpList(void *curlist)
{
    char *t = NULL;
    struct _acl_ip_data **Tail;
    struct _acl_ip_data *q = NULL;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	if ((q = aclParseIpData(t)) == NULL)
	    continue;
	*(Tail) = q;
	Tail = &q->next;
    }
}

#endif

#ifdef USE_SPLAY_TREE
static int
aclSplayIpCompare(struct in_addr addr, struct _acl_ip_data *data)
{
    int rc = 0;
    addr.s_addr &= data->mask.s_addr;	/* apply netmask */
    if (data->addr2.s_addr == 0) {	/* single address check */
	if (addr.s_addr > data->addr1.s_addr)
	    rc = 1;
	else if (addr.s_addr < data->addr1.s_addr)
	    rc = -1;
	else
	    rc = 0;
    } else {			/* range address check */
	if (addr.s_addr > data->addr2.s_addr)
	    rc = 1;
	else if (addr.s_addr < data->addr1.s_addr)
	    rc = -1;
	else
	    rc = 0;
    }
    return rc;
}

static struct _acl_ip_data *
aclSplayInsertIp(struct _acl_ip_data *q, struct _acl_ip_data *t)
{
    struct _acl_ip_data *new;
    new = xmalloc(sizeof(struct _acl_ip_data));
    new->addr1 = q->addr1;
    new->addr2 = q->addr2;
    new->mask = q->mask;
    if (t == NULL) {
	new->left = new->right = NULL;
	return new;
    }
    t = aclSplayIp(q->addr1, t);
    if (aclCompIpResult < 0) {
	new->left = t->left;
	new->right = t;
	t->left = NULL;
	return new;
    } else if (aclCompIpResult > 0) {
	new->right = t->right;
	new->left = t;
	t->right = NULL;
	return new;
    } else {
	debug_trap("aclSplayInsertIp: entry duplicated\n");
	safe_free(new);
	return t;
    }
}

static struct _acl_ip_data *
aclSplayIp(struct in_addr addr1, struct _acl_ip_data *t)
{
    struct _acl_ip_data N;
    struct _acl_ip_data *l;
    struct _acl_ip_data *r;
    struct _acl_ip_data *y;
    if (t == NULL)
	return t;
    N.left = N.right = NULL;
    l = r = &N;

    for (;;) {
	aclCompIpResult = aclSplayIpCompare(addr1, t);
	if (aclCompIpResult < 0) {
	    if (t->left == NULL)
		break;
	    if (aclSplayIpCompare(addr1, t->left) < 0) {
		y = t->left;	/* rotate right */
		t->left = y->right;
		y->right = t;
		t = y;
		if (t->left == NULL)
		    break;
	    }
	    r->left = t;	/* link right */
	    r = t;
	    t = t->left;
	} else if (aclCompIpResult > 0) {
	    if (t->right == NULL)
		break;
	    if (aclSplayIpCompare(addr1, t->right) > 0) {
		y = t->right;	/* rotate left */
		t->right = y->left;
		y->left = t;
		t = y;
		if (t->right == NULL)
		    break;
	    }
	    l->right = t;	/* link left */
	    l = t;
	    t = t->right;
	} else {
	    break;
	}
    }
    l->right = t->left;		/* assemble */
    r->left = t->right;
    t->left = N.right;
    t->right = N.left;
    return t;
}
#endif /* USE_SPLAY_TREE */

static void
aclParseTimeSpec(void *curlist)
{
    struct _acl_time_data *q = NULL;
    struct _acl_time_data **Tail;
    int h1, m1, h2, m2;
    char *t = NULL;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    q = xcalloc(1, sizeof(struct _acl_time_data));
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
		default:
		    debug(28, 0, "%s line %d: %s\n",
			cfg_filename, config_lineno, config_input_line);
		    debug(28, 0, "aclParseTimeSpec: Bad Day '%c'\n",
			*t);
		    break;
		}
	    }
	} else {
	    /* assume its time-of-day spec */
	    if (sscanf(t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4) {
		debug(28, 0, "%s line %d: %s\n",
		    cfg_filename, config_lineno, config_input_line);
		debug(28, 0, "aclParseTimeSpec: Bad time range '%s'\n",
		    t);
		xfree(q);
		return;
	    }
	    q->start = h1 * 60 + m1;
	    q->stop = h2 * 60 + m2;
	    if (q->start > q->stop) {
		debug(28, 0, "%s line %d: %s\n",
		    cfg_filename, config_lineno, config_input_line);
		debug(28, 0, "aclParseTimeSpec: Reversed time range '%s'\n",
		    t);
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
aclParseRegexList(void *curlist, int icase)
{
    relist **Tail;
    relist *q = NULL;
    char *t = NULL;
    regex_t comp;
    int errcode;
    int flags = REG_EXTENDED | REG_NOSUB;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    if (icase)
	flags |= REG_ICASE;
    while ((t = strtokFile())) {
	if ((errcode = regcomp(&comp, t, flags)) != 0) {
	    char errbuf[256];
	    regerror(errcode, &comp, errbuf, sizeof errbuf);
	    debug(28, 0, "%s line %d: %s\n",
		cfg_filename, config_lineno, config_input_line);
	    debug(28, 0, "aclParseRegexList: Invalid regular expression '%s': %s\n",
		t, errbuf);
	    continue;
	}
	q = xcalloc(1, sizeof(relist));
	q->pattern = xstrdup(t);
	q->regex = comp;
	*(Tail) = q;
	Tail = &q->next;
    }
}

static void
aclParseWordList(void *curlist)
{
    wordlist **Tail;
    wordlist *q = NULL;
    char *t = NULL;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	q = xcalloc(1, sizeof(wordlist));
	q->key = xstrdup(t);
	*(Tail) = q;
	Tail = &q->next;
    }
}


static void
aclParseDomainList(void *curlist)
{
    wordlist **Tail;
    wordlist *q = NULL;
    char *t = NULL;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	Tolower(t);
	q = xcalloc(1, sizeof(wordlist));
	q->key = xstrdup(t);
	*(Tail) = q;
	Tail = &q->next;
    }
}


void
aclParseAclLine(void)
{
    /* we're already using strtok() to grok the line */
    char *t = NULL;
    struct _acl *A = NULL;
    LOCAL_ARRAY(char, aclname, ACL_NAME_SZ);
    squid_acl acltype;

    /* snarf the ACL name */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: missing ACL name.\n");
	return;
    }
    xstrncpy(aclname, t, ACL_NAME_SZ);
    /* snarf the ACL type */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: missing ACL type.\n");
	return;
    }
    if ((acltype = aclType(t)) == ACL_NONE) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: Invalid ACL type '%s'\n", t);
	return;
    }
    if ((A = aclFindByName(aclname)) == NULL) {
	debug(28, 3, "aclParseAclLine: Creating ACL '%s'\n", aclname);
	A = xcalloc(1, sizeof(struct _acl));
	xstrncpy(A->name, aclname, ACL_NAME_SZ);
	A->type = acltype;
	A->cfgline = xstrdup(config_input_line);
	*AclListTail = A;
	AclListTail = &A->next;
    } else {
	if (acltype != A->type) {
	    debug(28, 0, "aclParseAclLine: ACL '%s' already exists with different type, skipping.\n", A->name);
	    return;
	}
	debug(28, 3, "aclParseAclLine: Appending to '%s'\n", aclname);
    }
    switch (A->type) {
    case ACL_SRC_IP:
    case ACL_DST_IP:
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
	aclParseRegexList(&A->data, 0);
	break;
    case ACL_URL_PORT:
	aclParseIntlist(&A->data);
	break;
    case ACL_USER:
	Config.identLookup = 1;
	aclParseWordList(&A->data);
	break;
    case ACL_PROTO:
	aclParseProtoList(&A->data);
	break;
    case ACL_METHOD:
	aclParseMethodList(&A->data);
	break;
    case ACL_BROWSER:
	aclParseRegexList(&A->data, 0);
	break;
    case ACL_NONE:
    default:
	debug_trap("Bad ACL type");
	break;
    }
}

/* maex@space.net (06.09.96)
 *    get (if any) the URL from deny_info for a certain acl
 */
char *
aclGetDenyInfoUrl(struct _acl_deny_info_list **head, const char *name)
{
    struct _acl_deny_info_list *A = NULL;
    struct _acl_name_list *L = NULL;

    A = *head;
    if (NULL == *head)		/* empty list */
	return (NULL);
    while (A) {
	L = A->acl_list;
	if (NULL == L)		/* empty list should never happen, but in case */
	    continue;
	while (L) {
	    if (!strcmp(name, L->name))
		return (A->url);
	    L = L->next;
	}
	A = A->next;
    }
    return (NULL);
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
aclParseDenyInfoLine(struct _acl_deny_info_list **head)
{
    char *t = NULL;
    struct _acl_deny_info_list *A = NULL;
    struct _acl_deny_info_list *B = NULL;
    struct _acl_deny_info_list **T = NULL;
    struct _acl_name_list *L = NULL;
    struct _acl_name_list **Tail = NULL;

    /* first expect an url */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseDenyInfoLine: missing 'url' parameter.\n");
	return;
    }
    A = xcalloc(1, sizeof(struct _acl_deny_info_list));
    xstrncpy(A->url, t, MAX_URL);
    A->next = (struct _acl_deny_info_list *) NULL;
    /* next expect a list of ACL names */
    Tail = &A->acl_list;
    while ((t = strtok(NULL, w_space))) {
	L = xcalloc(1, sizeof(struct _acl_name_list));
	xstrncpy(L->name, t, ACL_NAME_SZ);
	*Tail = L;
	Tail = &L->next;
    }
    if (A->acl_list == NULL) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseDenyInfoLine: deny_info line contains no ACL's, skipping\n");
	xfree(A);
	return;
    }
    for (B = *head, T = head; B; T = &B->next, B = B->next);	/* find the tail */
    *T = A;
}

void
aclParseAccessLine(struct _acl_access **head)
{
    char *t = NULL;
    struct _acl_access *A = NULL;
    struct _acl_access *B = NULL;
    struct _acl_access **T = NULL;
    struct _acl_list *L = NULL;
    struct _acl_list **Tail = NULL;
    struct _acl *a = NULL;

    /* first expect either 'allow' or 'deny' */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseAccessLine: missing 'allow' or 'deny'.\n");
	return;
    }
    A = xcalloc(1, sizeof(struct _acl_access));
    if (!strcmp(t, "allow"))
	A->allow = 1;
    else if (!strcmp(t, "deny"))
	A->allow = 0;
    else {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseAccessLine: expecting 'allow' or 'deny', got '%s'.\n", t);
	xfree(A);
	return;
    }

    /* next expect a list of ACL names, possibly preceeded
     * by '!' for negation */
    Tail = &A->acl_list;
    while ((t = strtok(NULL, w_space))) {
	L = xcalloc(1, sizeof(struct _acl_list));
	L->op = 1;		/* defaults to non-negated */
	if (*t == '!') {
	    /* negated ACL */
	    L->op = 0;
	    t++;
	}
	debug(28, 3, "aclParseAccessLine: looking for ACL name '%s'\n", t);
	a = aclFindByName(t);
	if (a == NULL) {
	    debug(28, 0, "%s line %d: %s\n",
		cfg_filename, config_lineno, config_input_line);
	    debug(28, 0, "aclParseAccessLine: ACL name '%s' not found.\n", t);
	    xfree(L);
	    continue;
	}
	L->acl = a;
	*Tail = L;
	Tail = &L->next;
    }
    if (A->acl_list == NULL) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseAccessLine: Access line contains no ACL's, skipping\n");
	xfree(A);
	return;
    }
    A->cfgline = xstrdup(config_input_line);
    for (B = *head, T = head; B; T = &B->next, B = B->next);	/* find the tail */
    *T = A;
}

static int
#ifndef USE_SPLAY_TREE
aclMatchIp(struct _acl_ip_data *data, struct in_addr c)
#else
aclMatchIp(void *dataptr, struct in_addr c)
#endif				/* USE_SPLAY_TREE */
{
#ifndef USE_SPLAY_TREE
    struct in_addr h;
    unsigned long lh, la1, la2;
    struct _acl_ip_data *first, *prev;

    first = data;		/* remember first element, this will never be moved */
    prev = NULL;		/* previous element in the list */
    while (data) {
	h.s_addr = c.s_addr & data->mask.s_addr;
	debug(28, 3, "aclMatchIp: h     = %s\n", inet_ntoa(h));
	debug(28, 3, "aclMatchIp: addr1 = %s\n", inet_ntoa(data->addr1));
	debug(28, 3, "aclMatchIp: addr2 = %s\n", inet_ntoa(data->addr2));
	if (!data->addr2.s_addr) {
	    if (h.s_addr == data->addr1.s_addr) {
		debug(28, 3, "aclMatchIp: returning 1\n");
		if (prev != NULL) {
		    /* shift the element just found to the second position
		     * in the list */
		    prev->next = data->next;
		    data->next = first->next;
		    first->next = data;
		}
		return 1;
	    }
	} else {
	    /* This is a range check */
	    lh = ntohl(h.s_addr);
	    la1 = ntohl(data->addr1.s_addr);
	    la2 = ntohl(data->addr2.s_addr);
	    if (lh >= la1 && lh <= la2) {
		debug(28, 3, "aclMatchIp: returning 1\n");
		return 1;
	    }
	}
	prev = data;
	data = data->next;
    }
    debug(28, 3, "aclMatchIp: returning 0\n");
    return 0;
#else
    struct _acl_ip_data **data = dataptr;
    *data = aclSplayIp(c, *data);
    return !aclCompIpResult;
#endif /* USE_SPLAY_TREE */
}

static int
aclMatchDomainList(wordlist * data, const char *host)
{
    wordlist *first, *prev;

    if (host == NULL)
	return 0;
    debug(28, 3, "aclMatchDomainList: checking '%s'\n", host);
    first = data;
    prev = NULL;
    for (; data; data = data->next) {
	debug(28, 3, "aclMatchDomainList: looking for '%s'\n", data->key);
	if (matchDomainName(data->key, host)) {
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
    }
    return 0;
}

int
aclMatchRegex(relist * data, const char *word)
{
    relist *first, *prev;
    if (word == NULL)
	return 0;
    debug(28, 3, "aclMatchRegex: checking '%s'\n", word);
    first = data;
    prev = NULL;
    while (data) {
	debug(28, 3, "aclMatchRegex: looking for '%s'\n", data->pattern);
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
aclMatchIdent(wordlist * data, const char *ident)
{
    if (ident == NULL)
	return 0;
    debug(28, 3, "aclMatchIdent: checking '%s'\n", ident);
    while (data) {
	debug(28, 3, "aclMatchIdent: looking for '%s'\n", data->key);
	if (strcmp(data->key, "REQUIRED") == 0 && *ident != '\0')
	    return 1;
	if (strcmp(data->key, ident) == 0)
	    return 1;
	data = data->next;
    }
    return 0;
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
aclMatchTime(struct _acl_time_data *data, time_t when)
{
    static time_t last_when = 0;
    static struct tm tm;
    time_t t;

    if (when != last_when) {
	last_when = when;
	xmemcpy(&tm, localtime(&when), sizeof(struct tm));
    }
    t = (time_t) (tm.tm_hour * 60 + tm.tm_min);
    debug(28, 3, "aclMatchTime: checking %d in %d-%d, weekbits=%x\n",
	(int) t, (int) data->start, (int) data->stop, data->weekbits);

    if (t < data->start || t > data->stop)
	return 0;
    return data->weekbits & (1 << tm.tm_wday) ? 1 : 0;
}

int
aclMatchAcl(struct _acl *acl, aclCheck_t * checklist)
{
    const request_t *r = checklist->request;
    const ipcache_addrs *ia = NULL;
    const char *fqdn = NULL;
    int k;
    if (!acl)
	return 0;
    debug(28, 3, "aclMatchAcl: checking '%s'\n", acl->cfgline);
    switch (acl->type) {
    case ACL_SRC_IP:
#ifndef USE_SPLAY_TREE
	return aclMatchIp(acl->data, checklist->src_addr);
#else
	return aclMatchIp(&acl->data, checklist->src_addr);
#endif /* USE_SPLAY_TREE */
	/* NOTREACHED */
    case ACL_DST_IP:
	ia = ipcache_gethostbyname(r->host, IP_LOOKUP_IF_MISS);
	if (ia) {
	    for (k = 0; k < (int) ia->count; k++) {
		checklist->dst_addr = ia->in_addrs[k];
#ifndef USE_SPLAY_TREE
		if (aclMatchIp(acl->data, checklist->dst_addr))
#else
		if (aclMatchIp(&acl->data, checklist->dst_addr))
#endif /* USE_SPLAY_TREE */
		    return 1;
	    }
	    return 0;
	} else if (checklist->state[ACL_DST_IP] == ACL_LOOKUP_NONE) {
	    debug(28, 3, "aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		acl->name, r->host);
	    checklist->state[ACL_DST_IP] = ACL_LOOKUP_NEED;
	    return 0;
	} else {
#ifndef USE_SPLAY_TREE
	    return aclMatchIp(acl->data, no_addr);
#else
	    return aclMatchIp(&acl->data, no_addr);
#endif /* USE_SPLAY_TREE */
	}
	/* NOTREACHED */
    case ACL_DST_DOMAIN:
	if ((ia = ipcacheCheckNumeric(r->host)) == NULL)
	    return aclMatchDomainList(acl->data, r->host);
	fqdn = fqdncache_gethostbyaddr(ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
	if (fqdn)
	    return aclMatchDomainList(acl->data, fqdn);
	if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3, "aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		acl->name, inet_ntoa(ia->in_addrs[0]));
	    checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEED;
	    return 0;
	}
	return aclMatchDomainList(acl->data, "none");
	/* NOTREACHED */
    case ACL_SRC_DOMAIN:
	fqdn = fqdncache_gethostbyaddr(checklist->src_addr, FQDN_LOOKUP_IF_MISS);
	if (fqdn) {
	    return aclMatchDomainList(acl->data, fqdn);
	} else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE) {
	    debug(28, 3, "aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
		acl->name, inet_ntoa(checklist->src_addr));
	    checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEED;
	    return 0;
	} else {
	    return aclMatchDomainList(acl->data, "none");
	}
	/* NOTREACHED */
    case ACL_TIME:
	return aclMatchTime(acl->data, squid_curtime);
	/* NOTREACHED */
    case ACL_URLPATH_REGEX:
	return aclMatchRegex(acl->data, r->urlpath);
	/* NOTREACHED */
    case ACL_URL_REGEX:
	return aclMatchRegex(acl->data, urlCanonical(r, NULL));
	/* NOTREACHED */
    case ACL_URL_PORT:
	return aclMatchInteger(acl->data, r->port);
	/* NOTREACHED */
    case ACL_USER:
	/* debug(28, 0, "aclMatchAcl: ACL_USER unimplemented\n"); */
	/* return 0; */
	return aclMatchIdent(acl->data, checklist->ident);
	/* NOTREACHED */
    case ACL_PROTO:
	return aclMatchInteger(acl->data, r->protocol);
	/* NOTREACHED */
    case ACL_METHOD:
	return aclMatchInteger(acl->data, r->method);
	/* NOTREACHED */
    case ACL_BROWSER:
	return aclMatchRegex(acl->data, checklist->browser);
	/* NOTREACHED */
    case ACL_NONE:
    default:
	debug(28, 0, "aclMatchAcl: '%s' has bad type %d\n",
	    acl->name, acl->type);
	return 0;
    }
    /* NOTREACHED */
}

static int
aclMatchAclList(const struct _acl_list *list, aclCheck_t * checklist)
{
    while (list) {
	AclMatchedName = list->acl->name;
	debug(28, 3, "aclMatchAclList: checking %s%s\n",
	    list->op ? null_string : "!", list->acl->name);
	if (aclMatchAcl(list->acl, checklist) != list->op) {
	    debug(28, 3, "aclMatchAclList: returning 0\n");
	    return 0;
	}
	list = list->next;
    }
    debug(28, 3, "aclMatchAclList: returning 1\n");
    return 1;
}

int
aclCheck(const struct _acl_access *A, aclCheck_t * checklist)
{
    int allow = 0;

    while (A) {
	debug(28, 3, "aclCheck: checking '%s'\n", A->cfgline);
	allow = A->allow;
	if (aclMatchAclList(A->acl_list, checklist)) {
	    debug(28, 3, "aclCheck: match found, returning %d\n", allow);
	    return allow;
	}
	A = A->next;
    }
    return !allow;
}

#ifdef USE_SPLAY_TREE
static void
aclDestroyIpList(struct _acl_ip_data *data)
{
    if (data == NULL)
	return;
    aclDestroyIpList(data->left);
    aclDestroyIpList(data->right);
    safe_free(data);
}

#else

static void
aclDestroyIpList(struct _acl_ip_data *data)
{
    struct _acl_ip_data *next = NULL;
    for (; data; data = next) {
	next = data->next;
	safe_free(data);
    }
}
#endif

static void
aclDestroyTimeList(struct _acl_time_data *data)
{
    struct _acl_time_data *next = NULL;
    for (; data; data = next) {
	next = data->next;
	safe_free(data);
    }
}

void
aclDestroyRegexList(struct _relist *data)
{
    struct _relist *next = NULL;
    for (; data; data = next) {
	next = data->next;
	regfree(&data->regex);
	safe_free(data->pattern);
	safe_free(data);
    }
}

void
aclDestroyAcls(void)
{
    struct _acl *a = NULL;
    struct _acl *next = NULL;
    for (a = AclList; a; a = next) {
	next = a->next;
	debug(28, 3, "aclDestroyAcls: '%s'\n", a->cfgline);
	switch (a->type) {
	case ACL_SRC_IP:
	case ACL_DST_IP:
	    aclDestroyIpList(a->data);
	    break;
	case ACL_DST_DOMAIN:
	case ACL_SRC_DOMAIN:
	case ACL_USER:
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
	case ACL_URL_PORT:
	case ACL_PROTO:
	case ACL_METHOD:
	    intlistDestroy((intlist **) & a->data);
	    break;
	case ACL_NONE:
	default:
	    fatal_dump("aclDestroyAcls: Found ACL_NONE?");
	    break;
	}
	safe_free(a->cfgline);
	safe_free(a);
    }
    AclList = NULL;
    AclListTail = &AclList;
}

static void
aclDestroyAclList(struct _acl_list *list)
{
    struct _acl_list *next = NULL;
    for (; list; list = next) {
	next = list->next;
	safe_free(list);
    }
}

void
aclDestroyAccessList(struct _acl_access **list)
{
    struct _acl_access *l = NULL;
    struct _acl_access *next = NULL;
    for (l = *list; l; l = next) {
	debug(28, 3, "aclDestroyAccessList: '%s'\n", l->cfgline);
	next = l->next;
	aclDestroyAclList(l->acl_list);
	l->acl_list = NULL;
	safe_free(l->cfgline);
	safe_free(l);
    }
    *list = NULL;
}

/* maex@space.net (06.09.1996)
 *    destroy an _acl_deny_info_list */
void
aclDestroyDenyInfoList(struct _acl_deny_info_list **list)
{
    struct _acl_deny_info_list *a = NULL;
    struct _acl_deny_info_list *a_next = NULL;
    struct _acl_name_list *l = NULL;
    struct _acl_name_list *l_next = NULL;

    for (a = *list; a; a = a_next) {
	for (l = a->acl_list; l; l = l_next) {
	    l_next = l->next;
	    safe_free(l);
	}
	a_next = a->next;
	safe_free(a);
    }
    *list = NULL;
}
