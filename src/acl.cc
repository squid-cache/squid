#ident "$Id: acl.cc,v 1.8 1996/04/11 22:52:24 wessels Exp $"

/*
 * DEBUG: Section 28          acl
 */

#include "squid.h"

/* These two should never be referenced directly in this file! */
struct _acl_access *HTTPAccessList = NULL;
struct _acl_access *ICPAccessList = NULL;

static struct _acl *AclList = NULL;
static struct _acl **AclListTail = &AclList;

static int aclMatchAcl _PARAMS((struct _acl *, struct in_addr, method_t, protocol_t, char *host, int port, char *request));
static int aclMatchAclList _PARAMS((struct _acl_list *, struct in_addr, method_t, protocol_t, char *host, int port, char *request));

static acl_t aclType(s)
     char *s;
{
    if (!strcmp(s, "src"))
	return ACL_SRC_IP;
    if (!strcmp(s, "domain"))
	return ACL_DST_DOMAIN;
    if (!strcmp(s, "time"))
	return ACL_TIME;
    if (!strcmp(s, "pattern"))
	return ACL_URL_REGEX;
    if (!strcmp(s, "port"))
	return ACL_URL_PORT;
    if (!strcmp(s, "user"))
	return ACL_USER;
    if (!strcmp(s, "proto"))
	return ACL_PROTO;
    if (!strcmp(s, "method"))
	return ACL_METHOD;
    return ACL_NONE;
}

struct _acl *aclFindByName(name)
     char *name;
{
    struct _acl *a;
    for (a = AclList; a; a = a->next)
	if (!strcasecmp(a->name, name))
	    return a;
    return NULL;
}


intlist *aclParseIntlist()
{
    intlist *head = NULL;
    intlist **Tail = &head;
    intlist *q = NULL;
    char *t = NULL;
    while ((t = strtok(NULL, w_space))) {
	q = (intlist *) xcalloc(1, sizeof(intlist));
	q->i = atoi(t);
	*(Tail) = q;
	Tail = &q->next;
    }
    return head;
}

intlist *aclParseProtoList()
{
    intlist *head = NULL;
    intlist **Tail = &head;
    intlist *q = NULL;
    char *t = NULL;
    while ((t = strtok(NULL, w_space))) {
	q = (intlist *) xcalloc(1, sizeof(intlist));
	q->i = (int) urlParseProtocol(t);
	*(Tail) = q;
	Tail = &q->next;
    }
    return head;
}

intlist *aclParseMethodList()
{
    intlist *head = NULL;
    intlist **Tail = &head;
    intlist *q = NULL;
    char *t = NULL;
    while ((t = strtok(NULL, w_space))) {
	q = (intlist *) xcalloc(1, sizeof(intlist));
	q->i = (int) urlParseMethod(t);
	*(Tail) = q;
	Tail = &q->next;
    }
    return head;
}

struct _acl_ip_data *aclParseIpList()
{
    char *t = NULL;
    struct _acl_ip_data *head = NULL;
    struct _acl_ip_data **Tail = &head;
    struct _acl_ip_data *q = NULL;
    int a1, a2, a3, a4;
    int m1, m2, m3, m4;
    struct in_addr lmask;
    int c;

    while ((t = strtok(NULL, w_space))) {
	q = (struct _acl_ip_data *) xcalloc(1, sizeof(struct _acl_ip_data));
	a1 = a2 = a3 = a4 = 0;
	if (!strcasecmp(t, "all")) {
	    lmask.s_addr = 0;
	} else {
	    c = sscanf(t, "%d.%d.%d.%d/%d.%d.%d.%d",
		&a1, &a2, &a3, &a4,
		&m1, &m2, &m3, &m4);
	    switch (c) {
	    case 4:
		if (a1 == 0 && a2 == 0 && a3 == 0 && a4 == 0)	/* world   */
		    lmask.s_addr = 0x00000000;
		else if (a2 == 0 && a3 == 0 && a4 == 0)		/* class A */
		    lmask.s_addr = htonl(0xff000000);
		else if (a3 == 0 && a4 == 0)	/* class B */
		    lmask.s_addr = htonl(0xffff0000);
		else if (a4 == 0)	/* class C */
		    lmask.s_addr = htonl(0xffffff00);
		else
		    lmask.s_addr = 0xffffffff;
		break;
	    case 5:
		if (m1 < 0 || m1 > 32) {
	            debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
		    debug(28, 0, "aclParseIpList: Ignoring invalid IP acl entry '%s'\n", t);
		    safe_free(q);
		    continue;
		}
		lmask.s_addr = htonl(0xffffffff << (32 - m1));
		break;
	    case 8:
		lmask.s_addr = htonl(m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4);
		break;
	    default:
	        debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
		debug(28, 0, "aclParseIpList: Ignoring invalid IP acl entry '%s'\n", t);
		safe_free(q);
		continue;
	    }
	}
	q->addr1.s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);
	q->mask1.s_addr = lmask.s_addr;
	*(Tail) = q;
	Tail = &q->next;
    }
    return head;
}

struct _acl_time_data *aclParseTimeSpec()
{
    struct _acl_time_data *data = NULL;
    int h1, m1, h2, m2;
    char *t = NULL;

    data = (struct _acl_time_data *) xcalloc(1, sizeof(struct _acl_time_data));
    while ((t = strtok(NULL, w_space))) {
	if (*t < '0' || *t > '9') {
	    /* assume its day-of-week spec */
	    while (*t) {
		switch (*t++) {
		case 'S':
		    data->weekbits |= ACL_SUNDAY;
		    break;
		case 'M':
		    data->weekbits |= ACL_MONDAY;
		    break;
		case 'T':
		    data->weekbits |= ACL_TUESDAY;
		    break;
		case 'W':
		    data->weekbits |= ACL_WEDNESDAY;
		    break;
		case 'H':
		    data->weekbits |= ACL_THURSDAY;
		    break;
		case 'F':
		    data->weekbits |= ACL_FRIDAY;
		    break;
		case 'A':
		    data->weekbits |= ACL_SATURDAY;
		    break;
		default:
		    debug(28, 0, "cached.conf line %d: %s\n",
			config_lineno,
			config_input_line);
		    debug(28, 0, "aclParseTimeSpec: Bad Day '%c'\n",
			*t);
		    break;
		}
	    }
	} else {
	    /* assume its time-of-day spec */
	    if (sscanf(t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4) {
		debug(28, 0, "cached.conf line %d: %s\n",
		    config_lineno,
		    config_input_line);
		debug(28, 0, "aclParseTimeSpec: Bad time range '%s'\n",
		    t);
		xfree(&data);
		return NULL;
	    }
	    data->start = h1 * 60 + m1;
	    data->stop = h2 * 60 + m2;
	    if (data->start > data->stop) {
		debug(28, 0, "cached.conf line %d: %s\n",
		    config_lineno,
		    config_input_line);
		debug(28, 0, "aclParseTimeSpec: Reversed time range '%s'\n",
		    t);
		xfree(&data);
		return NULL;
	    }
	}
    }
    if (data->start == 0 && data->stop == 0)
	data->stop = 23 * 60 + 59;
    if (data->weekbits == 0)
	data->weekbits = ACL_ALLWEEK;
    return data;
}

struct _relist *aclParseRegexList()
{
    relist *head = NULL;
    relist **Tail = &head;
    relist *q = NULL;
    char *t = NULL;
    regex_t comp;
    while ((t = strtok(NULL, w_space))) {
	if (regcomp(&comp, t, REG_EXTENDED) != REG_NOERROR) {
	    debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	    debug(28, 0, "aclParseRegexList: Invalid regular expression: '%s'\n", t);
	    continue;
	}
	q = (relist *) xcalloc(1, sizeof(relist));
	q->pattern = xstrdup(t);
	q->regex = comp;
	*(Tail) = q;
	Tail = &q->next;
    }
    return head;
}

wordlist *aclParseWordList()
{
    wordlist *head = NULL;
    wordlist **Tail = &head;
    wordlist *q = NULL;
    char *t = NULL;
    while ((t = strtok(NULL, w_space))) {
	q = (wordlist *) xcalloc(1, sizeof(wordlist));
	q->key = xstrdup(t);
	*(Tail) = q;
	Tail = &q->next;
    }
    return head;
}



void aclParseAclLine()
{
    /* we're already using strtok() to grok the line */
    char *t = NULL;
    struct _acl *A = NULL;

    A = (struct _acl *) xcalloc(1, sizeof(struct _acl));
    /* snarf the ACL name */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: missing ACL name.\n");
	xfree(A);
	return;
    }
    if (aclFindByName(t)) {
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: ACL name '%s' already exists.\n", t);
	xfree(A);
	return;
    }
    strncpy(A->name, t, ACL_NAME_SZ);
    /* snarf the ACL type */
    if ((t = strtok(NULL, w_space)) == NULL) {
	xfree(A);
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: missing ACL type.\n");
	return;
    }
    switch (A->type = aclType(t)) {
    case ACL_SRC_IP:
	A->data = (void *) aclParseIpList();
	break;
    case ACL_DST_DOMAIN:
	A->data = (void *) aclParseWordList();
	break;
    case ACL_TIME:
	A->data = (void *) aclParseTimeSpec();
	break;
    case ACL_URL_REGEX:
	A->data = (void *) aclParseRegexList();
	break;
    case ACL_URL_PORT:
	A->data = (void *) aclParseIntlist();
	break;
    case ACL_USER:
	A->data = (void *) aclParseWordList();
	break;
    case ACL_PROTO:
	A->data = (void *) aclParseProtoList();
	break;
    case ACL_METHOD:
	A->data = (void *) aclParseMethodList();
	break;
    case ACL_NONE:
    default:
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAclLine: Invalid ACL type '%s'\n", t);
	xfree(A);
	return;
	break;
    }
    A->cfgline = xstrdup(config_input_line);
    *AclListTail = A;
    AclListTail = &A->next;
}

void aclParseAccessLine(head)
    struct _acl_access **head;
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
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAccessLine: missing 'allow' or 'deny'.\n");
	return;
    }
    A = (struct _acl_access *) xcalloc(1, sizeof(struct _acl_access));
    if (!strcmp(t, "allow"))
	A->allow = 1;
    else if (!strcmp(t, "deny"))
	A->allow = 0;
    else {
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAccessLine: expecting 'allow' or 'deny', got '%s'.\n", t);
	xfree(A);
	return;
    }

    /* next expect a list of ACL names, possibly preceeded
     * by '!' for negation */
    Tail = &A->acl_list;
    while ((t = strtok(NULL, w_space))) {
	L = (struct _acl_list *) xcalloc(1, sizeof(struct _acl_list));
	L->op = 1;		/* defaults to non-negated */
	if (*t == '!') {
	    /* negated ACL */
	    L->op = 0;
	    t++;
	}
	debug(28, 1, "aclParseAccessLine: looking for ACL name '%s'\n", t);
	a = aclFindByName(t);
	if (a == NULL) {
	    debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	    debug(28, 0, "aclParseAccessLine: ACL name '%s' not found.\n", t);
	    xfree(L);
	    continue;
	}
	L->acl = a;
	*Tail = L;
	Tail = &L->next;
    }
    if (A->acl_list == NULL) {
	debug(28, 0, "cached.conf line %d: %s\n", config_lineno, config_input_line);
	debug(28, 0, "aclParseAccessLine: Access line contains no ACL's, skipping\n");
	xfree(A);
	return;
    }
    A->cfgline = xstrdup(config_input_line);
    for (B=*head, T=head; B; T=&B->next, B=B->next);	/* find the tail */
    *T = A;
}

int aclMatchIp(data, c)
     struct _acl_ip_data *data;
     struct in_addr c;
{
    struct in_addr h;
    while (data) {
	h.s_addr = c.s_addr & data->mask1.s_addr;
	debug(28, 1, "aclMatchIp: h     = %s\n", inet_ntoa(h));
	debug(28, 1, "aclMatchIp: addr1 = %s\n", inet_ntoa(data->addr1));
	if (h.s_addr == data->addr1.s_addr) {
	    debug(28, 1, "aclMatchIp: returning 1\n");
	    return 1;
	}
	data = data->next;
    }
    debug(28, 1, "aclMatchIp: returning 0\n");
    return 0;
}

int aclMatchWord(data, word)
     wordlist *data;
     char *word;
{
    debug(28, 1, "aclMatchWord: checking '%s'\n", word);
    while (data) {
	debug(28, 1, "aclMatchWord: looking for '%s'\n", data->key);
	if (strstr(word, data->key))
	    return 1;
	data = data->next;
    }
    return 0;
}
int aclMatchRegex(data, word)
     relist *data;
     char *word;
{
    debug(28, 1, "aclMatchRegex: checking '%s'\n", word);
    while (data) {
	debug(28, 1, "aclMatchRegex: looking for '%s'\n", data->pattern);
	if (regexec(&data->regex, word, 0, 0, 0) == 0)
	    return 1;
	data = data->next;
    }
    return 0;
}
int aclMatchInteger(data, i)
     intlist *data;
     int i;
{
    while (data) {
	if (data->i == i)
	    return 1;
	data = data->next;
    }
    return 0;
}

int aclMatchTime(data, when)
	struct _acl_time_data *data;
	time_t when;
{
	static time_t last_when = 0;
	static struct tm tm;
	time_t t;

	if (when != last_when) {
		last_when = when;
		memcpy(&tm, localtime(&when), sizeof(struct tm));
	}

	debug(28, 1, "aclMatchTime: checking %d-%d, weekbits=%x\n",
		data->start, data->stop, data->weekbits);

	t = (time_t) (tm.tm_hour * 60 + tm.tm_min);
	if (t < data->start || t > data->stop)
		return 0;
	return data->weekbits & tm.tm_wday ? 1 : 0;
}

static int aclMatchAcl(acl, c, m, pr, h, po, r)
     struct _acl *acl;
     struct in_addr c;
     method_t m;
     protocol_t pr;
     char *h;
     int po;
     char *r;
{
    if (!acl)
	return 0;
    debug(28, 1, "aclMatchAcl: checking '%s'\n", acl->cfgline);
    switch (acl->type) {
    case ACL_SRC_IP:
	return aclMatchIp(acl->data, c);
	break;
    case ACL_DST_DOMAIN:
	return aclMatchWord(acl->data, h);
	break;
    case ACL_TIME:
	return aclMatchTime(acl->data, cached_curtime);
	return 0;
	break;
    case ACL_URL_REGEX:
	return aclMatchRegex(acl->data, r);
	break;
    case ACL_URL_PORT:
	return aclMatchInteger(acl->data, po);
	break;
    case ACL_USER:
	debug(28, 0, "aclMatchAcl: ACL_USER unimplemented\n");
	return 0;
	break;
    case ACL_PROTO:
	return aclMatchInteger(acl->data, pr);
	break;
    case ACL_METHOD:
	return aclMatchInteger(acl->data, m);
	break;
    case ACL_NONE:
    default:
	debug(28, 0, "aclMatchAcl: '%s' has bad type %d\n",
	    acl->name, acl->type);
	return 0;
    }
    fatal_dump("aclMatchAcl: This should never happen.");
    return 0;
}

static int aclMatchAclList(list, c, m, pr, h, po, r)
     struct _acl_list *list;
     struct in_addr c;
     method_t m;
     protocol_t pr;
     char *h;
     int po;
     char *r;
{
    debug(28, 1, "aclMatchAclList: list=%p  op=%d\n", list, list->op);
    while (list) {
	if (aclMatchAcl(list->acl, c, m, pr, h, po, r) != list->op) {
	    debug(28, 1, "aclMatchAclList: returning 0\n");
	    return 0;
	}
	list = list->next;
    }
    debug(28, 1, "aclMatchAclList: returning 1\n");
    return 1;
}

int aclCheck(A, cli_addr, method, proto, host, port, request)
     struct _acl_access *A;
     struct in_addr cli_addr;
     method_t method;
     protocol_t proto;
     char *host;
     int port;
     char *request;
{
    int allow = 0;

    debug(28, 1, "aclCheck: cli_addr=%s\n", inet_ntoa(cli_addr));
    debug(28, 1, "aclCheck: method=%d\n", method);
    debug(28, 1, "aclCheck: proto=%d\n", proto);
    debug(28, 1, "aclCheck: host=%s\n", host);
    debug(28, 1, "aclCheck: port=%d\n", port);
    debug(28, 1, "aclCheck: request=%s\n", request);

    while (A) {
	debug(28, 1, "aclCheck: checking '%s'\n", A->cfgline);
	allow = A->allow;
	if (aclMatchAclList(A->acl_list, cli_addr, method, proto, host, port, request)) {
	    debug(28, 1, "aclCheck: match found, returning %d\n", allow);
	    return allow;
	}
	A = A->next;
    }
    return !allow;
}

static void aclDestroyIpList(data)
	struct _acl_ip_data *data;
{
	struct _acl_ip_data *next;
	for (; data; data=next) {
		next = data->next;
		safe_free(data);
	}
}

static void aclDestroyTimeList(data)
	struct _acl_time_data *data;
{
	struct _acl_time_data *next;
	for (; data; data=next) {
		next = data->next;
		safe_free(data);
	}
}

static void aclDestroyRegexList(data)
	struct _relist *data;
{
	struct _relist *next;
	for (; data; data=next) {
		next = data->next;
		regfree(&data->regex);
		safe_free(data->pattern);
		safe_free(data);
	}
}

void aclDestroyAcls() {
	struct _acl *a = NULL;
	struct _acl *next = NULL;
	for (a=AclList; a; a=next) {
		next = a->next;
		debug(28,1,"aclDestroyAcls: '%s'\n", a->cfgline);
		switch(a->type) {
    		case ACL_SRC_IP:
			aclDestroyIpList(a->data);
			break;
    		case ACL_DST_DOMAIN:
    		case ACL_USER:
			wordlistDestroy((wordlist **) &a->data);
			break;
    		case ACL_TIME:
			aclDestroyTimeList(a->data);
			break;
    		case ACL_URL_REGEX:
			aclDestroyRegexList(a->data);
			break;
    		case ACL_URL_PORT:
    		case ACL_PROTO:
    		case ACL_METHOD:
			intlistDestroy((intlist **) &a->data);
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

void aclDestroyAclList(list)
	struct _acl_list *list;
{
	struct _acl_list *next = NULL;
	for (; list ; list=next) {
		next = list->next;
		safe_free(list);
	}
}

void aclDestroyAccessList(list)
	struct _acl_access **list;
{
	struct _acl_access *l = NULL;
	struct _acl_access *next = NULL;
	for (l=*list; l ; l=next) {
		debug(28,1,"aclDestroyAccessList: '%s'\n", l->cfgline);
		next = l->next;
		aclDestroyAclList(l->acl_list);
		l->acl_list = NULL;
		safe_free(l->cfgline);
		safe_free(l);
	}
	*list = NULL;
}

