#ident "$Id: acl.cc,v 1.1 1996/04/11 02:40:30 wessels Exp $"

#include "squid.h"

static struct _acl_access *AccessList = NULL;
static struct _acl_access **AccessListTail = &AccessList;
static struct _acl *AclList = NULL;
static struct _acl **AclListTail = &AclList;

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
    return ACL_NONE;
}

struct _acl *aclFindByName(name)
	char *name;
{
	struct _acl *a;
	for (a = AclList; a; a=a->next)
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
	q->i = proto_url_to_id(t);
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
		    debug(3, 0, "aclParseIpList: Ignoring invalid IP acl entry '%s'\n", t);
		    safe_free(q);
		    continue;
		}
		lmask.s_addr = htonl(0xffffffff << (32 - m1));
		break;
	    case 8:
		lmask.s_addr = htonl(m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4);
		break;
	    default:
		debug(3, 0, "aclParseIpList: Ignoring invalid IP acl entry '%s'\n", t);
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
    return NULL;
}

struct _relist *aclParseRegexList()
{
    relist *head = NULL;
    relist **Tail = &head;
    relist *q = NULL;
    char *t = NULL;
    while ((t = strtok(NULL, w_space))) {
	q = (relist *) xcalloc(1, sizeof(relist));
	q->compiled_pattern = re_comp
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
	xfree(A);
	debug(28, 1, "aclParseAclLine: missing ACL name.\n");
	return;
    }
    strncpy(A->name, t, ACL_NAME_SZ);
    /* snarf the ACL type */
    if ((t = strtok(NULL, w_space)) == NULL) {
	xfree(A);
	debug(28, 1, "aclParseAclLine: missing ACL type.\n");
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
    case ACL_NONE:
    default:
	xfree(A);
	debug(28, 1, "aclParseAclLine: Invalid ACL type '%s'\n", t);
	return;
	break;
    }
    *AclListTail = A;
    AclListTail = &A->next;
}

void aclParseAccessLine()
{
    char *t = NULL;
    struct _acl_access *A = NULL;
    struct _acl_list *L = NULL;
    struct _acl_list **Tail = &L;
    struct _acl *a = NULL;

    /* first expect either 'allow' or 'deny' */
    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(28, 1, "aclParseAccessLine: missing 'allow' or 'deny'.\n");
	return;
    }
    A = (struct _acl_access *) xcalloc(1, sizeof(struct _acl_access));
    if (!strcmp(t, "allow"))
	A->allow = 1;
    else if (!strcmp(t, "deny"))
	A->allow = 0;
    else {
	debug(28, 1, "aclParseAccessLine: expecting 'allow' or 'deny', got '%s'.\n", t);
	xfree(A);
	return;
    }

    /* next expect a list of ACL names, possibly preceeded
     * by '!' for negation */
    while ((t = strtok(NULL, w_space))) {
	L = (struct _acl_list *) xcalloc (1, sizeof(struct _acl_list));
	L->op = 1;	/* defaults to non-negated */
	if (*t == '!') {
		/* negated ACL */
		L->op = 0;
		t++;
	}
	a = aclFindByName(t);
	if (a == NULL) {
		debug(28, 1, "aclParseAccessLine: ACL name '%s' not found.\n", t);
		xfree(L);
		continue;
	}
	L->acl = a;
	*Tail = L;
	Tail = &L->next;
    }
    *AccessListTail = A;
    AccessListTail = &A->next;
}


    if (regcomp(&comp, pattern, REG_EXTENDED) != REG_NOERROR) {
	debug(22, 0, "ttlAddToList: Invalid regular expression: %s\n",
	    pattern);
	return;
    }
    pct_age = pct_age < 0 ? 0 : pct_age > 100 ? 100 : pct_age;
    age_max = age_max < 0 ? 0 : age_max;
