
/*
 * $Id: ipcache.cc,v 1.211 1999/04/14 05:16:16 wessels Exp $
 *
 * DEBUG: section 14    IP Cache
 * AUTHOR: Harvest Derived
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

static struct {
    int requests;
    int replies;
    int hits;
    int misses;
    int pending_hits;
    int negative_hits;
    int errors;
    int ghbn_calls;		/* # calls to blocking gethostbyname() */
    int release_locked;
} IpcacheStats;

static dlink_list lru_list;

static FREE ipcacheFreeEntry;
#if USE_DNSSERVERS
static HLPCB ipcacheHandleReply;
#else
static IDNSCB ipcacheHandleReply;
#endif
static IPH dummy_handler;
static int ipcacheExpiredEntry(ipcache_entry *);
static int ipcache_testname(void);
static ipcache_entry *ipcacheAddNew(const char *, const struct hostent *, ipcache_status_t);
#if USE_DNSSERVERS
static ipcache_entry *ipcacheParse(const char *buf);
#else
static ipcache_entry *ipcacheParse(rfc1035_rr *, int);
#endif
static ipcache_entry *ipcache_create(const char *name);
static ipcache_entry *ipcache_get(const char *);
static void ipcacheAddHostent(ipcache_entry *, const struct hostent *);
static void ipcacheAddPending(ipcache_entry *, IPH *, void *);
static void ipcacheChangeKey(ipcache_entry * i);
static void ipcacheLockEntry(ipcache_entry *);
static void ipcacheStatPrint(ipcache_entry *, StoreEntry *);
static void ipcacheUnlockEntry(ipcache_entry *);
static void ipcache_call_pending(ipcache_entry *);
static void ipcache_release(ipcache_entry *);

static ipcache_addrs static_addrs;
static hash_table *ip_table = NULL;

static char ipcache_status_char[] =
{
    'C',
    'N',
    'P',
    'D'
};

static long ipcache_low = 180;
static long ipcache_high = 200;

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;
#endif

static int
ipcache_testname(void)
{
    wordlist *w = NULL;
    debug(14, 1) ("Performing DNS Tests...\n");
    if ((w = Config.dns_testname_list) == NULL)
	return 1;
    for (; w; w = w->next) {
	IpcacheStats.ghbn_calls++;
	if (gethostbyname(w->key) != NULL)
	    return 1;
    }
    return 0;
}

/* removes the given ipcache entry */
static void
ipcache_release(ipcache_entry * i)
{
    hash_link *table_entry = NULL;
    if ((table_entry = hash_lookup(ip_table, i->name)) == NULL) {
	snprintf(tmp_error_buf, ERROR_BUF_SZ, "ipcache_release: key '%s' not found\n", i->name);
	fatal_dump(tmp_error_buf);
    }
    assert(i == (ipcache_entry *) table_entry);
    if (i->locks) {
	i->expires = squid_curtime;
	ipcacheChangeKey(i);
	IpcacheStats.release_locked++;
	return;
    }
    hash_remove_link(ip_table, table_entry);
    dlinkDelete(&i->lru, &lru_list);
    if (i->status == IP_CACHED) {
	safe_free(i->addrs.in_addrs);
	safe_free(i->addrs.bad_mask);
	debug(14, 5) ("ipcache_release: Released IP cached record for '%s'.\n",
	    i->name);
    }
    safe_free(i->name);
    safe_free(i->error_message);
    memFree(i, MEM_IPCACHE_ENTRY);
    return;
}

static ipcache_entry *
ipcache_get(const char *name)
{
    assert(ip_table != NULL);
    return (ipcache_entry *) hash_lookup(ip_table, name);
}

static int
ipcacheExpiredEntry(ipcache_entry * i)
{
    if (i->status == IP_PENDING)
	return 0;
    if (i->status == IP_DISPATCHED)
	return 0;
    if (i->locks != 0)
	return 0;
    if (i->addrs.count == 0)
	return 1;
    if (i->expires > squid_curtime)
	return 0;
    return 1;
}

void
ipcache_purgelru(void *voidnotused)
{
    dlink_node *m;
    dlink_node *prev = NULL;
    ipcache_entry *i;
    int removed = 0;
    eventAdd("ipcache_purgelru", ipcache_purgelru, NULL, 10.0, 1);
    for (m = lru_list.tail; m; m = prev) {
	if (memInUse(MEM_IPCACHE_ENTRY) < ipcache_low)
	    break;
	prev = m->prev;
	i = m->data;
	if (i->status == IP_PENDING)
	    continue;
	if (i->status == IP_DISPATCHED)
	    continue;
	if (i->locks != 0)
	    continue;
	ipcache_release(i);
	removed++;
    }
    debug(14, 9) ("ipcache_purgelru: removed %d entries\n", removed);
}

/* create blank ipcache_entry */
static ipcache_entry *
ipcache_create(const char *name)
{
    static ipcache_entry *i;
    i = memAllocate(MEM_IPCACHE_ENTRY);
    i->name = xstrdup(name);
    i->expires = squid_curtime + Config.negativeDnsTtl;
    hash_join(ip_table, (hash_link *) i);
    dlinkAdd(i, &i->lru, &lru_list);
    return i;
}

static void
ipcacheAddHostent(ipcache_entry * i, const struct hostent *hp)
{
    int addr_count = 0;
    int k;
    safe_free(i->addrs.in_addrs);
    safe_free(i->addrs.bad_mask);
    while ((addr_count < 255) && *(hp->h_addr_list + addr_count))
	++addr_count;
    i->addrs.count = (unsigned char) addr_count;
    i->addrs.in_addrs = xcalloc(addr_count, sizeof(struct in_addr));
    i->addrs.bad_mask = xcalloc(addr_count, sizeof(unsigned char));
    i->addrs.badcount = 0;
    for (k = 0; k < addr_count; k++)
	xmemcpy(&i->addrs.in_addrs[k].s_addr,
	    *(hp->h_addr_list + k),
	    hp->h_length);
}

static ipcache_entry *
ipcacheAddNew(const char *name, const struct hostent *hp, ipcache_status_t status)
{
    ipcache_entry *i;
    if (ipcache_get(name))
	fatal_dump("ipcacheAddNew: somebody adding a duplicate!");
    debug(14, 10) ("ipcacheAddNew: Adding '%s', status=%c\n",
	name,
	ipcache_status_char[status]);
    i = ipcache_create(name);
    if (hp)
	ipcacheAddHostent(i, hp);
    i->status = status;
    i->lastref = squid_curtime;
    return i;
}

/* walks down the pending list, calling handlers */
static void
ipcache_call_pending(ipcache_entry * i)
{
    ip_pending *p = NULL;
    int nhandler = 0;
    i->lastref = squid_curtime;
    ipcacheLockEntry(i);
    while (i->pending_head != NULL) {
	p = i->pending_head;
	i->pending_head = p->next;
	if (p->handler) {
	    nhandler++;
	    dns_error_message = i->error_message;
	    if (cbdataValid(p->handlerData)) {
		p->handler(i->status == IP_CACHED ? &i->addrs : NULL,
		    p->handlerData);
	    }
	    cbdataUnlock(p->handlerData);
	}
	memFree(p, MEM_IPCACHE_PENDING);
    }
    i->pending_head = NULL;	/* nuke list */
    debug(14, 10) ("ipcache_call_pending: Called %d handlers.\n", nhandler);
    ipcacheUnlockEntry(i);
}

#if USE_DNSSERVERS
static ipcache_entry *
ipcacheParse(const char *inbuf)
{
    LOCAL_ARRAY(char, buf, DNS_INBUF_SZ);
    char *token;
    static ipcache_entry i;
    int j;
    int k;
    int ipcount = 0;
    int ttl;
    char A[32][16];
    memset(&i, '\0', sizeof(i));
    i.expires = squid_curtime;
    i.status = IP_NEGATIVE_CACHED;
    if (inbuf == NULL) {
	debug(14, 1) ("ipcacheParse: Got <NULL> reply\n");
	i.error_message = xstrdup("Internal Squid Error");
	return &i;
    }
    xstrncpy(buf, inbuf, DNS_INBUF_SZ);
    debug(14, 5) ("ipcacheParse: parsing: {%s}\n", buf);
    token = strtok(buf, w_space);
    if (NULL == token) {
	debug(14, 1) ("ipcacheParse: Got <NULL>, expecting '$addr'\n");
	return &i;
    }
    if (0 == strcmp(token, "$fail")) {
	i.expires = squid_curtime + Config.negativeDnsTtl;
	token = strtok(NULL, "\n");
	assert(NULL != token);
	i.error_message = xstrdup(token);
	return &i;
    }
    if (0 != strcmp(token, "$addr")) {
	debug(14, 1) ("ipcacheParse: Got '%s', expecting '$addr'\n", token);
	return &i;
    }
    token = strtok(NULL, w_space);
    if (NULL == token) {
	debug(14, 1) ("ipcacheParse: Got <NULL>, expecting TTL\n");
	return &i;
    }
    i.status = IP_CACHED;
    ttl = atoi(token);
    if (ttl > 0)
	i.expires = squid_curtime + ttl;
    else
	i.expires = squid_curtime + Config.positiveDnsTtl;
    while (NULL != (token = strtok(NULL, w_space))) {
	xstrncpy(A[ipcount], token, 16);
	if (++ipcount == 32)
	    break;
    }
    if (0 == ipcount) {
	i.addrs.in_addrs = NULL;
	i.addrs.bad_mask = NULL;
    } else {
	i.addrs.in_addrs = xcalloc(ipcount, sizeof(struct in_addr));
	i.addrs.bad_mask = xcalloc(ipcount, sizeof(unsigned char));
    }
    for (j = 0, k = 0; k < ipcount; k++) {
	if (safe_inet_addr(A[k], &i.addrs.in_addrs[j]))
	    j++;
	else
	    debug(14, 1) ("ipcacheParse: Invalid IP address '%s'\n", A[k]);
    }
    i.addrs.count = (unsigned char) j;
    return &i;
}
#else
static ipcache_entry *
ipcacheParse(rfc1035_rr * answers, int na)
{
    static ipcache_entry i;
    memset(&i, '\0', sizeof(i));
    i.expires = squid_curtime;
    i.status = IP_NEGATIVE_CACHED;
    if (na < 0) {
	debug(14, 1) ("ipcacheParse: Lookup failed\n");
	debug(14, 1) ("\trfc1035_errno = %d\n", rfc1035_errno);
	assert(rfc1035_error_message);
	i.error_message = xstrdup(rfc1035_error_message);
    } else if (na == 0) {
	debug(14, 1) ("ipcacheParse: No Address records\n");
	i.error_message = xstrdup("No Address records");
    } else {
	int k;
	int j;
	assert(answers);
	i.status = IP_CACHED;
	i.expires = squid_curtime + answers->ttl;
	i.addrs.in_addrs = xcalloc(na, sizeof(struct in_addr));
	i.addrs.bad_mask = xcalloc(na, sizeof(unsigned char));
	for (j = 0, k = 0; k < na; k++) {
	    if (answers[k].type != RFC1035_TYPE_A)
		continue;
	    if (answers[k].class != RFC1035_CLASS_IN)
		continue;
	    assert(answers[k].rdlength == 4);
	    xmemcpy(&i.addrs.in_addrs[j++], answers[k].rdata, 4);
	    debug(14, 1) ("ipcacheParse: #%d %s\n",
		j - 1,
		inet_ntoa(i.addrs.in_addrs[j - 1]));
	}
	i.addrs.count = (unsigned char) j;
    }
    return &i;
}
#endif

static void
#if USE_DNSSERVERS
ipcacheHandleReply(void *data, char *reply)
#else
ipcacheHandleReply(void *data, rfc1035_rr * answers, int na)
#endif
{
    int n;
    generic_cbdata *c = data;
    ipcache_entry *i = c->data;
    ipcache_entry *x = NULL;
    assert(i->status == IP_DISPATCHED);
    assert(i->locks);
    cbdataFree(c);
    c = NULL;
    n = ++IpcacheStats.replies;
    statHistCount(&Counter.dns.svc_time, tvSubMsec(i->request_time, current_time));
#if USE_DNSSERVERS
    x = ipcacheParse(reply);
#else
    x = ipcacheParse(answers, na);
#endif
    assert(x);
    i->status = x->status;
    i->addrs = x->addrs;
    i->error_message = x->error_message;
    i->expires = x->expires;
    ipcache_call_pending(i);
    ipcacheUnlockEntry(i);	/* unlock from IP_DISPATCHED */
}

static void
ipcacheAddPending(ipcache_entry * i, IPH * handler, void *handlerData)
{
    ip_pending *pending = memAllocate(MEM_IPCACHE_PENDING);
    ip_pending **I = NULL;
    i->lastref = squid_curtime;
    pending->handler = handler;
    pending->handlerData = handlerData;
    cbdataLock(handlerData);
    for (I = &(i->pending_head); *I; I = &((*I)->next));
    *I = pending;
}

void
ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData)
{
    ipcache_entry *i = NULL;
    const ipcache_addrs *addrs = NULL;
    generic_cbdata *c;
    assert(handler != NULL);
    debug(14, 4) ("ipcache_nbgethostbyname: Name '%s'.\n", name);
    IpcacheStats.requests++;
    if (name == NULL || name[0] == '\0') {
	debug(14, 4) ("ipcache_nbgethostbyname: Invalid name!\n");
	handler(NULL, handlerData);
	return;
    }
    if ((addrs = ipcacheCheckNumeric(name))) {
	handler(addrs, handlerData);
	return;
    }
    if ((i = ipcache_get(name))) {
	if (ipcacheExpiredEntry(i)) {
	    ipcache_release(i);
	    i = NULL;
	}
    }
    if (i == NULL) {
	/* MISS: No entry, create the new one */
	debug(14, 5) ("ipcache_nbgethostbyname: MISS for '%s'\n", name);
	IpcacheStats.misses++;
	i = ipcacheAddNew(name, NULL, IP_PENDING);
	ipcacheAddPending(i, handler, handlerData);
	i->request_time = current_time;
    } else if (i->status == IP_CACHED || i->status == IP_NEGATIVE_CACHED) {
	/* HIT */
	debug(14, 4) ("ipcache_nbgethostbyname: HIT for '%s'\n", name);
	if (i->status == IP_NEGATIVE_CACHED)
	    IpcacheStats.negative_hits++;
	else
	    IpcacheStats.hits++;
	ipcacheAddPending(i, handler, handlerData);
	ipcache_call_pending(i);
	return;
    } else if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	debug(14, 4) ("ipcache_nbgethostbyname: PENDING for '%s'\n", name);
	IpcacheStats.pending_hits++;
	ipcacheAddPending(i, handler, handlerData);
	if (squid_curtime - i->expires > 600) {
	    debug(14, 0) ("ipcache_nbgethostbyname: '%s' PENDING for %d seconds, aborting\n", name, (int) (squid_curtime + Config.negativeDnsTtl - i->expires));
	    ipcacheChangeKey(i);
	    ipcache_call_pending(i);
	}
	return;
    } else {
	fatal_dump("ipcache_nbgethostbyname: BAD ipcache_entry status");
    }
    /* for HIT, PENDING, DISPATCHED we've returned.  For MISS we submit */
    c = xcalloc(1, sizeof(*c));
    c->data = i;
    cbdataAdd(c, cbdataXfree, 0);
    i->status = IP_DISPATCHED;
    ipcacheLockEntry(i);
#if USE_DNSSERVERS
    dnsSubmit(i->name, ipcacheHandleReply, c);
#else
    idnsALookup(i->name, ipcacheHandleReply, c);
#endif
}

/* initialize the ipcache */
void
ipcache_init(void)
{
    int n;
    debug(14, 3) ("Initializing IP Cache...\n");
    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));
    memset(&lru_list, '\0', sizeof(lru_list));
    /* test naming lookup */
    if (!opt_dns_tests) {
	debug(14, 4) ("ipcache_init: Skipping DNS name lookup tests.\n");
    } else if (!ipcache_testname()) {
	fatal("ipcache_init: DNS name lookup tests failed.");
    } else {
	debug(14, 1) ("Successful DNS name lookup tests...\n");
    }
    memset(&static_addrs, '\0', sizeof(ipcache_addrs));
    static_addrs.in_addrs = xcalloc(1, sizeof(struct in_addr));
    static_addrs.bad_mask = xcalloc(1, sizeof(unsigned char));
    ipcache_high = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.low) / (float) 100);
    n = hashPrime(ipcache_high / 4);
    ip_table = hash_create((HASHCMP *) strcmp, n, hash4);
    cachemgrRegister("ipcache",
	"IP Cache Stats and Contents",
	stat_ipcache_get, 0, 1);
}

int
ipcacheUnregister(const char *name, void *data)
{
    ipcache_entry *i = NULL;
    ip_pending *p = NULL;
    int n = 0;
    debug(14, 3) ("ipcacheUnregister: name '%s'\n", name);
    if ((i = ipcache_get(name)) == NULL)
	return 0;
    if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	for (p = i->pending_head; p; p = p->next) {
	    if (p->handlerData != data)
		continue;
	    p->handler = NULL;
	    n++;
	}
    }
    assert(n > 0);
    debug(14, 3) ("ipcacheUnregister: unregistered %d handlers\n", n);
    return n;
}

const ipcache_addrs *
ipcache_gethostbyname(const char *name, int flags)
{
    ipcache_entry *i = NULL;
    ipcache_addrs *addrs;
    if (!name)
	fatal_dump("ipcache_gethostbyname: NULL name");
    debug(14, 3) ("ipcache_gethostbyname: '%s', flags=%x\n", name, flags);
    IpcacheStats.requests++;
    if ((i = ipcache_get(name))) {
	if (ipcacheExpiredEntry(i)) {
	    ipcache_release(i);
	    i = NULL;
	}
    }
    if (i) {
	if (i->status == IP_NEGATIVE_CACHED) {
	    IpcacheStats.negative_hits++;
	    dns_error_message = i->error_message;
	    return NULL;
	} else if (i->addrs.count == 0) {
	    (void) 0;
	} else {
	    IpcacheStats.hits++;
	    i->lastref = squid_curtime;
	    return &i->addrs;
	}
    }
    if ((addrs = ipcacheCheckNumeric(name)))
	return addrs;
    IpcacheStats.misses++;
    if (flags & IP_LOOKUP_IF_MISS)
	ipcache_nbgethostbyname(name, dummy_handler, NULL);
    return NULL;
}

static void
ipcacheStatPrint(ipcache_entry * i, StoreEntry * sentry)
{
    int k;
    storeAppendPrintf(sentry, " %-32.32s  %c%c %6d %6d %2d(%2d)",
	i->name,
	ipcache_status_char[i->status],
	i->locks ? 'L' : ' ',
	(int) (squid_curtime - i->lastref),
	(int) (i->expires - squid_curtime),
	(int) i->addrs.count,
	(int) i->addrs.badcount);
    for (k = 0; k < (int) i->addrs.count; k++) {
	storeAppendPrintf(sentry, " %15s-%3s", inet_ntoa(i->addrs.in_addrs[k]),
	    i->addrs.bad_mask[k] ? "BAD" : "OK ");
    }
    storeAppendPrintf(sentry, "\n");
}

/* process objects list */
void
stat_ipcache_get(StoreEntry * sentry)
{
    dlink_node *m;
    assert(ip_table != NULL);
    storeAppendPrintf(sentry, "IP Cache Statistics:\n");
    storeAppendPrintf(sentry, "IPcache Entries: %d\n",
	memInUse(MEM_IPCACHE_ENTRY));
    storeAppendPrintf(sentry, "IPcache Requests: %d\n",
	IpcacheStats.requests);
    storeAppendPrintf(sentry, "IPcache Hits: %d\n",
	IpcacheStats.hits);
    storeAppendPrintf(sentry, "IPcache Pending Hits: %d\n",
	IpcacheStats.pending_hits);
    storeAppendPrintf(sentry, "IPcache Negative Hits: %d\n",
	IpcacheStats.negative_hits);
    storeAppendPrintf(sentry, "IPcache Misses: %d\n",
	IpcacheStats.misses);
    storeAppendPrintf(sentry, "Blocking calls to gethostbyname(): %d\n",
	IpcacheStats.ghbn_calls);
    storeAppendPrintf(sentry, "Attempts to release locked entries: %d\n",
	IpcacheStats.release_locked);
    storeAppendPrintf(sentry, "\n\n");
    storeAppendPrintf(sentry, "IP Cache Contents:\n\n");
    storeAppendPrintf(sentry, " %-29.29s %5s %6s %6s %1s\n",
	"Hostname",
	"Flags",
	"lstref",
	"TTL",
	"N");
    for (m = lru_list.head; m; m = m->next)
	ipcacheStatPrint(m->data, sentry);
}

static void
dummy_handler(const ipcache_addrs * addrsnotused, void *datanotused)
{
    return;
}

void
ipcacheReleaseInvalid(const char *name)
{
    ipcache_entry *i;
    if (NULL == name) {
	debug(14, 1) ("ipcacheReleaseInvalid: NULL name\n");
	return;
    }
    if (0 == strlen(name)) {
	debug(14, 1) ("ipcacheReleaseInvalid: Empty name\n");
	return;
    }
    if ((i = ipcache_get(name)) == NULL)
	return;
    if (i->status != IP_NEGATIVE_CACHED)
	return;
    ipcache_release(i);
}

void
ipcacheInvalidate(const char *name)
{
    ipcache_entry *i;
    if ((i = ipcache_get(name)) == NULL)
	return;
    i->expires = squid_curtime;
    /* NOTE, don't call ipcache_release here becuase we might be here due
     * to a thread started from ipcache_call_pending() which will cause a
     * FMR */
}

ipcache_addrs *
ipcacheCheckNumeric(const char *name)
{
    struct in_addr ip;
    /* check if it's already a IP address in text form. */
    if (!safe_inet_addr(name, &ip))
	return NULL;
    static_addrs.count = 1;
    static_addrs.cur = 0;
    static_addrs.in_addrs[0].s_addr = ip.s_addr;
    static_addrs.bad_mask[0] = FALSE;
    static_addrs.badcount = 0;
    return &static_addrs;
}

static void
ipcacheLockEntry(ipcache_entry * i)
{
    if (i->locks++ == 0) {
	dlinkDelete(&i->lru, &lru_list);
	dlinkAdd(i, &i->lru, &lru_list);
    }
}

static void
ipcacheUnlockEntry(ipcache_entry * i)
{
    assert(i->locks > 0);
    i->locks--;
    if (ipcacheExpiredEntry(i))
	ipcache_release(i);
}

void
ipcacheCycleAddr(const char *name, ipcache_addrs * ia)
{
    ipcache_entry *i;
    unsigned char k;
    assert(name || ia);
    if (NULL == ia) {
	if ((i = ipcache_get(name)) == NULL)
	    return;
	if (i->status != IP_CACHED)
	    return;
	ia = &i->addrs;
    }
    for (k = 0; k < ia->count; k++) {
	if (++ia->cur == ia->count)
	    ia->cur = 0;
	if (!ia->bad_mask[ia->cur])
	    break;;
    }
    if (k == ia->count) {
	/* All bad, reset to All good */
	debug(14, 3) ("ipcacheCycleAddr: Changing ALL %s addrs from BAD to OK\n",
	    name);
	for (k = 0; k < ia->count; k++)
	    ia->bad_mask[k] = 0;
	ia->badcount = 0;
	ia->cur = 0;
    }
    debug(14, 3) ("ipcacheCycleAddr: %s now at %s\n", name,
	inet_ntoa(ia->in_addrs[ia->cur]));
}

/*
 * Marks the given address as BAD and calls ipcacheCycleAddr to
 * advance the current pointer to the next OK address.
 */
void
ipcacheMarkBadAddr(const char *name, struct in_addr addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;
    if ((i = ipcache_get(name)) == NULL)
	return;
    ia = &i->addrs;
    for (k = 0; k < (int) ia->count; k++) {
	if (ia->in_addrs[k].s_addr == addr.s_addr)
	    break;
    }
    if (k == (int) ia->count)	/* not found */
	return;
    if (!ia->bad_mask[k]) {
	ia->bad_mask[k] = TRUE;
	ia->badcount++;
	debug(14, 2) ("ipcacheMarkBadAddr: %s [%s]\n", name, inet_ntoa(addr));
    }
    ipcacheCycleAddr(name, ia);
}

void
ipcacheMarkGoodAddr(const char *name, struct in_addr addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;
    if ((i = ipcache_get(name)) == NULL)
	return;
    ia = &i->addrs;
    for (k = 0; k < (int) ia->count; k++) {
	if (ia->in_addrs[k].s_addr == addr.s_addr)
	    break;
    }
    if (k == (int) ia->count)	/* not found */
	return;
    if (!ia->bad_mask[k])	/* already OK */
	return;
    ia->bad_mask[k] = FALSE;
    ia->badcount--;
    debug(14, 2) ("ipcacheMarkGoodAddr: %s [%s]\n", name, inet_ntoa(addr));
}

static void
ipcacheFreeEntry(void *data)
{
    ipcache_entry *i = data;
    ip_pending *p;
    while ((p = i->pending_head)) {
	i->pending_head = p->next;
	memFree(p, MEM_IPCACHE_PENDING);
    }
    safe_free(i->addrs.in_addrs);
    safe_free(i->addrs.bad_mask);
    safe_free(i->name);
    safe_free(i->error_message);
    memFree(i, MEM_IPCACHE_ENTRY);
}

void
ipcacheFreeMemory(void)
{
    hashFreeItems(ip_table, ipcacheFreeEntry);
    hashFreeMemory(ip_table);
    ip_table = NULL;
}

static void
ipcacheChangeKey(ipcache_entry * i)
{
    static int index = 0;
    LOCAL_ARRAY(char, new_key, 256);
    hash_link *table_entry = hash_lookup(ip_table, i->name);
    if (table_entry == NULL) {
	debug(14, 0) ("ipcacheChangeKey: Could not find key '%s'\n", i->name);
	return;
    }
    assert(i == (ipcache_entry *) table_entry);
    hash_remove_link(ip_table, table_entry);
    snprintf(new_key, 256, "%d/%s", ++index, i->name);
    debug(14, 1) ("ipcacheChangeKey: from '%s' to '%s'\n", i->name, new_key);
    safe_free(i->name);
    i->name = xstrdup(new_key);
    hash_join(ip_table, (hash_link *) i);
}

/* call during reconfigure phase to clear out all the 
 * pending and dispatched reqeusts that got lost */
void
ipcache_restart(void)
{
    ipcache_entry *this;
    assert(ip_table != NULL);
    hash_first(ip_table);
    while ((this = (ipcache_entry *) hash_next(ip_table))) {
	if (this->status == IP_CACHED)
	    continue;
	if (this->status == IP_NEGATIVE_CACHED)
	    continue;
    }
    /* recalculate these while we're at it */
    ipcache_high = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.low) / (float) 100);
}

#ifdef SQUID_SNMP
/*
 * The function to return the ip cache statistics to via SNMP
 */

variable_list *
snmp_netIpFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;

    debug(49, 5) ("snmp_netIpFn: Processing request:\n", Var->name[LEN_SQ_NET + 1]);
    snmpDebugOid(5, Var->name, Var->name_length);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(snint);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = SMI_COUNTER32;

    switch (Var->name[LEN_SQ_NET + 1]) {
    case IP_ENT:
	*(Answer->val.integer) = memInUse(MEM_IPCACHE_ENTRY);
	Answer->type = SMI_GAUGE32;
	break;
    case IP_REQ:
	*(Answer->val.integer) = IpcacheStats.requests;
	break;
    case IP_HITS:
	*(Answer->val.integer) = IpcacheStats.hits;
	break;
    case IP_PENDHIT:
	*(Answer->val.integer) = IpcacheStats.pending_hits;
	Answer->type = SMI_GAUGE32;
	break;
    case IP_NEGHIT:
	*(Answer->val.integer) = IpcacheStats.negative_hits;
	break;
    case IP_MISS:
	*(Answer->val.integer) = IpcacheStats.misses;
	break;
    case IP_GHBN:
	*(Answer->val.integer) = IpcacheStats.ghbn_calls;
	break;
    case IP_LOC:
	*(Answer->val.integer) = IpcacheStats.release_locked;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

#endif /*SQUID_SNMP */
