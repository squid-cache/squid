

/*
 * $Id: fqdncache.cc,v 1.125 1998/11/20 06:13:15 wessels Exp $
 *
 * DEBUG: section 35    FQDN Cache
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

#define FQDN_LOW_WATER       90
#define FQDN_HIGH_WATER      95

static struct {
    int requests;
    int replies;
    int hits;
    int misses;
    int pending_hits;
    int negative_hits;
    int errors;
    int ghba_calls;		/* # calls to blocking gethostbyaddr() */
} FqdncacheStats;

static dlink_list lru_list;

static HLPCB fqdncacheHandleReply;
static fqdncache_entry *fqdncacheParse(const char *buf);
static void fqdncache_release(fqdncache_entry *);
static fqdncache_entry *fqdncache_create(const char *name);
static void fqdncache_call_pending(fqdncache_entry *);
static void fqdncacheAddHostent(fqdncache_entry *, const struct hostent *);
static fqdncache_entry *fqdncache_get(const char *);
static FQDNH dummy_handler;
static int fqdncacheExpiredEntry(const fqdncache_entry *);
static void fqdncacheAddPending(fqdncache_entry *, FQDNH *, void *);
static void fqdncacheChangeKey(fqdncache_entry * i);
static void fqdncacheLockEntry(fqdncache_entry * f);
static void fqdncacheUnlockEntry(fqdncache_entry * f);
static FREE fqdncacheFreeEntry;

static hash_table *fqdn_table = NULL;

static char fqdncache_status_char[] =
{
    'C',
    'N',
    'P',
    'D'
};

static long fqdncache_low = 180;
static long fqdncache_high = 200;

/* removes the given fqdncache entry */
static void
fqdncache_release(fqdncache_entry * f)
{
    int k;
    assert(f->status != FQDN_PENDING);
    assert(f->status != FQDN_DISPATCHED);
    assert(f->pending_head == NULL);
    hash_remove_link(fqdn_table, (hash_link *) f);
    if (f->status == FQDN_CACHED) {
	for (k = 0; k < (int) f->name_count; k++)
	    safe_free(f->names[k]);
	debug(35, 5) ("fqdncache_release: Released FQDN record for '%s'.\n",
	    f->name);
    }
    dlinkDelete(&f->lru, &lru_list);
    safe_free(f->name);
    safe_free(f->error_message);
    memFree(MEM_FQDNCACHE_ENTRY, f);
}

/* return match for given name */
static fqdncache_entry *
fqdncache_get(const char *name)
{
    hash_link *e;
    static fqdncache_entry *f;
    f = NULL;
    if (fqdn_table) {
	if ((e = hash_lookup(fqdn_table, name)) != NULL)
	    f = (fqdncache_entry *) e;
    }
    return f;
}

static int
fqdncacheExpiredEntry(const fqdncache_entry * f)
{
    if (f->status == FQDN_PENDING)
	return 0;
    if (f->status == FQDN_DISPATCHED)
	return 0;
    if (f->locks != 0)
	return 0;
    if (f->expires > squid_curtime)
	return 0;
    return 1;
}

void
fqdncache_purgelru(void *notused)
{
    dlink_node *m;
    dlink_node *prev = NULL;
    fqdncache_entry *f;
    int removed = 0;
    eventAdd("fqdncache_purgelru", fqdncache_purgelru, NULL, 10.0, 1);
    for (m = lru_list.tail; m; m = prev) {
	if (memInUse(MEM_FQDNCACHE_ENTRY) < fqdncache_low)
	    break;
	prev = m->prev;
	f = m->data;
	if (f->status == FQDN_PENDING)
	    continue;
	if (f->status == FQDN_DISPATCHED)
	    continue;
	if (f->locks != 0)
	    continue;
	fqdncache_release(f);
	removed++;
    }
    debug(35, 9) ("fqdncache_purgelru: removed %d entries\n", removed);
}

/* create blank fqdncache_entry */
static fqdncache_entry *
fqdncache_create(const char *name)
{
    static fqdncache_entry *f;
    f = memAllocate(MEM_FQDNCACHE_ENTRY);
    f->name = xstrdup(name);
    f->expires = squid_curtime + Config.negativeDnsTtl;
    hash_join(fqdn_table, (hash_link *) f);
    dlinkAdd(f, &f->lru, &lru_list);
    return f;
}

static void
fqdncacheAddHostent(fqdncache_entry * f, const struct hostent *hp)
{
    int k;
    f->name_count = 0;
    f->names[f->name_count++] = xstrdup((char *) hp->h_name);
    for (k = 0; hp->h_aliases[k]; k++) {
	f->names[f->name_count++] = xstrdup(hp->h_aliases[k]);
	if (f->name_count == FQDN_MAX_NAMES)
	    break;
    }
}

static fqdncache_entry *
fqdncacheAddNew(const char *name, const struct hostent *hp, fqdncache_status_t status)
{
    fqdncache_entry *f;
    assert(fqdncache_get(name) == NULL);
    debug(35, 10) ("fqdncacheAddNew: Adding '%s', status=%c\n",
	name,
	fqdncache_status_char[status]);
    f = fqdncache_create(name);
    if (hp)
	fqdncacheAddHostent(f, hp);
    f->status = status;
    f->lastref = squid_curtime;
    return f;
}

/* walks down the pending list, calling handlers */
static void
fqdncache_call_pending(fqdncache_entry * f)
{
    fqdn_pending *p = NULL;
    int nhandler = 0;
    f->lastref = squid_curtime;
    fqdncacheLockEntry(f);
    while (f->pending_head != NULL) {
	p = f->pending_head;
	f->pending_head = p->next;
	if (p->handler) {
	    nhandler++;
	    dns_error_message = f->error_message;
	    p->handler((f->status == FQDN_CACHED) ? f->names[0] : NULL,
		p->handlerData);
	}
	memFree(MEM_FQDNCACHE_PENDING, p);
    }
    f->pending_head = NULL;	/* nuke list */
    debug(35, 10) ("fqdncache_call_pending: Called %d handlers.\n", nhandler);
    fqdncacheUnlockEntry(f);
}


static fqdncache_entry *
fqdncacheParse(const char *inbuf)
{
    LOCAL_ARRAY(char, buf, DNS_INBUF_SZ);
    char *token;
    static fqdncache_entry f;
    int ttl;
    xstrncpy(buf, inbuf, DNS_INBUF_SZ);
    debug(35, 5) ("fqdncacheParse: parsing: {%s}\n", buf);
    memset(&f, '\0', sizeof(f));
    f.expires = squid_curtime;
    f.status = FQDN_NEGATIVE_CACHED;
    if (inbuf == NULL) {
	debug(35, 1) ("fqdncacheParse: Got <NULL> reply\n");
	return &f;
    }
    token = strtok(buf, w_space);
    if (NULL == token) {
	debug(35, 1) ("fqdncacheParse: Got <NULL>, expecting '$name'\n");
	return &f;
    }
    if (0 == strcmp(token, "$fail")) {
	f.expires = squid_curtime + Config.negativeDnsTtl;
	token = strtok(NULL, "\n");
	assert(NULL != token);
	f.error_message = xstrdup(token);
	return &f;
    }
    if (0 != strcmp(token, "$name")) {
	debug(35, 1) ("fqdncacheParse: Got '%s', expecting '$name'\n", token);
	return &f;
    }
    token = strtok(NULL, w_space);
    if (NULL == token) {
	debug(35, 1) ("fqdncacheParse: Got <NULL>, expecting TTL\n");
	return &f;
    }
    f.status = FQDN_CACHED;
    ttl = atoi(token);
    if (ttl > 0)
	f.expires = squid_curtime + ttl;
    else
	f.expires = squid_curtime + Config.positiveDnsTtl;
    token = strtok(NULL, w_space);
    if (NULL != token) {
	f.names[0] = xstrdup(token);
	f.name_count = 1;
    }
    return &f;
}

static void
fqdncacheHandleReply(void *data, char *reply)
{
    int n;
    generic_cbdata *c = data;
    fqdncache_entry *f = c->data;
    fqdncache_entry *x = NULL;
    assert(f->status == FQDN_DISPATCHED);
    assert(f->locks);
    cbdataFree(c);
    c = NULL;
    n = ++FqdncacheStats.replies;
    statHistCount(&Counter.dns.svc_time,
	tvSubMsec(f->request_time, current_time));
    x = fqdncacheParse(reply);
    assert(x);
    f->name_count = x->name_count;
    for (n = 0; n < (int) f->name_count; n++)
	f->names[n] = x->names[n];
    f->error_message = x->error_message;
    f->status = x->status;
    f->expires = x->expires;
    fqdncache_call_pending(f);
    fqdncacheUnlockEntry(f);	/* unlock from FQDN_DISPATCHED */
}

static void
fqdncacheAddPending(fqdncache_entry * f, FQDNH * handler, void *handlerData)
{
    fqdn_pending *pending = memAllocate(MEM_FQDNCACHE_PENDING);
    fqdn_pending **I = NULL;
    f->lastref = squid_curtime;
    pending->handler = handler;
    pending->handlerData = handlerData;
    for (I = &(f->pending_head); *I; I = &((*I)->next));
    *I = pending;
}

void
fqdncache_nbgethostbyaddr(struct in_addr addr, FQDNH * handler, void *handlerData)
{
    fqdncache_entry *f = NULL;
    char *name = inet_ntoa(addr);
    generic_cbdata *c;
    assert(handler);
    debug(35, 4) ("fqdncache_nbgethostbyaddr: Name '%s'.\n", name);
    FqdncacheStats.requests++;
    if (name == NULL || name[0] == '\0') {
	debug(35, 4) ("fqdncache_nbgethostbyaddr: Invalid name!\n");
	handler(NULL, handlerData);
	return;
    }
    if ((f = fqdncache_get(name))) {
	if (fqdncacheExpiredEntry(f)) {
	    fqdncache_release(f);
	    f = NULL;
	}
    }
    if (f == NULL) {
	/* MISS: No entry, create the new one */
	debug(35, 5) ("fqdncache_nbgethostbyaddr: MISS for '%s'\n", name);
	FqdncacheStats.misses++;
	f = fqdncacheAddNew(name, NULL, FQDN_PENDING);
	fqdncacheAddPending(f, handler, handlerData);
	f->request_time = current_time;
    } else if (f->status == FQDN_CACHED || f->status == FQDN_NEGATIVE_CACHED) {
	/* HIT */
	debug(35, 4) ("fqdncache_nbgethostbyaddr: HIT for '%s'\n", name);
	if (f->status == FQDN_NEGATIVE_CACHED)
	    FqdncacheStats.negative_hits++;
	else
	    FqdncacheStats.hits++;
	fqdncacheAddPending(f, handler, handlerData);
	fqdncache_call_pending(f);
	return;
    } else if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED) {
	debug(35, 4) ("fqdncache_nbgethostbyaddr: PENDING for '%s'\n", name);
	FqdncacheStats.pending_hits++;
	fqdncacheAddPending(f, handler, handlerData);
	if (squid_curtime - f->expires > 600) {
	    debug(35, 0) ("fqdncache_nbgethostbyname: '%s' PENDING for %d seconds, aborting\n", name,
		(int) (squid_curtime + Config.negativeDnsTtl - f->expires));
	    fqdncacheChangeKey(f);
	    fqdncache_call_pending(f);
	}
	return;
    } else {
	debug(35, 1) ("fqdncache_nbgethostbyaddr: BAD status %d",
	    (int) f->status);
	assert(0);
    }
    /* for HIT, PENDING, DISPATCHED we've returned.  For MISS we submit */
    c = xcalloc(1, sizeof(*c));
    c->data = f;
    cbdataAdd(c, MEM_NONE);
    f->status = FQDN_DISPATCHED;
    fqdncacheLockEntry(f);	/* lock while FQDN_DISPATCHED */
    dnsSubmit(f->name, fqdncacheHandleReply, c);
}

/* initialize the fqdncache */
void
fqdncache_init(void)
{
    int n;
    if (fqdn_table)
	return;
    debug(35, 3) ("Initializing FQDN Cache...\n");
    memset(&FqdncacheStats, '\0', sizeof(FqdncacheStats));
    memset(&lru_list, '\0', sizeof(lru_list));
    fqdncache_high = (long) (((float) Config.fqdncache.size *
	    (float) FQDN_HIGH_WATER) / (float) 100);
    fqdncache_low = (long) (((float) Config.fqdncache.size *
	    (float) FQDN_LOW_WATER) / (float) 100);
    n = hashPrime(fqdncache_high / 4);
    fqdn_table = hash_create((HASHCMP *) strcmp, n, hash4);
    cachemgrRegister("fqdncache",
	"FQDN Cache Stats and Contents",
	fqdnStats, 0, 1);
}

/* clean up the pending entries in dnsserver */
/* return 1 if we found the host, 0 otherwise */
int
fqdncacheUnregister(struct in_addr addr, void *data)
{
    char *name = inet_ntoa(addr);
    fqdncache_entry *f = NULL;
    fqdn_pending *p = NULL;
    int n = 0;
    debug(35, 3) ("fqdncacheUnregister: name '%s'\n", name);
    if ((f = fqdncache_get(name)) == NULL)
	return 0;
    if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED) {
	for (p = f->pending_head; p; p = p->next) {
	    if (p->handlerData != data)
		continue;
	    p->handler = NULL;
	    n++;
	}
    }
    if (n == 0)
	debug_trap("fqdncacheUnregister: callback data not found");
    debug(35, 3) ("fqdncacheUnregister: unregistered %d handlers\n", n);
    return n;
}

const char *
fqdncache_gethostbyaddr(struct in_addr addr, int flags)
{
    char *name = inet_ntoa(addr);
    fqdncache_entry *f = NULL;
    struct in_addr ip;
    assert(name);
    FqdncacheStats.requests++;
    if ((f = fqdncache_get(name))) {
	if (fqdncacheExpiredEntry(f)) {
	    fqdncache_release(f);
	    f = NULL;
	}
    }
    if (f) {
	if (f->status == FQDN_NEGATIVE_CACHED) {
	    FqdncacheStats.negative_hits++;
	    dns_error_message = f->error_message;
	    return NULL;
	} else {
	    FqdncacheStats.hits++;
	    f->lastref = squid_curtime;
	    return f->names[0];
	}
    }
    /* check if it's already a FQDN address in text form. */
    if (!safe_inet_addr(name, &ip))
	return name;
    FqdncacheStats.misses++;
    if (flags & FQDN_LOOKUP_IF_MISS)
	fqdncache_nbgethostbyaddr(addr, dummy_handler, NULL);
    return NULL;
}


/* process objects list */
void
fqdnStats(StoreEntry * sentry)
{
    fqdncache_entry *f = NULL;
    int k;
    int ttl;
    if (fqdn_table == NULL)
	return;
    storeAppendPrintf(sentry, "FQDN Cache Statistics:\n");
    storeAppendPrintf(sentry, "FQDNcache Entries: %d\n",
	memInUse(MEM_FQDNCACHE_ENTRY));
    storeAppendPrintf(sentry, "FQDNcache Requests: %d\n",
	FqdncacheStats.requests);
    storeAppendPrintf(sentry, "FQDNcache Hits: %d\n",
	FqdncacheStats.hits);
    storeAppendPrintf(sentry, "FQDNcache Pending Hits: %d\n",
	FqdncacheStats.pending_hits);
    storeAppendPrintf(sentry, "FQDNcache Negative Hits: %d\n",
	FqdncacheStats.negative_hits);
    storeAppendPrintf(sentry, "FQDNcache Misses: %d\n",
	FqdncacheStats.misses);
    storeAppendPrintf(sentry, "Blocking calls to gethostbyaddr(): %d\n",
	FqdncacheStats.ghba_calls);
    storeAppendPrintf(sentry, "FQDN Cache Contents:\n\n");

    hash_first(fqdn_table);
    while ((f = (fqdncache_entry *) hash_next(fqdn_table))) {
	if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED)
	    ttl = 0;
	else
	    ttl = (f->expires - squid_curtime);
	storeAppendPrintf(sentry, " %-32.32s %c %6d %d",
	    f->name,
	    fqdncache_status_char[f->status],
	    ttl,
	    (int) f->name_count);
	for (k = 0; k < (int) f->name_count; k++)
	    storeAppendPrintf(sentry, " %s", f->names[k]);
	storeAppendPrintf(sentry, "\n");
    }
}

static void
dummy_handler(const char *bufnotused, void *datanotused)
{
    return;
}

void
fqdncacheReleaseInvalid(const char *name)
{
    fqdncache_entry *f;
    if ((f = fqdncache_get(name)) == NULL)
	return;
    if (f->status != FQDN_NEGATIVE_CACHED)
	return;
    fqdncache_release(f);
}

const char *
fqdnFromAddr(struct in_addr addr)
{
    const char *n;
    static char buf[32];
    if (Config.onoff.log_fqdn && (n = fqdncache_gethostbyaddr(addr, 0)))
	return n;
    xstrncpy(buf, inet_ntoa(addr), 32);
    return buf;
}

static void
fqdncacheLockEntry(fqdncache_entry * f)
{
    if (f->locks++ == 0) {
	dlinkDelete(&f->lru, &lru_list);
	dlinkAdd(f, &f->lru, &lru_list);
    }
}

static void
fqdncacheUnlockEntry(fqdncache_entry * f)
{
    if (f->locks == 0) {
	debug_trap("fqdncacheUnlockEntry: Entry has no locks");
	return;
    }
    f->locks--;
    if (fqdncacheExpiredEntry(f))
	fqdncache_release(f);
}

static void
fqdncacheFreeEntry(void *data)
{
    fqdncache_entry *f = data;
    fqdn_pending *p = NULL;
    int k;
    while ((p = f->pending_head)) {
	f->pending_head = p->next;
	memFree(MEM_FQDNCACHE_PENDING, p);
    }
    for (k = 0; k < (int) f->name_count; k++)
	safe_free(f->names[k]);
    safe_free(f->name);
    safe_free(f->error_message);
    memFree(MEM_FQDNCACHE_ENTRY, f);
}

void
fqdncacheFreeMemory(void)
{
    hashFreeItems(fqdn_table, fqdncacheFreeEntry);
    hashFreeMemory(fqdn_table);
    fqdn_table = NULL;
}

static void
fqdncacheChangeKey(fqdncache_entry * f)
{
    static int index = 0;
    LOCAL_ARRAY(char, new_key, 256);
    hash_link *table_entry = hash_lookup(fqdn_table, f->name);
    if (table_entry == NULL) {
	debug(35, 0) ("fqdncacheChangeKey: Could not find key '%s'\n", f->name);
	return;
    }
    if (f != (fqdncache_entry *) table_entry) {
	debug_trap("fqdncacheChangeKey: f != table_entry!");
	return;
    }
    hash_remove_link(fqdn_table, table_entry);
    snprintf(new_key, 256, "%d/", ++index);
    strncat(new_key, f->name, 128);
    debug(35, 1) ("fqdncacheChangeKey: from '%s' to '%s'\n", f->name, new_key);
    safe_free(f->name);
    f->name = xstrdup(new_key);
    hash_join(fqdn_table, (hash_link *) f);
}

/* call during reconfigure phase to clear out all the
 * pending and dispatched reqeusts that got lost */
void
fqdncache_restart(void)
{
    fqdncache_entry *this;
    assert(fqdn_table);
    hash_first(fqdn_table);
    while ((this = (fqdncache_entry *) hash_next(fqdn_table))) {
	if (this->status == FQDN_CACHED)
	    continue;
	if (this->status == FQDN_NEGATIVE_CACHED)
	    continue;
    }
    fqdncache_high = (long) (((float) Config.fqdncache.size *
	    (float) FQDN_HIGH_WATER) / (float) 100);
    fqdncache_low = (long) (((float) Config.fqdncache.size *
	    (float) FQDN_LOW_WATER) / (float) 100);
}

#ifdef SQUID_SNMP
/*
 * The function to return the fqdn statistics via SNMP
 */

variable_list *
snmp_netFqdnFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;

    debug(49, 5) ("snmp_netFqdnFn: Processing request:\n", Var->name[LEN_SQ_NET +
	    1]);
    snmpDebugOid(5, Var->name, Var->name_length);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(snint);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = SMI_COUNTER32;

    switch (Var->name[LEN_SQ_NET + 1]) {
    case FQDN_ENT:
	*(Answer->val.integer) = memInUse(MEM_FQDNCACHE_ENTRY);
	Answer->type = SMI_GAUGE32;
	break;
    case FQDN_REQ:
	*(Answer->val.integer) = FqdncacheStats.requests;
	break;
    case FQDN_HITS:
	*(Answer->val.integer) = FqdncacheStats.hits;
	break;
    case FQDN_PENDHIT:
	*(Answer->val.integer) = FqdncacheStats.pending_hits;
	Answer->type = SMI_GAUGE32;
	break;
    case FQDN_NEGHIT:
	*(Answer->val.integer) = FqdncacheStats.negative_hits;
	break;
    case FQDN_MISS:
	*(Answer->val.integer) = FqdncacheStats.misses;
	break;
    case FQDN_GHBN:
	*(Answer->val.integer) = FqdncacheStats.ghba_calls;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

#endif /*SQUID_SNMP */
