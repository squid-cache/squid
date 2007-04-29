
/*
 * $Id: ipcache.cc,v 1.259 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 14    IP Cache
 * AUTHOR: Harvest Derived
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
#include "cbdata.h"
#include "event.h"
#include "CacheManager.h"
#include "SquidTime.h"
#include "Store.h"
#include "wordlist.h"

typedef struct _ipcache_entry ipcache_entry;

struct _ipcache_entry
{
    hash_link hash;		/* must be first */
    time_t lastref;
    time_t expires;
    ipcache_addrs addrs;
    IPH *handler;
    void *handlerData;
    char *error_message;

    struct timeval request_time;
    dlink_node lru;
    unsigned short locks;

    struct
    {

unsigned int negcached:
        1;

unsigned int fromhosts:
        1;
    }

    flags;
};

static struct
{
    int requests;
    int replies;
    int hits;
    int misses;
    int negative_hits;
}

IpcacheStats;

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
#if USE_DNSSERVERS
static int ipcacheParse(ipcache_entry *, const char *buf);
#else
static int ipcacheParse(ipcache_entry *, rfc1035_rr *, int, const char *error);
#endif
static ipcache_entry *ipcache_get(const char *);
static void ipcacheLockEntry(ipcache_entry *);
static void ipcacheStatPrint(ipcache_entry *, StoreEntry *);
static void ipcacheUnlockEntry(ipcache_entry *);
static void ipcacheRelease(ipcache_entry *);

static ipcache_addrs static_addrs;
static hash_table *ip_table = NULL;

static long ipcache_low = 180;
static long ipcache_high = 200;

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;
#endif

static int
ipcache_testname(void)
{
    wordlist *w = NULL;
    debugs(14, 1, "Performing DNS Tests...");

    if ((w = Config.dns_testname_list) == NULL)
        return 1;

    for (; w; w = w->next) {
        if (gethostbyname(w->key) != NULL)
            return 1;
    }

    return 0;
}

/* removes the given ipcache entry */
static void
ipcacheRelease(ipcache_entry * i)
{
    debugs(14, 3, "ipcacheRelease: Releasing entry for '" << (const char *) i->hash.key << "'");

    hash_remove_link(ip_table, (hash_link *) i);
    dlinkDelete(&i->lru, &lru_list);
    ipcacheFreeEntry(i);
}

static ipcache_entry *
ipcache_get(const char *name)
{
    if (ip_table != NULL)
        return (ipcache_entry *) hash_lookup(ip_table, name);
    else
        return NULL;
}

static int
ipcacheExpiredEntry(ipcache_entry * i)
{
    /* all static entries are locked, so this takes care of them too */

    if (i->locks != 0)
        return 0;

    if (i->addrs.count == 0)
        if (0 == i->flags.negcached)
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

        i = (ipcache_entry *)m->data;

        if (i->locks != 0)
            continue;

        ipcacheRelease(i);

        removed++;
    }

    debugs(14, 9, "ipcache_purgelru: removed " << removed << " entries");
}

/* purges entries added from /etc/hosts (or whatever). */
static void
purge_entries_fromhosts(void)
{
    dlink_node *m = lru_list.head;
    ipcache_entry *i = NULL, *t;

    while (m) {
        if (i != NULL) {	/* need to delay deletion */
            ipcacheRelease(i);	/* we just override locks */
            i = NULL;
        }

        t = (ipcache_entry*)m->data;

        if (t->flags.fromhosts)
            i = t;

        m = m->next;
    }

    if (i != NULL)
        ipcacheRelease(i);
}

/* create blank ipcache_entry */
static ipcache_entry *
ipcacheCreateEntry(const char *name)
{
    static ipcache_entry *i;
    i = (ipcache_entry *)memAllocate(MEM_IPCACHE_ENTRY);
    i->hash.key = xstrdup(name);
    i->expires = squid_curtime + Config.negativeDnsTtl;
    return i;
}

static void
ipcacheAddEntry(ipcache_entry * i)
{
    hash_link *e = (hash_link *)hash_lookup(ip_table, i->hash.key);

    if (NULL != e) {
        /* avoid colission */
        ipcache_entry *q = (ipcache_entry *) e;
        ipcacheRelease(q);
    }

    hash_join(ip_table, &i->hash);
    dlinkAdd(i, &i->lru, &lru_list);
    i->lastref = squid_curtime;
}

/* walks down the pending list, calling handlers */
static void
ipcacheCallback(ipcache_entry * i)
{
    IPH *callback = i->handler;
    void *cbdata;
    i->lastref = squid_curtime;

    if (!i->handler)
        return;

    ipcacheLockEntry(i);

    callback = i->handler;

    i->handler = NULL;

    if (cbdataReferenceValidDone(i->handlerData, &cbdata)) {
        dns_error_message = i->error_message;
        callback(i->flags.negcached ? NULL : &i->addrs, cbdata);
    }

    ipcacheUnlockEntry(i);
}

#if USE_DNSSERVERS
static int
ipcacheParse(ipcache_entry *i, const char *inbuf)
{
    LOCAL_ARRAY(char, buf, DNS_INBUF_SZ);
    char *token;
    int ipcount = 0;
    int ttl;
    char *A[32];
    const char *name = (const char *)i->hash.key;
    i->expires = squid_curtime + Config.negativeDnsTtl;
    i->flags.negcached = 1;
    safe_free(i->addrs.in_addrs);
    safe_free(i->addrs.bad_mask);
    safe_free(i->error_message);
    i->addrs.count = 0;

    if (inbuf == NULL) {
        debugs(14, 1, "ipcacheParse: Got <NULL> reply");
        i->error_message = xstrdup("Internal Error");
        return -1;
    }

    xstrncpy(buf, inbuf, DNS_INBUF_SZ);
    debugs(14, 5, "ipcacheParse: parsing: {" << buf << "}");
    token = strtok(buf, w_space);

    if (NULL == token) {
        debugs(14, 1, "ipcacheParse: expecting result, got '" << inbuf << "'");

        i->error_message = xstrdup("Internal Error");
        return -1;
    }

    if (0 == strcmp(token, "$fail")) {
        token = strtok(NULL, "\n");
        assert(NULL != token);
        i->error_message = xstrdup(token);
        return 0;
    }

    if (0 != strcmp(token, "$addr")) {
        debugs(14, 1, "ipcacheParse: expecting '$addr', got '" << inbuf << "' in response to '" << name << "'");

        i->error_message = xstrdup("Internal Error");
        return -1;
    }

    token = strtok(NULL, w_space);

    if (NULL == token) {
        debugs(14, 1, "ipcacheParse: expecting TTL, got '" << inbuf << "' in response to '" << name << "'");

        i->error_message = xstrdup("Internal Error");
        return -1;
    }

    ttl = atoi(token);

    while (NULL != (token = strtok(NULL, w_space))) {
        A[ipcount] = token;

        if (++ipcount == 32)
            break;
    }

    if (ipcount > 0) {
        int j, k;

        i->addrs.in_addrs = (struct IN_ADDR *)xcalloc(ipcount, sizeof(struct IN_ADDR));
        i->addrs.bad_mask = (unsigned char *)xcalloc(ipcount, sizeof(unsigned char));

        for (j = 0, k = 0; k < ipcount; k++) {
            if (safe_inet_addr(A[k], &i->addrs.in_addrs[j]))
                j++;
            else
                debugs(14, 1, "ipcacheParse: Invalid IP address '" << A[k] << "' in response to '" << name << "'");
        }

        i->addrs.count = (unsigned char) j;
    }

    if (i->addrs.count <= 0) {
        debugs(14, 1, "ipcacheParse: No addresses in response to '" << name << "'");
        return -1;
    }

    if (ttl == 0 || ttl > Config.positiveDnsTtl)
        ttl = Config.positiveDnsTtl;

    if (ttl < Config.negativeDnsTtl)
        ttl = Config.negativeDnsTtl;

    i->expires = squid_curtime + ttl;

    i->flags.negcached = 0;

    return i->addrs.count;
}

#else
static int
ipcacheParse(ipcache_entry *i, rfc1035_rr * answers, int nr, const char *error_message)
{
    int k;
    int j;
    int na = 0;
    int ttl = 0;
    const char *name = (const char *)i->hash.key;
    i->expires = squid_curtime + Config.negativeDnsTtl;
    i->flags.negcached = 1;
    safe_free(i->addrs.in_addrs);
    safe_free(i->addrs.bad_mask);
    safe_free(i->error_message);
    i->addrs.count = 0;

    if (nr < 0) {
        debugs(14, 3, "ipcacheParse: Lookup failed '" << error_message << "' for '" << (const char *)i->hash.key << "'");
        i->error_message = xstrdup(error_message);
        return -1;
    }

    if (nr == 0) {
        debugs(14, 3, "ipcacheParse: No DNS records in response to '" << name << "'");
        i->error_message = xstrdup("No DNS records");
        return 0;
    }

    assert(answers);

    for (k = 0; k < nr; k++) {
        if (answers[k].type != RFC1035_TYPE_A)
            continue;

        if (answers[k]._class != RFC1035_CLASS_IN)
            continue;

        if (answers[k].rdlength != 4) {
            debugs(14, 1, "ipcacheParse: Invalid IP address in response to '" << name << "'");
            continue;
        }

        na++;
    }

    if (na == 0) {
        debugs(14, 1, "ipcacheParse: No Address records in response to '" << name << "'");
        i->error_message = xstrdup("No Address records");
        return 0;
    }

    i->addrs.in_addrs = (struct IN_ADDR *)xcalloc(na, sizeof(struct IN_ADDR));
    i->addrs.bad_mask = (unsigned char *)xcalloc(na, sizeof(unsigned char));

    for (j = 0, k = 0; k < nr; k++) {
        if (answers[k]._class != RFC1035_CLASS_IN)
            continue;

        if (answers[k].type == RFC1035_TYPE_A) {
            if (answers[k].rdlength != 4)
                continue;

            xmemcpy(&i->addrs.in_addrs[j++], answers[k].rdata, 4);

            debugs(14, 3, "ipcacheParse: #" << j - 1 << " " << inet_ntoa(i->addrs.in_addrs[j - 1]));

        } else if (answers[k].type != RFC1035_TYPE_CNAME)
            continue;

        if (ttl == 0 || (int) answers[k].ttl < ttl)
            ttl = answers[k].ttl;

    }

    assert(j == na);

    if (na < 256)
        i->addrs.count = (unsigned char) na;
    else
        i->addrs.count = 255;

    if (ttl == 0 || ttl > Config.positiveDnsTtl)
        ttl = Config.positiveDnsTtl;

    if (ttl < Config.negativeDnsTtl)
        ttl = Config.negativeDnsTtl;

    i->expires = squid_curtime + ttl;

    i->flags.negcached = 0;

    return i->addrs.count;
}

#endif

static void
#if USE_DNSSERVERS
ipcacheHandleReply(void *data, char *reply)
#else
ipcacheHandleReply(void *data, rfc1035_rr * answers, int na, const char *error_message)
#endif
{
    ipcache_entry *i;
    static_cast<generic_cbdata *>(data)->unwrap(&i);
    IpcacheStats.replies++;
    statHistCount(&statCounter.dns.svc_time,
                  tvSubMsec(i->request_time, current_time));
#if USE_DNSSERVERS

    ipcacheParse(i, reply);
#else

    ipcacheParse(i, answers, na, error_message);
#endif

    ipcacheAddEntry(i);
    ipcacheCallback(i);
}

void
ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData)
{
    ipcache_entry *i = NULL;
    const ipcache_addrs *addrs = NULL;
    generic_cbdata *c;
    assert(handler != NULL);
    debugs(14, 4, "ipcache_nbgethostbyname: Name '" << name << "'.");
    IpcacheStats.requests++;

    if (name == NULL || name[0] == '\0') {
        debugs(14, 4, "ipcache_nbgethostbyname: Invalid name!");
        dns_error_message = "Invalid hostname";
        handler(NULL, handlerData);
        return;
    }

    if ((addrs = ipcacheCheckNumeric(name))) {
        dns_error_message = NULL;
        handler(addrs, handlerData);
        return;
    }

    i = ipcache_get(name);

    if (NULL == i) {
        /* miss */
        (void) 0;
    } else if (ipcacheExpiredEntry(i)) {
        /* hit, but expired -- bummer */
        ipcacheRelease(i);
        i = NULL;
    } else {
        /* hit */
        debugs(14, 4, "ipcache_nbgethostbyname: HIT for '" << name << "'");

        if (i->flags.negcached)
            IpcacheStats.negative_hits++;
        else
            IpcacheStats.hits++;

        i->handler = handler;

        i->handlerData = cbdataReference(handlerData);

        ipcacheCallback(i);

        return;
    }

    debugs(14, 5, "ipcache_nbgethostbyname: MISS for '" << name << "'");
    IpcacheStats.misses++;
    i = ipcacheCreateEntry(name);
    i->handler = handler;
    i->handlerData = cbdataReference(handlerData);
    i->request_time = current_time;
    c = new generic_cbdata(i);
#if USE_DNSSERVERS

    dnsSubmit(hashKeyStr(&i->hash), ipcacheHandleReply, c);
#else

    idnsALookup(hashKeyStr(&i->hash), ipcacheHandleReply, c);
#endif
}

/* initialize the ipcache */
void
ipcache_init(void)
{
    int n;
    debugs(14, 3, "Initializing IP Cache...");
    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));
    memset(&lru_list, '\0', sizeof(lru_list));
    /* test naming lookup */

    if (!opt_dns_tests) {
        debugs(14, 4, "ipcache_init: Skipping DNS name lookup tests.");
    } else if (!ipcache_testname()) {
        fatal("ipcache_init: DNS name lookup tests failed.");
    } else {
        debugs(14, 1, "Successful DNS name lookup tests...");
    }

    memset(&static_addrs, '\0', sizeof(ipcache_addrs));

    static_addrs.in_addrs = (struct IN_ADDR *)xcalloc(1, sizeof(struct IN_ADDR));
    static_addrs.bad_mask = (unsigned char *)xcalloc(1, sizeof(unsigned char));
    ipcache_high = (long) (((float) Config.ipcache.size *
                            (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
                           (float) Config.ipcache.low) / (float) 100);
    n = hashPrime(ipcache_high / 4);
    ip_table = hash_create((HASHCMP *) strcmp, n, hash4);
    memDataInit(MEM_IPCACHE_ENTRY, "ipcache_entry", sizeof(ipcache_entry), 0);
}

void
ipcacheRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("ipcache",
                           "IP Cache Stats and Contents",
                           stat_ipcache_get, 0, 1);
}

const ipcache_addrs *
ipcache_gethostbyname(const char *name, int flags)
{
    ipcache_entry *i = NULL;
    ipcache_addrs *addrs;
    assert(name);
    debugs(14, 3, "ipcache_gethostbyname: '" << name  << "', flags=" << std::hex << flags);
    IpcacheStats.requests++;
    i = ipcache_get(name);

    if (NULL == i) {
        (void) 0;
    } else if (ipcacheExpiredEntry(i)) {
        ipcacheRelease(i);
        i = NULL;
    } else if (i->flags.negcached) {
        IpcacheStats.negative_hits++;
        dns_error_message = i->error_message;
        return NULL;
    } else {
        IpcacheStats.hits++;
        i->lastref = squid_curtime;
        dns_error_message = i->error_message;
        return &i->addrs;
    }

    dns_error_message = NULL;

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
    storeAppendPrintf(sentry, " %-32.32s %c%c %6d %6d %2d(%2d)",
                      hashKeyStr(&i->hash),
                      i->flags.fromhosts ? 'H' : ' ',
                      i->flags.negcached ? 'N' : ' ',
                      (int) (squid_curtime - i->lastref),
                      (int) ((i->flags.fromhosts ? -1 : i->expires - squid_curtime)),
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
    storeAppendPrintf(sentry, "IPcache Negative Hits: %d\n",
                      IpcacheStats.negative_hits);
    storeAppendPrintf(sentry, "IPcache Misses: %d\n",
                      IpcacheStats.misses);
    storeAppendPrintf(sentry, "\n\n");
    storeAppendPrintf(sentry, "IP Cache Contents:\n\n");
    storeAppendPrintf(sentry, " %-29.29s %3s %6s %6s %1s\n",
                      "Hostname",
                      "Flg",
                      "lstref",
                      "TTL",
                      "N");

    for (m = lru_list.head; m; m = m->next)
        ipcacheStatPrint((ipcache_entry *)m->data, sentry);
}

static void
dummy_handler(const ipcache_addrs * addrsnotused, void *datanotused)
{
    return;
}

void
ipcacheInvalidate(const char *name)
{
    ipcache_entry *i;

    if ((i = ipcache_get(name)) == NULL)
        return;

    i->expires = squid_curtime;

    /*
     * NOTE, don't call ipcacheRelease here becuase we might be here due
     * to a thread started from a callback.
     */
}

void
ipcacheInvalidateNegative(const char *name)
{
    ipcache_entry *i;

    if ((i = ipcache_get(name)) == NULL)
        return;

    if (i->flags.negcached)
        i->expires = squid_curtime;

    /*
     * NOTE, don't call ipcacheRelease here becuase we might be here due
     * to a thread started from a callback.
     */
}

ipcache_addrs *
ipcacheCheckNumeric(const char *name)
{

    struct IN_ADDR ip;
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
        ipcacheRelease(i);
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

        if (i->flags.negcached)
            return;

        ia = &i->addrs;
    }

    for (k = 0; k < ia->count; k++) {
        if (++ia->cur == ia->count)
            ia->cur = 0;

        if (!ia->bad_mask[ia->cur])
            break;
    }

    if (k == ia->count) {
        /* All bad, reset to All good */
        debugs(14, 3, "ipcacheCycleAddr: Changing ALL " << name << " addrs from BAD to OK");

        for (k = 0; k < ia->count; k++)
            ia->bad_mask[k] = 0;

        ia->badcount = 0;

        ia->cur = 0;
    }

    debugs(14, 3, "ipcacheCycleAddr: " << name << " now at " << inet_ntoa(ia->in_addrs[ia->cur]));
}

/*
 * Marks the given address as BAD and calls ipcacheCycleAddr to
 * advance the current pointer to the next OK address.
 */
void

ipcacheMarkBadAddr(const char *name, struct IN_ADDR addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;

    if ((i = ipcache_get(name)) == NULL)
        return;

    ia = &i->addrs;

    for (k = 0; k < (int) ia->count; k++)
    {
        if (ia->in_addrs[k].s_addr == addr.s_addr)
            break;
    }

    if (k == (int) ia->count)	/* not found */
        return;

    if (!ia->bad_mask[k])
    {
        ia->bad_mask[k] = TRUE;
        ia->badcount++;
        i->expires = XMIN(squid_curtime + XMAX((time_t)60, Config.negativeDnsTtl), i->expires);
        debugs(14, 2, "ipcacheMarkBadAddr: " << name << " [" << inet_ntoa(addr) << "]");
    }

    ipcacheCycleAddr(name, ia);
}

void

ipcacheMarkGoodAddr(const char *name, struct IN_ADDR addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;

    if ((i = ipcache_get(name)) == NULL)
        return;

    ia = &i->addrs;

    for (k = 0; k < (int) ia->count; k++)
    {
        if (ia->in_addrs[k].s_addr == addr.s_addr)
            break;
    }

    if (k == (int) ia->count)	/* not found */
        return;

    if (!ia->bad_mask[k])	/* already OK */
        return;

    ia->bad_mask[k] = FALSE;

    ia->badcount--;

    debugs(14, 2, "ipcacheMarkGoodAddr: " << name << " [" << inet_ntoa(addr) << "]");
}

static void
ipcacheFreeEntry(void *data)
{
    ipcache_entry *i = (ipcache_entry *)data;
    safe_free(i->addrs.in_addrs);
    safe_free(i->addrs.bad_mask);
    safe_free(i->hash.key);
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

/* Recalculate IP cache size upon reconfigure */
void
ipcache_restart(void)
{
    ipcache_high = (long) (((float) Config.ipcache.size *
                            (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
                           (float) Config.ipcache.low) / (float) 100);
    purge_entries_fromhosts();
}

/*
 *  adds a "static" entry from /etc/hosts.  
 *  returns 0 upon success, 1 if the ip address is invalid
 */
int
ipcacheAddEntryFromHosts(const char *name, const char *ipaddr)
{
    ipcache_entry *i;

    struct IN_ADDR ip;

    if (!safe_inet_addr(ipaddr, &ip)) {
        if (strchr(ipaddr, ':') && strspn(ipaddr, "0123456789abcdefABCDEF:") == strlen(ipaddr)) {
            debugs(14, 3, "ipcacheAddEntryFromHosts: Skipping IPv6 address '" << ipaddr << "'");
        } else {
            debugs(14, 1, "ipcacheAddEntryFromHosts: Bad IP address '" << ipaddr << "'");
        }

        return 1;
    }

    if ((i = ipcache_get(name))) {
        if (1 == i->flags.fromhosts) {
            ipcacheUnlockEntry(i);
        } else if (i->locks > 0) {
            debugs(14, 1, "ipcacheAddEntryFromHosts: can't add static entry for locked name '" << name << "'");
            return 1;
        } else {
            ipcacheRelease(i);
        }
    }

    i = ipcacheCreateEntry(name);
    i->addrs.count = 1;
    i->addrs.cur = 0;
    i->addrs.badcount = 0;

    i->addrs.in_addrs = (struct IN_ADDR *)xcalloc(1, sizeof(struct IN_ADDR));
    i->addrs.bad_mask = (unsigned char *)xcalloc(1, sizeof(unsigned char));
    i->addrs.in_addrs[0].s_addr = ip.s_addr;
    i->addrs.bad_mask[0] = FALSE;
    i->flags.fromhosts = 1;
    ipcacheAddEntry(i);
    ipcacheLockEntry(i);
    return 0;
}

#ifdef SQUID_SNMP
/*
 * The function to return the ip cache statistics to via SNMP
 */

variable_list *
snmp_netIpFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;
    debugs(49, 5, "snmp_netIpFn: Processing request:");
    snmpDebugOid(5, Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_NET + 1]) {

    case IP_ENT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      memInUse(MEM_IPCACHE_ENTRY),
                                      SMI_GAUGE32);
        break;

    case IP_REQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      IpcacheStats.requests,
                                      SMI_COUNTER32);
        break;

    case IP_HITS:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      IpcacheStats.hits,
                                      SMI_COUNTER32);
        break;

    case IP_PENDHIT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      0,
                                      SMI_GAUGE32);
        break;

    case IP_NEGHIT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      IpcacheStats.negative_hits,
                                      SMI_COUNTER32);
        break;

    case IP_MISS:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      IpcacheStats.misses,
                                      SMI_COUNTER32);
        break;

    case IP_GHBN:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      0, /* deprecated */
                                      SMI_COUNTER32);
        break;

    case IP_LOC:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      0, /* deprecated */
                                      SMI_COUNTER32);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        snmp_var_free(Answer);
        return (NULL);
    }

    return Answer;
}

#endif /*SQUID_SNMP */
