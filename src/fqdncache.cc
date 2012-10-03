/*
 * DEBUG: section 35    FQDN Cache
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
#include "DnsLookupDetails.h"
#include "event.h"
#include "Mem.h"
#include "mgr/Registration.h"
#include "SquidConfig.h"
#include "SquidDns.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "wordlist.h"

#if SQUID_SNMP
#include "snmp_core.h"
#endif

/**
 \defgroup FQDNCacheAPI FQDN Cache API
 \ingroup Components
 \section Introduction Introduction
 \par
 *  The FQDN cache is a built-in component of squid providing
 *  Hostname to IP-Number translation functionality and managing
 *  the involved data-structures. Efficiency concerns require
 *  mechanisms that allow non-blocking access to these mappings.
 *  The FQDN cache usually doesn't block on a request except for
 *  special cases where this is desired (see below).
 *
 \todo FQDN Cache should have its own API *.h file.
 */

/**
 \defgroup FQDNCacheInternal FQDN Cache Internals
 \ingroup FQDNCacheAPI
 \par
 *  Internally, the execution flow is as follows:
 *  On a miss, fqdncache_nbgethostbyaddr() checks whether a request
 *  for this name is already pending, and if positive, it creates a
 *  new entry using fqdncacheAddEntry(). Then it calls
 *  fqdncacheAddPending() to add a request to the queue together
 *  with data and handler.  Else, ifqdncache_dnsDispatch() is called
 *  to directly create a DNS query or to fqdncacheEnqueue() if all
 *  no DNS port is free.
 *
 \par
 *  fqdncacheCallback() is called regularly to walk down the pending
 *  list and call handlers.
 *
 \par
 *  LRU clean-up is performed through fqdncache_purgelru() according
 *  to the fqdncache_high threshold.
 */

/// \ingroup FQDNCacheInternal
#define FQDN_LOW_WATER       90

/// \ingroup FQDNCacheInternal
#define FQDN_HIGH_WATER      95

/**
 \ingroup FQDNCacheAPI
 * The data structure used for storing name-address mappings
 * is a small hashtable (static hash_table *fqdn_table),
 * where structures of type fqdncache_entry whose most
 * interesting members are:
 */
class fqdncache_entry
{
public:
    hash_link hash;		/* must be first */
    time_t lastref;
    time_t expires;
    unsigned char name_count;
    char *names[FQDN_MAX_NAMES + 1];
    FQDNH *handler;
    void *handlerData;
    char *error_message;

    struct timeval request_time;
    dlink_node lru;
    unsigned short locks;

    struct {
        unsigned int negcached:1;
        unsigned int fromhosts:1;
    } flags;

    int age() const; ///< time passed since request_time or -1 if unknown
};

/// \ingroup FQDNCacheInternal
static struct _fqdn_cache_stats {
    int requests;
    int replies;
    int hits;
    int misses;
    int negative_hits;
} FqdncacheStats;

/// \ingroup FQDNCacheInternal
static dlink_list lru_list;

#if USE_DNSHELPER
static HLPCB fqdncacheHandleReply;
static int fqdncacheParse(fqdncache_entry *, const char *buf);
#else
static IDNSCB fqdncacheHandleReply;
static int fqdncacheParse(fqdncache_entry *, const rfc1035_rr *, int, const char *error_message);
#endif
static void fqdncacheRelease(fqdncache_entry *);
static fqdncache_entry *fqdncacheCreateEntry(const char *name);
static void fqdncacheCallback(fqdncache_entry *, int wait);
static fqdncache_entry *fqdncache_get(const char *);
static int fqdncacheExpiredEntry(const fqdncache_entry *);
static void fqdncacheLockEntry(fqdncache_entry * f);
static void fqdncacheUnlockEntry(fqdncache_entry * f);
static FREE fqdncacheFreeEntry;
static void fqdncacheAddEntry(fqdncache_entry * f);

/// \ingroup FQDNCacheInternal
static hash_table *fqdn_table = NULL;

/// \ingroup FQDNCacheInternal
static long fqdncache_low = 180;

/// \ingroup FQDNCacheInternal
static long fqdncache_high = 200;

/// \ingroup FQDNCacheInternal
inline int fqdncacheCount() { return fqdn_table ? fqdn_table->count : 0; }

int
fqdncache_entry::age() const
{
    return request_time.tv_sec ? tvSubMsec(request_time, current_time) : -1;
}

/**
 \ingroup FQDNCacheInternal
 * Removes the given fqdncache entry
 */
static void
fqdncacheRelease(fqdncache_entry * f)
{
    int k;
    hash_remove_link(fqdn_table, (hash_link *) f);

    for (k = 0; k < (int) f->name_count; ++k)
        safe_free(f->names[k]);

    debugs(35, 5, "fqdncacheRelease: Released FQDN record for '" << hashKeyStr(&f->hash) << "'.");

    dlinkDelete(&f->lru, &lru_list);

    safe_free(f->hash.key);

    safe_free(f->error_message);

    memFree(f, MEM_FQDNCACHE_ENTRY);
}

/**
 \ingroup FQDNCacheInternal
 \param name	FQDN hash string.
 \retval Match for given name
 */
static fqdncache_entry *
fqdncache_get(const char *name)
{
    hash_link *e;
    static fqdncache_entry *f;
    f = NULL;

    if (fqdn_table) {
        if ((e = (hash_link *)hash_lookup(fqdn_table, name)) != NULL)
            f = (fqdncache_entry *) e;
    }

    return f;
}

/// \ingroup FQDNCacheInternal
static int
fqdncacheExpiredEntry(const fqdncache_entry * f)
{
    /* all static entries are locked, so this takes care of them too */

    if (f->locks != 0)
        return 0;

    if (f->expires > squid_curtime)
        return 0;

    return 1;
}

/// \ingroup FQDNCacheAPI
void
fqdncache_purgelru(void *notused)
{
    dlink_node *m;
    dlink_node *prev = NULL;
    fqdncache_entry *f;
    int removed = 0;
    eventAdd("fqdncache_purgelru", fqdncache_purgelru, NULL, 10.0, 1);

    for (m = lru_list.tail; m; m = prev) {
        if (fqdncacheCount() < fqdncache_low)
            break;

        prev = m->prev;

        f = (fqdncache_entry *)m->data;

        if (f->locks != 0)
            continue;

        fqdncacheRelease(f);

        ++removed;
    }

    debugs(35, 9, "fqdncache_purgelru: removed " << removed << " entries");
}

/// \ingroup FQDNCacheAPI
static void
purge_entries_fromhosts(void)
{
    dlink_node *m = lru_list.head;
    fqdncache_entry *i = NULL;
    fqdncache_entry *t;

    while (m) {
        if (i != NULL) {	/* need to delay deletion */
            fqdncacheRelease(i);	/* we just override locks */
            i = NULL;
        }

        t = (fqdncache_entry *)m->data;

        if (t->flags.fromhosts)
            i = t;

        m = m->next;
    }

    if (i != NULL)
        fqdncacheRelease(i);
}

/**
 \ingroup FQDNCacheInternal
 *
 * Create blank fqdncache_entry
 */
static fqdncache_entry *
fqdncacheCreateEntry(const char *name)
{
    static fqdncache_entry *f;
    f = (fqdncache_entry *)memAllocate(MEM_FQDNCACHE_ENTRY);
    f->hash.key = xstrdup(name);
    f->expires = squid_curtime + Config.negativeDnsTtl;
    return f;
}

/// \ingroup FQDNCacheInternal
static void
fqdncacheAddEntry(fqdncache_entry * f)
{
    hash_link *e = (hash_link *)hash_lookup(fqdn_table, f->hash.key);

    if (NULL != e) {
        /* avoid colission */
        fqdncache_entry *q = (fqdncache_entry *) e;
        fqdncacheRelease(q);
    }

    hash_join(fqdn_table, &f->hash);
    dlinkAdd(f, &f->lru, &lru_list);
    f->lastref = squid_curtime;
}

/**
 \ingroup FQDNCacheInternal
 *
 * Walks down the pending list, calling handlers
 */
static void
fqdncacheCallback(fqdncache_entry * f, int wait)
{
    FQDNH *callback;
    void *cbdata;
    f->lastref = squid_curtime;

    if (!f->handler)
        return;

    fqdncacheLockEntry(f);

    callback = f->handler;

    f->handler = NULL;

    if (cbdataReferenceValidDone(f->handlerData, &cbdata)) {
        const DnsLookupDetails details(f->error_message, wait);
        callback(f->name_count ? f->names[0] : NULL, details, cbdata);
    }

    fqdncacheUnlockEntry(f);
}

/// \ingroup FQDNCacheInternal
#if USE_DNSHELPER
static int
fqdncacheParse(fqdncache_entry *f, const char *inbuf)
{
    LOCAL_ARRAY(char, buf, DNS_INBUF_SZ);
    char *token;
    int ttl;
    const char *name = (const char *)f->hash.key;
    f->expires = squid_curtime + Config.negativeDnsTtl;
    f->flags.negcached = 1;

    if (inbuf == NULL) {
        debugs(35, DBG_IMPORTANT, "fqdncacheParse: Got <NULL> reply in response to '" << name << "'");
        f->error_message = xstrdup("Internal Error");
        return -1;
    }

    xstrncpy(buf, inbuf, DNS_INBUF_SZ);
    debugs(35, 5, "fqdncacheParse: parsing: {" << buf << "}");
    token = strtok(buf, w_space);

    if (NULL == token) {
        debugs(35, DBG_IMPORTANT, "fqdncacheParse: Got <NULL>, expecting '$name' in response to '" << name << "'");
        f->error_message = xstrdup("Internal Error");
        return -1;
    }

    if (0 == strcmp(token, "$fail")) {
        token = strtok(NULL, "\n");
        assert(NULL != token);
        f->error_message = xstrdup(token);
        return 0;
    }

    if (0 != strcmp(token, "$name")) {
        debugs(35, DBG_IMPORTANT, "fqdncacheParse: Got '" << inbuf << "', expecting '$name' in response to '" << name << "'");
        f->error_message = xstrdup("Internal Error");
        return -1;
    }

    token = strtok(NULL, w_space);

    if (NULL == token) {
        debugs(35, DBG_IMPORTANT, "fqdncacheParse: Got '" << inbuf << "', expecting TTL in response to '" << name << "'");
        f->error_message = xstrdup("Internal Error");
        return -1;
    }

    ttl = atoi(token);

    token = strtok(NULL, w_space);

    if (NULL == token) {
        debugs(35, DBG_IMPORTANT, "fqdncacheParse: Got '" << inbuf << "', expecting hostname in response to '" << name << "'");
        f->error_message = xstrdup("Internal Error");
        return -1;
    }

    f->names[0] = xstrdup(token);
    f->name_count = 1;

    if (ttl == 0 || ttl > Config.positiveDnsTtl)
        ttl = Config.positiveDnsTtl;

    if (ttl < Config.negativeDnsTtl)
        ttl = Config.negativeDnsTtl;

    f->expires = squid_curtime + ttl;

    f->flags.negcached = 0;

    return f->name_count;
}

#else
static int
fqdncacheParse(fqdncache_entry *f, const rfc1035_rr * answers, int nr, const char *error_message)
{
    int k;
    int ttl = 0;
    const char *name = (const char *)f->hash.key;
    f->expires = squid_curtime + Config.negativeDnsTtl;
    f->flags.negcached = 1;

    if (nr < 0) {
        debugs(35, 3, "fqdncacheParse: Lookup of '" << name << "' failed (" << error_message << ")");
        f->error_message = xstrdup(error_message);
        return -1;
    }

    if (nr == 0) {
        debugs(35, 3, "fqdncacheParse: No DNS records for '" << name << "'");
        f->error_message = xstrdup("No DNS records");
        return 0;
    }

    debugs(35, 3, "fqdncacheParse: " << nr << " answers for '" << name << "'");
    assert(answers);

    for (k = 0; k < nr; ++k) {
        if (answers[k]._class != RFC1035_CLASS_IN)
            continue;

        if (answers[k].type == RFC1035_TYPE_PTR) {
            if (!answers[k].rdata[0]) {
                debugs(35, 2, "fqdncacheParse: blank PTR record for '" << name << "'");
                continue;
            }

            if (strchr(answers[k].rdata, ' ')) {
                debugs(35, 2, "fqdncacheParse: invalid PTR record '" << answers[k].rdata << "' for '" << name << "'");
                continue;
            }

            f->names[f->name_count] = xstrdup(answers[k].rdata);
            ++ f->name_count;
        } else if (answers[k].type != RFC1035_TYPE_CNAME)
            continue;

        if (ttl == 0 || (int) answers[k].ttl < ttl)
            ttl = answers[k].ttl;

        if (f->name_count >= FQDN_MAX_NAMES)
            break;
    }

    if (f->name_count == 0) {
        debugs(35, DBG_IMPORTANT, "fqdncacheParse: No PTR record for '" << name << "'");
        return 0;
    }

    if (ttl > Config.positiveDnsTtl)
        ttl = Config.positiveDnsTtl;

    if (ttl < Config.negativeDnsTtl)
        ttl = Config.negativeDnsTtl;

    f->expires = squid_curtime + ttl;

    f->flags.negcached = 0;

    return f->name_count;
}

#endif

/**
 \ingroup FQDNCacheAPI
 *
 * Callback for handling DNS results.
 */
static void
#if USE_DNSHELPER
fqdncacheHandleReply(void *data, char *reply)
#else
fqdncacheHandleReply(void *data, const rfc1035_rr * answers, int na, const char *error_message)
#endif
{
    fqdncache_entry *f;
    static_cast<generic_cbdata *>(data)->unwrap(&f);
    ++FqdncacheStats.replies;
    const int age = f->age();
    statCounter.dns.svcTime.count(age);
#if USE_DNSHELPER

    fqdncacheParse(f, reply);
#else

    fqdncacheParse(f, answers, na, error_message);
#endif

    fqdncacheAddEntry(f);

    fqdncacheCallback(f, age);
}

/**
 \ingroup FQDNCacheAPI
 *
 \param addr		IP address of domain to resolve.
 \param handler		A pointer to the function to be called when
 *			the reply from the FQDN cache
 * 			(or the DNS if the FQDN cache misses)
 \param handlerData	Information that is passed to the handler
 * 			and does not affect the FQDN cache.
 */
void
fqdncache_nbgethostbyaddr(const Ip::Address &addr, FQDNH * handler, void *handlerData)
{
    fqdncache_entry *f = NULL;
    char name[MAX_IPSTRLEN];
    generic_cbdata *c;
    addr.NtoA(name,MAX_IPSTRLEN);
    debugs(35, 4, "fqdncache_nbgethostbyaddr: Name '" << name << "'.");
    ++FqdncacheStats.requests;

    if (name[0] == '\0') {
        debugs(35, 4, "fqdncache_nbgethostbyaddr: Invalid name!");
        const DnsLookupDetails details("Invalid hostname", -1); // error, no lookup
        if (handler)
            handler(NULL, details, handlerData);
        return;
    }

    f = fqdncache_get(name);

    if (NULL == f) {
        /* miss */
        (void) 0;
    } else if (fqdncacheExpiredEntry(f)) {
        /* hit, but expired -- bummer */
        fqdncacheRelease(f);
        f = NULL;
    } else {
        /* hit */
        debugs(35, 4, "fqdncache_nbgethostbyaddr: HIT for '" << name << "'");

        if (f->flags.negcached)
            ++ FqdncacheStats.negative_hits;
        else
            ++ FqdncacheStats.hits;

        f->handler = handler;

        f->handlerData = cbdataReference(handlerData);

        fqdncacheCallback(f, -1); // no lookup

        return;
    }

    debugs(35, 5, "fqdncache_nbgethostbyaddr: MISS for '" << name << "'");
    ++ FqdncacheStats.misses;
    f = fqdncacheCreateEntry(name);
    f->handler = handler;
    f->handlerData = cbdataReference(handlerData);
    f->request_time = current_time;
    c = new generic_cbdata(f);
#if USE_DNSHELPER
    dnsSubmit(hashKeyStr(&f->hash), fqdncacheHandleReply, c);
#else
    idnsPTRLookup(addr, fqdncacheHandleReply, c);
#endif
}

/**
 \ingroup FQDNCacheAPI
 *
 * Is different in that it only checks if an entry exists in
 * it's data-structures and does not by default contact the
 * DNS, unless this is requested, by setting the flags
 * to FQDN_LOOKUP_IF_MISS.
 *
 \param addr	address of the FQDN being resolved
 \param flags	values are NULL or FQDN_LOOKUP_IF_MISS. default is NULL.
 *
 */
const char *
fqdncache_gethostbyaddr(const Ip::Address &addr, int flags)
{
    char name[MAX_IPSTRLEN];
    fqdncache_entry *f = NULL;

    if (addr.IsAnyAddr() || addr.IsNoAddr()) {
        return NULL;
    }

    addr.NtoA(name,MAX_IPSTRLEN);
    ++ FqdncacheStats.requests;
    f = fqdncache_get(name);

    if (NULL == f) {
        (void) 0;
    } else if (fqdncacheExpiredEntry(f)) {
        fqdncacheRelease(f);
        f = NULL;
    } else if (f->flags.negcached) {
        ++ FqdncacheStats.negative_hits;
        // ignore f->error_message: the caller just checks FQDN cache presence
        return NULL;
    } else {
        ++ FqdncacheStats.hits;
        f->lastref = squid_curtime;
        // ignore f->error_message: the caller just checks FQDN cache presence
        return f->names[0];
    }

    /* no entry [any more] */

    ++ FqdncacheStats.misses;

    if (flags & FQDN_LOOKUP_IF_MISS) {
        fqdncache_nbgethostbyaddr(addr, NULL, NULL);
    }

    return NULL;
}

/**
 \ingroup FQDNCacheInternal
 *
 * Process objects list
 */
void
fqdnStats(StoreEntry * sentry)
{
    fqdncache_entry *f = NULL;
    int k;
    int ttl;

    if (fqdn_table == NULL)
        return;

    storeAppendPrintf(sentry, "FQDN Cache Statistics:\n");

    storeAppendPrintf(sentry, "FQDNcache Entries In Use: %d\n",
                      memInUse(MEM_FQDNCACHE_ENTRY));

    storeAppendPrintf(sentry, "FQDNcache Entries Cached: %d\n",
                      fqdncacheCount());

    storeAppendPrintf(sentry, "FQDNcache Requests: %d\n",
                      FqdncacheStats.requests);

    storeAppendPrintf(sentry, "FQDNcache Hits: %d\n",
                      FqdncacheStats.hits);

    storeAppendPrintf(sentry, "FQDNcache Negative Hits: %d\n",
                      FqdncacheStats.negative_hits);

    storeAppendPrintf(sentry, "FQDNcache Misses: %d\n",
                      FqdncacheStats.misses);

    storeAppendPrintf(sentry, "FQDN Cache Contents:\n\n");

    storeAppendPrintf(sentry, "%-45.45s %3s %3s %3s %s\n",
                      "Address", "Flg", "TTL", "Cnt", "Hostnames");

    hash_first(fqdn_table);

    while ((f = (fqdncache_entry *) hash_next(fqdn_table))) {
        ttl = (f->flags.fromhosts ? -1 : (f->expires - squid_curtime));
        storeAppendPrintf(sentry, "%-45.45s  %c%c %3.3d % 3d",
                          hashKeyStr(&f->hash),
                          f->flags.negcached ? 'N' : ' ',
                          f->flags.fromhosts ? 'H' : ' ',
                          ttl,
                          (int) f->name_count);

        for (k = 0; k < (int) f->name_count; ++k)
            storeAppendPrintf(sentry, " %s", f->names[k]);

        storeAppendPrintf(sentry, "\n");
    }
}

/// \ingroup FQDNCacheAPI
#if 0
const char *
fqdnFromAddr(const Ip::Address &addr)
{
    const char *n;
    static char buf[MAX_IPSTRLEN];

    if (Config.onoff.log_fqdn && (n = fqdncache_gethostbyaddr(addr, 0)))
        return n;

/// \todo Perhapse this should use toHostname() instead of straight NtoA.
///       that would wrap the IPv6 properly when raw.
    addr.NtoA(buf, MAX_IPSTRLEN);

    return buf;
}
#endif

/// \ingroup FQDNCacheInternal
static void
fqdncacheLockEntry(fqdncache_entry * f)
{
    if (f->locks++ == 0) {
        dlinkDelete(&f->lru, &lru_list);
        dlinkAdd(f, &f->lru, &lru_list);
    }
}

/// \ingroup FQDNCacheInternal
static void
fqdncacheUnlockEntry(fqdncache_entry * f)
{
    assert(f->locks > 0);
    -- f->locks;

    if (fqdncacheExpiredEntry(f))
        fqdncacheRelease(f);
}

/// \ingroup FQDNCacheInternal
static void
fqdncacheFreeEntry(void *data)
{
    fqdncache_entry *f = (fqdncache_entry *)data;
    int k;

    for (k = 0; k < (int) f->name_count; ++k)
        safe_free(f->names[k]);

    safe_free(f->hash.key);

    safe_free(f->error_message);

    memFree(f, MEM_FQDNCACHE_ENTRY);
}

/// \ingroup FQDNCacheAPI
void
fqdncacheFreeMemory(void)
{
    hashFreeItems(fqdn_table, fqdncacheFreeEntry);
    hashFreeMemory(fqdn_table);
    fqdn_table = NULL;
}

/**
 \ingroup FQDNCacheAPI
 *
 * Recalculate FQDN cache size upon reconfigure.
 * Is called to clear the FQDN cache's data structures,
 * cancel all pending requests.
 */
void
fqdncache_restart(void)
{
    fqdncache_high = (long) (((float) Config.fqdncache.size *
                              (float) FQDN_HIGH_WATER) / (float) 100);
    fqdncache_low = (long) (((float) Config.fqdncache.size *
                             (float) FQDN_LOW_WATER) / (float) 100);
    purge_entries_fromhosts();
}

/**
 \ingroup FQDNCacheAPI
 *
 * Adds a "static" entry from /etc/hosts.
 \par
 * The worldist is to be managed by the caller,
 * including pointed-to strings
 *
 \param addr		FQDN name to be added.
 \param hostnames	??
 */
void
fqdncacheAddEntryFromHosts(char *addr, wordlist * hostnames)
{
    fqdncache_entry *fce;
    int j = 0;

    if ((fce = fqdncache_get(addr))) {
        if (1 == fce->flags.fromhosts) {
            fqdncacheUnlockEntry(fce);
        } else if (fce->locks > 0) {
            debugs(35, DBG_IMPORTANT, "fqdncacheAddEntryFromHosts: can't add static entry for locked address '" << addr << "'");
            return;
        } else {
            fqdncacheRelease(fce);
        }
    }

    fce = fqdncacheCreateEntry(addr);

    while (hostnames) {
        fce->names[j] = xstrdup(hostnames->key);
        Tolower(fce->names[j]);
        ++j;
        hostnames = hostnames->next;

        if (j >= FQDN_MAX_NAMES)
            break;
    }

    fce->name_count = j;
    fce->names[j] = NULL;	/* it's safe */
    fce->flags.fromhosts = 1;
    fqdncacheAddEntry(fce);
    fqdncacheLockEntry(fce);
}

/// \ingroup FQDNCacheInternal
static void
fqdncacheRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("fqdncache", "FQDN Cache Stats and Contents",
                        fqdnStats, 0, 1);

}

/**
 \ingroup FQDNCacheAPI
 *
 * Initialize the fqdncache.
 * Called after IP cache initialization.
 */
void
fqdncache_init(void)
{
    int n;

    fqdncacheRegisterWithCacheManager();

    if (fqdn_table)
        return;

    debugs(35, 3, "Initializing FQDN Cache...");

    memset(&FqdncacheStats, '\0', sizeof(FqdncacheStats));

    memset(&lru_list, '\0', sizeof(lru_list));

    fqdncache_high = (long) (((float) Config.fqdncache.size *
                              (float) FQDN_HIGH_WATER) / (float) 100);

    fqdncache_low = (long) (((float) Config.fqdncache.size *
                             (float) FQDN_LOW_WATER) / (float) 100);

    n = hashPrime(fqdncache_high / 4);

    fqdn_table = hash_create((HASHCMP *) strcmp, n, hash4);

    memDataInit(MEM_FQDNCACHE_ENTRY, "fqdncache_entry",
                sizeof(fqdncache_entry), 0);
}

#if SQUID_SNMP
/**
 *  \ingroup FQDNCacheAPI
 * The function to return the FQDN statistics via SNMP
 */
variable_list *
snmp_netFqdnFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;
    MemBuf tmp;
    debugs(49, 5, "snmp_netFqdnFn: Processing request:" << snmpDebugOid(Var->name, Var->name_length, tmp));
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_NET + 1]) {

    case FQDN_ENT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      fqdncacheCount(),
                                      SMI_GAUGE32);
        break;

    case FQDN_REQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      FqdncacheStats.requests,
                                      SMI_COUNTER32);
        break;

    case FQDN_HITS:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      FqdncacheStats.hits,
                                      SMI_COUNTER32);
        break;

    case FQDN_PENDHIT:
        /* this is now worthless */
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      0,
                                      SMI_GAUGE32);
        break;

    case FQDN_NEGHIT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      FqdncacheStats.negative_hits,
                                      SMI_COUNTER32);
        break;

    case FQDN_MISS:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      FqdncacheStats.misses,
                                      SMI_COUNTER32);
        break;

    case FQDN_GHBN:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      0, /* deprecated */
                                      SMI_COUNTER32);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        break;
    }

    return Answer;
}

#endif /*SQUID_SNMP */
