/*
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
#include "CacheManager.h"
#include "cbdata.h"
#include "event.h"
#include "ip/tools.h"
#include "SquidTime.h"
#include "Store.h"
#include "wordlist.h"
#include "ip/IpAddress.h"

/**
 \defgroup IPCacheAPI IP Cache API
 \ingroup Components
 \section Introduction Introduction
 \par
 *  The IP cache is a built-in component of squid providing
 *  Hostname to IP-Number translation functionality and managing
 *  the involved data-structures. Efficiency concerns require
 *  mechanisms that allow non-blocking access to these mappings.
 *  The IP cache usually doesn't block on a request except for
 *  special cases where this is desired (see below).
 *
 \todo IP Cache should have its own API *.h header file.
 */

/**
 \defgroup IPCacheInternal IP Cache Internals
 \ingroup IPCacheAPI
 \todo  when IP cache is provided as a class. These sub-groups will be obsolete
 *	for now they are used to seperate the public and private functions.
 *	with the private ones all being in IPCachInternal and public in IPCacheAPI
 *
 \section InternalOperation Internal Operation
 *
 * Internally, the execution flow is as follows: On a miss,
 * ipcache_getnbhostbyname checks whether a request for
 * this name is already pending, and if positive, it creates
 * a new entry using ipcacheAddNew with the IP_PENDING
 * flag set . Then it calls ipcacheAddPending to add a
 * request to the queue together with data and handler.  Else,
 * ipcache_dnsDispatch() is called to directly create a
 * DNS query or to ipcacheEnqueue() if all no DNS port
 * is free.  ipcache_call_pending() is called regularly
 * to walk down the pending list and call handlers. LRU clean-up
 * is performed through ipcache_purgelru() according to
 * the ipcache_high threshold.
 */

/**
 \ingroup IPCacheAPI
 *
 * The data structure used for storing name-address mappings
 * is a small hashtable (static hash_table *ip_table),
 * where structures of type ipcache_entry whose most
 * interesting members are:
 */
class ipcache_entry
{
public:
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
#if DNS_CNAME
    unsigned short cname_wait;
#endif

    struct {
        unsigned int negcached:1;
        unsigned int fromhosts:1;
    } flags;

    int age() const; ///< time passed since request_time or -1 if unknown
};

/// \ingroup IPCacheInternal
static struct _ipcache_stats {
    int requests;
    int replies;
    int hits;
    int misses;
    int negative_hits;
    int numeric_hits;
    int rr_a;
    int rr_aaaa;
    int rr_cname;
    int cname_only;
    int invalid;
} IpcacheStats;

/// \ingroup IPCacheInternal
static dlink_list lru_list;

static FREE ipcacheFreeEntry;
#if USE_DNSSERVERS
static HLPCB ipcacheHandleReply;
#else
static IDNSCB ipcacheHandleReply;
#endif
static IPH ipcacheHandleCnameRecurse;
static int ipcacheExpiredEntry(ipcache_entry *);
#if USE_DNSSERVERS
static int ipcacheParse(ipcache_entry *, const char *buf);
#else
static int ipcacheParse(ipcache_entry *, rfc1035_rr *, int, const char *error);
#endif
static ipcache_entry *ipcache_get(const char *);
static void ipcacheLockEntry(ipcache_entry *);
static void ipcacheStatPrint(ipcache_entry *, StoreEntry *);
static void ipcacheUnlockEntry(ipcache_entry *);
static void ipcacheRelease(ipcache_entry *, bool dofree = true);

/// \ingroup IPCacheInternal
static ipcache_addrs static_addrs;
/// \ingroup IPCacheInternal
static hash_table *ip_table = NULL;

/// \ingroup IPCacheInternal
static long ipcache_low = 180;
/// \ingroup IPCacheInternal
static long ipcache_high = 200;

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;
#endif

/// \ingroup IPCacheInternal
inline int ipcacheCount() { return ip_table ? ip_table->count : 0; }

int
ipcache_entry::age() const
{
    return request_time.tv_sec ? tvSubMsec(request_time, current_time) : -1;
}



/**
 \ingroup IPCacheInternal
 *
 * removes the given ipcache entry
 */
static void
ipcacheRelease(ipcache_entry * i, bool dofree)
{
    if (!i) {
        debugs(14, 0, "ipcacheRelease: Releasing entry with i=<NULL>");
        return;
    }

    if (!i || !i->hash.key) {
        debugs(14, 0, "ipcacheRelease: Releasing entry without hash link!");
        return;
    }

    debugs(14, 3, "ipcacheRelease: Releasing entry for '" << (const char *) i->hash.key << "'");

    hash_remove_link(ip_table, (hash_link *) i);
    dlinkDelete(&i->lru, &lru_list);
    if (dofree)
        ipcacheFreeEntry(i);
}

/// \ingroup IPCacheInternal
static ipcache_entry *
ipcache_get(const char *name)
{
    if (ip_table != NULL)
        return (ipcache_entry *) hash_lookup(ip_table, name);
    else
        return NULL;
}

/// \ingroup IPCacheInternal
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

/// \ingroup IPCacheAPI
void
ipcache_purgelru(void *voidnotused)
{
    dlink_node *m;
    dlink_node *prev = NULL;
    ipcache_entry *i;
    int removed = 0;
    eventAdd("ipcache_purgelru", ipcache_purgelru, NULL, 10.0, 1);

    for (m = lru_list.tail; m; m = prev) {
        if (ipcacheCount() < ipcache_low)
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

/**
 \ingroup IPCacheInternal
 *
 * purges entries added from /etc/hosts (or whatever).
 */
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

/**
 \ingroup IPCacheInternal
 *
 * create blank ipcache_entry
 */
static ipcache_entry *
ipcacheCreateEntry(const char *name)
{
    static ipcache_entry *i;
    i = (ipcache_entry *)memAllocate(MEM_IPCACHE_ENTRY);
    i->hash.key = xstrdup(name);
    Tolower(static_cast<char*>(i->hash.key));
    i->expires = squid_curtime + Config.negativeDnsTtl;
    return i;
}

/// \ingroup IPCacheInternal
static void
ipcacheAddEntry(ipcache_entry * i)
{
    hash_link *e = (hash_link *)hash_lookup(ip_table, i->hash.key);

#if DNS_CNAME
    /* INET6 : should NOT be adding this entry until all CNAME have been received. */
    assert(i->cname_wait == 0);
#endif

    if (NULL != e) {
        /* avoid colission */
        ipcache_entry *q = (ipcache_entry *) e;
#if DNS_CNAME
        if (q == i)  {
            /* can occur with Multiple-depth CNAME Recursion if parent returned early with additional */
            /* just need to drop from the hash without releasing actual memory */
            ipcacheRelease(q, false);
        } else
#endif
            ipcacheRelease(q);
    }

    hash_join(ip_table, &i->hash);
    dlinkAdd(i, &i->lru, &lru_list);
    i->lastref = squid_curtime;
}

/**
 \ingroup IPCacheInternal
 *
 * walks down the pending list, calling handlers
 */
static void
ipcacheCallback(ipcache_entry *i, int wait)
{
    IPH *callback = i->handler;
    void *cbdata = NULL;
    i->lastref = squid_curtime;

    if (!i->handler)
        return;

    ipcacheLockEntry(i);

    callback = i->handler;

    i->handler = NULL;

    if (cbdataReferenceValidDone(i->handlerData, &cbdata)) {
        const DnsLookupDetails details(i->error_message, wait);
        callback((i->addrs.count ? &i->addrs : NULL), details, cbdata);
    }

    ipcacheUnlockEntry(i);
}

/// \ingroup IPCacheAPI
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

        i->addrs.in_addrs = (IpAddress *)xcalloc(ipcount, sizeof(IpAddress));
        for (int l = 0; l < ipcount; l++)
            i->addrs.in_addrs[l].SetEmpty(); // perform same init actions as constructor would.
        i->addrs.bad_mask = (unsigned char *)xcalloc(ipcount, sizeof(unsigned char));
        memset(i->addrs.bad_mask, 0, sizeof(unsigned char) * ipcount);

        for (j = 0, k = 0; k < ipcount; k++) {
            if ( i->addrs.in_addrs[j] = A[k] )
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
    int j = 0;
    int na = 0;
    int ttl = 0;
    const char *name = (const char *)i->hash.key;
    int cname_found = 0;

    i->expires = squid_curtime + Config.negativeDnsTtl;
    i->flags.negcached = 1;
    safe_free(i->addrs.in_addrs);
    assert(i->addrs.in_addrs == NULL);
    safe_free(i->addrs.bad_mask);
    assert(i->addrs.bad_mask == NULL);
    safe_free(i->error_message);
    assert(i->error_message == NULL);
    i->addrs.count = 0;

    if (nr < 0) {
        debugs(14, 3, "ipcacheParse: Lookup failed '" << error_message << "' for '" << (const char *)i->hash.key << "'");
        i->error_message = xstrdup(error_message);
        return -1;
    }

    if (nr == 0) {
        debugs(14, 3, "ipcacheParse: No DNS records in response to '" << name << "'");
        i->error_message = xstrdup("No DNS records");
        return -1;
    }

    assert(answers);

    for (k = 0; k < nr; k++) {

        if (Ip::EnableIpv6 && answers[k].type == RFC1035_TYPE_AAAA) {
            if (answers[k].rdlength != sizeof(struct in6_addr)) {
                debugs(14, 1, "ipcacheParse: Invalid IPv6 address in response to '" << name << "'");
                continue;
            }
            na++;
            IpcacheStats.rr_aaaa++;
            continue;
        }

        if (answers[k].type == RFC1035_TYPE_A) {
            if (answers[k].rdlength != sizeof(struct in_addr)) {
                debugs(14, 1, "ipcacheParse: Invalid IPv4 address in response to '" << name << "'");
                continue;
            }
            na++;
            IpcacheStats.rr_a++;
            continue;
        }

        /* With A and AAAA, the CNAME does not necessarily come with additional records to use. */
        if (answers[k].type == RFC1035_TYPE_CNAME) {
            cname_found=1;
            IpcacheStats.rr_cname++;

#if DNS_CNAME
            debugs(14, 5, "ipcacheParse: " << name << " CNAME " << answers[k].rdata << " (checking destination: " << i << ").");
            const ipcache_addrs *res = ipcache_gethostbyname(answers[k].rdata, 0);
            if (res) {
                na += res->count;
                debugs(14, 5, "ipcacheParse: CNAME " << answers[k].rdata << " already has " << res->count << " IPs cached.");
            } else {
                /* keep going on this, but flag the fact that we need to wait for a CNAME lookup to finish */
                debugs(14, 5, "ipcacheParse: CNAME " << answers[k].rdata << " has no IPs! Recursing.");
                ipcache_nbgethostbyname(answers[k].rdata, ipcacheHandleCnameRecurse, new generic_cbdata(i) );
                i->cname_wait++;
            }
#endif /* DNS_CNAME */

            continue;
        }

        // otherwise its an unknown RR. debug at level 9 since we usually want to ignore these and they are common.
        debugs(14, 9, HERE << "Unknown RR type received: type=" << answers[k].type << " starting at " << &(answers[k]) );
    }

#if DNS_CNAME
    if (na == 0 && i->cname_wait >0 ) {
        /* don't set any error message (yet). Allow recursion to do its work first. */
        IpcacheStats.cname_only++;
        return 0;
    }
#endif /* DNS_CNAME */

    if (na == 0) {
        debugs(14, 1, "ipcacheParse: No Address records in response to '" << name << "'");
        i->error_message = xstrdup("No Address records");
        if (cname_found)
            IpcacheStats.cname_only++;
        return 0;
    }

    i->addrs.in_addrs = (IpAddress *)xcalloc(na, sizeof(IpAddress));
    for (int l = 0; l < na; l++)
        i->addrs.in_addrs[l].SetEmpty(); // perform same init actions as constructor would.
    i->addrs.bad_mask = (unsigned char *)xcalloc(na, sizeof(unsigned char));

    for (j = 0, k = 0; k < nr; k++) {

        if (answers[k].type == RFC1035_TYPE_A) {
            if (answers[k].rdlength != sizeof(struct in_addr))
                continue;

            struct in_addr temp;
            xmemcpy(&temp, answers[k].rdata, sizeof(struct in_addr));
            i->addrs.in_addrs[j] = temp;

            debugs(14, 3, "ipcacheParse: " << name << " #" << j << " " << i->addrs.in_addrs[j]);
            j++;

        } else if (Ip::EnableIpv6 && answers[k].type == RFC1035_TYPE_AAAA) {
            if (answers[k].rdlength != sizeof(struct in6_addr))
                continue;

            struct in6_addr temp;
            xmemcpy(&temp, answers[k].rdata, sizeof(struct in6_addr));
            i->addrs.in_addrs[j] = temp;

            debugs(14, 3, "ipcacheParse: " << name << " #" << j << " " << i->addrs.in_addrs[j] );
            j++;
        }
#if DNS_CNAME
        else if (answers[k].type == RFC1035_TYPE_CNAME) {
            debugs(14, 3, "ipcacheParse: " << name << " #x CNAME " << answers[k].rdata);
            const ipcache_addrs *res = ipcache_gethostbyname(answers[k].rdata, 0);
            if (res) {
                /* NP: the results of *that* query need to be integrated in place of the CNAME */
                /* Ideally we should also integrate the min TTL of the above IPA's into ttl.   */
                for (int l = 0; l < res->count; l++, j++) {
                    i->addrs.in_addrs[j] = res->in_addrs[l];
                    debugs(14, 3, "ipcacheParse: " << name << " #" << j << " " << i->addrs.in_addrs[j] );
                }
            } else {
                debugs(14, 9, "ipcacheParse: " << answers[k].rdata << " (CNAME) waiting on A/AAAA records.");
            }
        }
#endif /* DNS_CNAME */

        if (ttl == 0 || (int) answers[k].ttl < ttl)
            ttl = answers[k].ttl;
    }

    assert(j == na);

    if (na < 256)
        i->addrs.count = (unsigned char) na;
    else
        i->addrs.count = 255;

    if (ttl > Config.positiveDnsTtl)
        ttl = Config.positiveDnsTtl;

    if (ttl < Config.negativeDnsTtl)
        ttl = Config.negativeDnsTtl;

    i->expires = squid_curtime + ttl;

    i->flags.negcached = 0;

#if DNS_CNAME
    /* SPECIAL CASE: may get here IFF CNAME received with Additional records */
    /*               reurn  0/'wait for further details' value.              */
    /*               NP: 'No DNS Results' is a return -1 +msg                */
    if (i->cname_wait)
        return 0;
    else
#endif /* DNS_CNAME */
        return i->addrs.count;
}

#endif

/// \ingroup IPCacheInternal
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
    const int age = i->age();
    statHistCount(&statCounter.dns.svc_time, age);

#if USE_DNSSERVERS
    ipcacheParse(i, reply);
#else

    int done = ipcacheParse(i, answers, na, error_message);

    /* If we have not produced either IPs or Error immediately, wait for recursion to finish. */
    if (done != 0 || error_message != NULL)
#endif

    {
        ipcacheAddEntry(i);
        ipcacheCallback(i, age);
    }
}

/**
 \ingroup IPCacheAPI
 *
 \param name		Host to resolve.
 \param handler		Pointer to the function to be called when the reply
 *			from the IP cache (or the DNS if the IP cache misses)
 \param handlerData	Information that is passed to the handler and does not affect the IP cache.
 *
 * XXX: on hits and some errors, the handler is called immediately instead
 * of scheduling an async call. This reentrant behavior means that the
 * user job must be extra careful after calling ipcache_nbgethostbyname,
 * especially if the handler destroys the job. Moreover, the job has
 * no way of knowing whether the reentrant call happened. commConnectStart
 * protects the job by scheduling an async call, but some user code calls
 * ipcache_nbgethostbyname directly.
 */
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
        IpcacheStats.invalid++;
        const DnsLookupDetails details("Invalid hostname", -1); // error, no lookup
        handler(NULL, details, handlerData);
        return;
    }

    if ((addrs = ipcacheCheckNumeric(name))) {
        debugs(14, 4, "ipcache_nbgethostbyname: BYPASS for '" << name << "' (already numeric)");
        IpcacheStats.numeric_hits++;
        const DnsLookupDetails details(NULL, -1); // no error, no lookup
        handler(addrs, details, handlerData);
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

        ipcacheCallback(i, -1); // no lookup

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

/// \ingroup IPCacheInternal
static void
ipcacheRegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("ipcache",
                   "IP Cache Stats and Contents",
                   stat_ipcache_get, 0, 1);
}


/**
 \ingroup IPCacheAPI
 *
 * Initialize the ipcache.
 * Is called from mainInitialize() after disk initialization
 * and prior to the reverse FQDNCache initialization
 */
void
ipcache_init(void)
{
    int n;
    debugs(14, DBG_IMPORTANT, "Initializing IP Cache...");
    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));
    memset(&lru_list, '\0', sizeof(lru_list));
    memset(&static_addrs, '\0', sizeof(ipcache_addrs));

    static_addrs.in_addrs = (IpAddress *)xcalloc(1, sizeof(IpAddress));
    static_addrs.in_addrs->SetEmpty(); // properly setup the IpAddress!
    static_addrs.bad_mask = (unsigned char *)xcalloc(1, sizeof(unsigned char));
    ipcache_high = (long) (((float) Config.ipcache.size *
                            (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
                           (float) Config.ipcache.low) / (float) 100);
    n = hashPrime(ipcache_high / 4);
    ip_table = hash_create((HASHCMP *) strcmp, n, hash4);
    memDataInit(MEM_IPCACHE_ENTRY, "ipcache_entry", sizeof(ipcache_entry), 0);

    ipcacheRegisterWithCacheManager();
}

/**
 \ingroup IPCacheAPI
 *
 * Is different from ipcache_nbgethostbyname in that it only checks
 * if an entry exists in the cache and does not by default contact the DNS,
 * unless this is requested, by setting the flags.
 *
 \param name		Host name to resolve.
 \param flags		Default is NULL, set to IP_LOOKUP_IF_MISS
 *			to explicitly perform DNS lookups.
 *
 \retval NULL	An error occured during lookup
 \retval NULL	No results available in cache and no lookup specified
 \retval *	Pointer to the ipcahce_addrs structure containing the lookup results
 */
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
        // ignore i->error_message: the caller just checks IP cache presence
        return NULL;
    } else {
        IpcacheStats.hits++;
        i->lastref = squid_curtime;
        // ignore i->error_message: the caller just checks IP cache presence
        return &i->addrs;
    }

    /* no entry [any more] */

    if ((addrs = ipcacheCheckNumeric(name))) {
        IpcacheStats.numeric_hits++;
        return addrs;
    }

    IpcacheStats.misses++;

    if (flags & IP_LOOKUP_IF_MISS)
        ipcache_nbgethostbyname(name, ipcacheHandleCnameRecurse, NULL);

    return NULL;
}

/// \ingroup IPCacheInternal
static void
ipcacheStatPrint(ipcache_entry * i, StoreEntry * sentry)
{
    int k;
    char buf[MAX_IPSTRLEN];

    if (!sentry) {
        debugs(14, 0, HERE << "CRITICAL: sentry is NULL!");
        return;
    }

    if (!i) {
        debugs(14, 0, HERE << "CRITICAL: ipcache_entry is NULL!");
        storeAppendPrintf(sentry, "CRITICAL ERROR\n");
        return;
    }

    int count = i->addrs.count;

    storeAppendPrintf(sentry, " %-32.32s %c%c %6d %6d %2d(%2d)",
                      hashKeyStr(&i->hash),
                      i->flags.fromhosts ? 'H' : ' ',
                      i->flags.negcached ? 'N' : ' ',
                      (int) (squid_curtime - i->lastref),
                      (int) ((i->flags.fromhosts ? -1 : i->expires - squid_curtime)),
                      (int) i->addrs.count,
                      (int) i->addrs.badcount);

    /** \par
     * Negative-cached entries have no IPs listed. */
    if (i->flags.negcached) {
        storeAppendPrintf(sentry, "\n");
        return;
    }

    /** \par
     * Cached entries have IPs listed with a BNF of:   ip-address '-' ('OK'|'BAD') */
    for (k = 0; k < count; k++) {
        /* Display tidy-up: IPv6 are so big make the list vertical */
        if (k == 0)
            storeAppendPrintf(sentry, " %45.45s-%3s\n",
                              i->addrs.in_addrs[k].NtoA(buf,MAX_IPSTRLEN),
                              i->addrs.bad_mask[k] ? "BAD" : "OK ");
        else
            storeAppendPrintf(sentry, "%s %45.45s-%3s\n",
                              "                                                         ", /* blank-space indenting IP list */
                              i->addrs.in_addrs[k].NtoA(buf,MAX_IPSTRLEN),
                              i->addrs.bad_mask[k] ? "BAD" : "OK ");
    }
}

/**
 \ingroup IPCacheInternal
 *
 * process objects list
 */
void
stat_ipcache_get(StoreEntry * sentry)
{
    dlink_node *m;
    assert(ip_table != NULL);
    storeAppendPrintf(sentry, "IP Cache Statistics:\n");
    storeAppendPrintf(sentry, "IPcache Entries In Use:  %d\n",
                      memInUse(MEM_IPCACHE_ENTRY));
    storeAppendPrintf(sentry, "IPcache Entries Cached:  %d\n",
                      ipcacheCount());
    storeAppendPrintf(sentry, "IPcache Requests: %d\n",
                      IpcacheStats.requests);
    storeAppendPrintf(sentry, "IPcache Hits:            %d\n",
                      IpcacheStats.hits);
    storeAppendPrintf(sentry, "IPcache Negative Hits:       %d\n",
                      IpcacheStats.negative_hits);
    storeAppendPrintf(sentry, "IPcache Numeric Hits:        %d\n",
                      IpcacheStats.numeric_hits);
    storeAppendPrintf(sentry, "IPcache Misses:          %d\n",
                      IpcacheStats.misses);
    storeAppendPrintf(sentry, "IPcache Retrieved A:     %d\n",
                      IpcacheStats.rr_a);
    storeAppendPrintf(sentry, "IPcache Retrieved AAAA:  %d\n",
                      IpcacheStats.rr_aaaa);
    storeAppendPrintf(sentry, "IPcache Retrieved CNAME: %d\n",
                      IpcacheStats.rr_cname);
    storeAppendPrintf(sentry, "IPcache CNAME-Only Response: %d\n",
                      IpcacheStats.cname_only);
    storeAppendPrintf(sentry, "IPcache Invalid Request: %d\n",
                      IpcacheStats.invalid);
    storeAppendPrintf(sentry, "\n\n");
    storeAppendPrintf(sentry, "IP Cache Contents:\n\n");
    storeAppendPrintf(sentry, " %-31.31s %3s %6s %6s  %4s\n",
                      "Hostname",
                      "Flg",
                      "lstref",
                      "TTL",
                      "N(b)");

    for (m = lru_list.head; m; m = m->next) {
        assert( m->next != m );
        ipcacheStatPrint((ipcache_entry *)m->data, sentry);
    }
}

#if DNS_CNAME
/**
 * Takes two IpAddress arrays and merges them into a single array
 * which is allocated dynamically to fit the number of unique addresses
 *
 \param aaddrs	One list to merge
 \param alen	Size of list aaddrs
 \param baddrs	Other list to merge
 \param alen	Size of list baddrs
 \param out	Combined list of unique addresses (sorted with IPv6 first in IPv6-mode)
 \param outlen	Size of list out
 */
void
ipcacheMergeIPLists(const IpAddress *aaddrs, const int alen,
                    const IpAddress *baddrs, const int blen,
                    IpAddress **out, int &outlen )
{
    int fc=0, t=0, c=0;

    IpAddress const *ip4ptrs[255];
    IpAddress const *ip6ptrs[255];
    int num_ip4 = 0;
    int num_ip6 = 0;

    memset(ip4ptrs, 0, sizeof(IpAddress*)*255);
    memset(ip6ptrs, 0, sizeof(IpAddress*)*255);

    // for each unique address in list A - grab ptr
    for (t = 0; t < alen; t++) {
        if (aaddrs[t].IsIPv4()) {
            // check against IPv4 pruned list
            for (c = 0; c <= num_ip4; c++) {
                if (ip4ptrs[c] && aaddrs[t] == *(ip4ptrs[c]) ) break; // duplicate.
            }
            if (c > num_ip4) {
                ip4ptrs[num_ip4] = &aaddrs[t];
                num_ip4++;
            }
        } else if (aaddrs[t].IsIPv6()) {
            debugs(14,8, HERE << "A[" << t << "]=IPv6 " << aaddrs[t]);
            // check against IPv6 pruned list
            for (c = 0; c <= num_ip6; c++) {
                if (ip6ptrs[c] && aaddrs[t] == *ip6ptrs[c]) break; // duplicate.
            }
            if (c > num_ip6) {
                ip6ptrs[num_ip6] = &aaddrs[t];
                num_ip6++;
            }
        }
    }

    // for each unique address in list B - grab ptr
    for (t = 0; t < blen; t++) {
        if (baddrs[t].IsIPv4()) {
            // check against IPv4 pruned list
            for (c = 0; c <= num_ip4; c++) {
                if (ip4ptrs[c] && baddrs[t] == *ip4ptrs[c]) break; // duplicate.
            }
            if (c > num_ip4) {
                ip4ptrs[num_ip4] = &baddrs[t];
                num_ip4++;
            }
        } else if (baddrs[t].IsIPv6()) {
            // check against IPv6 pruned list
            for (c = 0; c <= num_ip6; c++) {
                if (ip6ptrs[c] && baddrs[t] == *ip6ptrs[c]) break; // duplicate.
            }
            if (c > num_ip6) {
                ip6ptrs[num_ip6] = &baddrs[t];
                num_ip6++;
            }
        }
    }

    fc = num_ip6 + num_ip4;

    assert(fc > 0);

    debugs(14, 5, "ipcacheMergeIPLists: Merge " << alen << "+" << blen << " into " << fc << " unique IPs.");

    // copy the old IPs into the new list buffer.
    (*out) = (IpAddress*)xcalloc(fc, sizeof(IpAddress));
    outlen=0;

    assert(out != NULL);

    /* IPv6 are preferred (tried first) over IPv4 */

    for (int l = 0; outlen < num_ip6; l++, outlen++) {
        (*out)[outlen] = *ip6ptrs[l];
        debugs(14, 5, "ipcacheMergeIPLists:  #" << outlen << " " << (*out)[outlen] );
    }

    for (int l = 0; outlen < num_ip4; l++, outlen++) {
        (*out)[outlen] = *ip4ptrs[l];
        debugs(14, 5, "ipcacheMergeIPLists:  #" << outlen << " " << (*out)[outlen] );
    }

    assert(outlen == fc); // otherwise something broke badly!
}
#endif /* DNS_CNAME */

/// \ingroup IPCacheInternal
/// Callback.
static void
ipcacheHandleCnameRecurse(const ipcache_addrs *addrs, const DnsLookupDetails &, void *cbdata)
{
#if DNS_CNAME
    ipcache_entry *i = NULL;
    char *pname = NULL;
    IpAddress *tmpbuf = NULL;
    int fc = 0;
    int ttl = 0;
    generic_cbdata* gcb = (generic_cbdata*)cbdata;
    // count of addrs at parent and child (REQ as .count is a char type!)
    int ccount = 0, pcount = 0;

    debugs(14, 5, "ipcacheHandleCnameRecurse: Handling basic A/AAAA response.");

    /* IFF no CNAME recursion being processed. do nothing. */
    if (cbdata == NULL)
        return;

    gcb->unwrap(&i);
    assert(i != NULL);

    // make sure we are actualy waiting for a CNAME callback to be run.
    assert(i->cname_wait > 0);
    // count this event. its being handled.
    i->cname_wait--;

    pname = (char*)i->hash.key;
    assert(pname != NULL);

    debugs(14, 5, "ipcacheHandleCnameRecurse: Handling CNAME recursion. CBDATA('" << gcb->data << "')='" << pname << "' -> " << std::hex << i);

    if (i == NULL) {
        return; // Parent has expired. Don't merge, just leave for future Ref:
    }

    /* IFF addrs is NULL (Usually an Error or Timeout occured on lookup.) */
    /* Ignore it and HOPE that we got some Additional records to use.     */
    if (addrs == NULL)
        return;

    ccount = (0+ addrs->count);
    pcount = (0+ i->addrs.count);
    ttl = i->expires;

    /* IFF no CNAME results. do none of the processing BUT finish anyway. */
    if (addrs) {

        debugs(14, 5, "ipcacheHandleCnameRecurse: Merge IP Lists for " << pname << " (" << pcount << "+" << ccount << ")");

        /* add new IP records to entry */
        tmpbuf = i->addrs.in_addrs;
        i->addrs.in_addrs = NULL;
        ipcacheMergeIPLists(tmpbuf, pcount, addrs->in_addrs, ccount, &(i->addrs.in_addrs), fc);
        debugs(14,8, HERE << "in=" << tmpbuf << ", out=" << i->addrs.in_addrs );
        assert( (pcount>0 ? tmpbuf!=NULL : tmpbuf==NULL) );
        safe_free(tmpbuf);

        if ( pcount > 0) {
            /* IFF the parent initial lookup was given Additional records with A */
            // clear the 'bad IP mask'
            safe_free(i->addrs.bad_mask);
        }
        // create a new bad IP mask to fit the new size needed.
        if (fc > 0) {
            i->addrs.bad_mask = (unsigned char*)xcalloc(fc, sizeof(unsigned char));
            memset(i->addrs.bad_mask, 0, sizeof(unsigned char)*fc);
        }

        if (fc < 256)
            i->addrs.count = (unsigned char) fc;
        else
            i->addrs.count = 255;

        if (ttl == 0 || ttl > Config.positiveDnsTtl)
            ttl = Config.positiveDnsTtl;

        if (ttl < Config.negativeDnsTtl)
            ttl = Config.negativeDnsTtl;

        i->expires = squid_curtime + ttl;

        i->flags.negcached = 0;

        i->addrs.cur = 0;

        i->addrs.badcount = 0;
    }

    if (fc == 0) {
        i->error_message = xstrdup("No DNS Records");
    }

    /* finish the lookup we were doing on parent when we got side-tracked for CNAME loop */
    if (i->cname_wait == 0) {
        ipcacheAddEntry(i);
        ipcacheCallback(i, i->age()); // age since i creation, includes CNAMEs
    }
    // else still more CNAME to be found.
#endif /* DNS_CNAME */
}

/// \ingroup IPCacheAPI
void
ipcacheInvalidate(const char *name)
{
    ipcache_entry *i;

    if ((i = ipcache_get(name)) == NULL)
        return;

    i->expires = squid_curtime;

    /*
     * NOTE, don't call ipcacheRelease here because we might be here due
     * to a thread started from a callback.
     */
}

/// \ingroup IPCacheAPI
void
ipcacheInvalidateNegative(const char *name)
{
    ipcache_entry *i;

    if ((i = ipcache_get(name)) == NULL)
        return;

    if (i->flags.negcached)
        i->expires = squid_curtime;

    /*
     * NOTE, don't call ipcacheRelease here because we might be here due
     * to a thread started from a callback.
     */
}

/// \ingroup IPCacheAPI
ipcache_addrs *
ipcacheCheckNumeric(const char *name)
{

    IpAddress ip;
    /* check if it's already a IP address in text form. */

    /* it may be IPv6-wrapped */
    if (name[0] == '[') {
        char *tmp = xstrdup(&name[1]);
        tmp[strlen(tmp)-1] = '\0';
        if (!(ip = tmp)) {
            delete tmp;
            return NULL;
        }
        delete tmp;
    } else if (!(ip = name))
        return NULL;

    debugs(14, 4, "ipcacheCheckNumeric: HIT_BYPASS for '" << name << "' == " << ip );

    static_addrs.count = 1;

    static_addrs.cur = 0;

    static_addrs.in_addrs[0] = ip;

    static_addrs.bad_mask[0] = FALSE;

    static_addrs.badcount = 0;

    return &static_addrs;
}

/// \ingroup IPCacheInternal
static void
ipcacheLockEntry(ipcache_entry * i)
{
    if (i->locks++ == 0) {
        dlinkDelete(&i->lru, &lru_list);
        dlinkAdd(i, &i->lru, &lru_list);
    }
}

/// \ingroup IPCacheInternal
static void
ipcacheUnlockEntry(ipcache_entry * i)
{
    if (i->locks < 1) {
        debugs(14, 1, "WARNING: ipcacheEntry unlocked with no lock! locks=" << i->locks);
        return;
    }

    i->locks--;

    if (ipcacheExpiredEntry(i))
        ipcacheRelease(i);
}

/// \ingroup IPCacheAPI
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

    /* NP: zero-based so we increase the human-readable number of our position */
    debugs(14, 3, "ipcacheCycleAddr: " << name << " now at " << ia->in_addrs[ia->cur] << " (" << (ia->cur+1) << " of " << ia->count << ")");
}

/**
 \ingroup IPCacheAPI
 *
 \param name	domain name to have an IP marked bad
 \param addr	specific addres to be marked bad
 */
void
ipcacheMarkBadAddr(const char *name, IpAddress &addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;

    /** Does nothing if the domain name does not exist. */
    if ((i = ipcache_get(name)) == NULL)
        return;

    ia = &i->addrs;

    for (k = 0; k < (int) ia->count; k++) {
        if (addr == ia->in_addrs[k] )
            break;
    }

    /** Does nothing if the IP does not exist for the doamin. */
    if (k == (int) ia->count)
        return;

    /** Marks the given address as BAD */
    if (!ia->bad_mask[k]) {
        ia->bad_mask[k] = TRUE;
        ia->badcount++;
        i->expires = min(squid_curtime + max((time_t)60, Config.negativeDnsTtl), i->expires);
        debugs(14, 2, "ipcacheMarkBadAddr: " << name << " " << addr );
    }

    /** then calls ipcacheCycleAddr() to advance the current pointer to the next OK address. */
    ipcacheCycleAddr(name, ia);
}

/// \ingroup IPCacheAPI
void
ipcacheMarkAllGood(const char *name)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;

    if ((i = ipcache_get(name)) == NULL)
        return;

    ia = &i->addrs;

    /* All bad, reset to All good */
    debugs(14, 3, "ipcacheMarkAllGood: Changing ALL " << name << " addrs to OK (" << ia->badcount << "/" << ia->count << " bad)");

    for (k = 0; k < ia->count; k++)
        ia->bad_mask[k] = 0;

    ia->badcount = 0;
}

/// \ingroup IPCacheAPI
void
ipcacheMarkGoodAddr(const char *name, IpAddress &addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;

    if ((i = ipcache_get(name)) == NULL)
        return;

    ia = &i->addrs;

    for (k = 0; k < (int) ia->count; k++) {
        if (addr == ia->in_addrs[k])
            break;
    }

    if (k == (int) ia->count)	/* not found */
        return;

    if (!ia->bad_mask[k])	/* already OK */
        return;

    ia->bad_mask[k] = FALSE;

    ia->badcount--;

    debugs(14, 2, "ipcacheMarkGoodAddr: " << name << " " << addr );
}

/// \ingroup IPCacheInternal
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

/// \ingroup IPCacheAPI
void
ipcacheFreeMemory(void)
{
    hashFreeItems(ip_table, ipcacheFreeEntry);
    hashFreeMemory(ip_table);
    ip_table = NULL;
}

/**
 \ingroup IPCacheAPI
 *
 * Recalculate IP cache size upon reconfigure.
 * Is called to clear the IPCache's data structures,
 * cancel all pending requests.
 */
void
ipcache_restart(void)
{
    ipcache_high = (long) (((float) Config.ipcache.size *
                            (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
                           (float) Config.ipcache.low) / (float) 100);
    purge_entries_fromhosts();
}

/**
 \ingroup IPCacheAPI
 *
 * Adds a "static" entry from /etc/hosts
 *
 \param name	Hostname to be linked with IP
 \param ipaddr	IP Address to be cached.
 *
 \retval 0	Success.
 \retval 1	IP address is invalid or other error.
 */
int
ipcacheAddEntryFromHosts(const char *name, const char *ipaddr)
{
    ipcache_entry *i;

    IpAddress ip;

    if (!(ip = ipaddr)) {
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

    i->addrs.in_addrs = (IpAddress *)xcalloc(1, sizeof(IpAddress));
    i->addrs.bad_mask = (unsigned char *)xcalloc(1, sizeof(unsigned char));
    i->addrs.in_addrs[0] = ip;
    i->addrs.bad_mask[0] = FALSE;
    i->flags.fromhosts = 1;
    ipcacheAddEntry(i);
    ipcacheLockEntry(i);
    return 0;
}

#ifdef SQUID_SNMP
/**
 \ingroup IPCacheAPI
 *
 * The function to return the ip cache statistics to via SNMP
 */
variable_list *
snmp_netIpFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;
    MemBuf tmp;
    debugs(49, 5, "snmp_netIpFn: Processing request:" << snmpDebugOid(Var->name, Var->name_length, tmp));
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_NET + 1]) {

    case IP_ENT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      ipcacheCount(),
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
