/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 14    IP Cache */

#include "squid.h"
#include "CacheManager.h"
#include "cbdata.h"
#include "debug/Messages.h"
#include "dlink.h"
#include "dns/LookupDetails.h"
#include "dns/rfc3596.h"
#include "event.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "mgr/Registration.h"
#include "snmp_agent.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "Store.h"
#include "util.h"
#include "wordlist.h"

#if SQUID_SNMP
#include "snmp_core.h"
#endif

/**
 \defgroup IPCacheAPI IP Cache API
 \ingroup Components
 \section IpcacheIntroduction Introduction
 \par
 *  The IP cache is a built-in component of squid providing
 *  Hostname to IP-Number translation functionality and managing
 *  the involved data-structures. Efficiency concerns require
 *  mechanisms that allow non-blocking access to these mappings.
 *  The IP cache usually doesn't block on a request except for
 *  special cases where this is desired (see below).
 */

/**
 \defgroup IPCacheInternal IP Cache Internals
 \ingroup IPCacheAPI
 \note  when IP cache is provided as a class. These sub-groups will be obsolete
 *  for now they are used to separate the public and private functions.
 *  with the private ones all being in IPCachInternal and public in IPCacheAPI
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

/// metadata for parsing DNS A and AAAA records
template <class Content>
class RrSpecs
{
public:
    typedef Content DataType; ///< actual RR DATA type
    const char *kind; ///< human-friendly record type description
    int &recordCounter; ///< where this kind of records are counted (for stats)
};

/// forwards non-blocking IP cache lookup results to either IPH or IpReciever
class IpCacheLookupForwarder
{
public:
    IpCacheLookupForwarder() {}
    explicit IpCacheLookupForwarder(const CbcPointer<Dns::IpReceiver> &receiver);
    IpCacheLookupForwarder(IPH *fun, void *data);

    /// forwards notification about the end of the lookup; last method to be called
    void finalCallback(const Dns::CachedIps *addrs, const Dns::LookupDetails &details);

    /// forwards an IP notification
    /// \returns whether it may be possible to deliver more notifications
    bool forwardIp(const Ip::Address &ip);

    /// convenience wrapper to safely forwardIp() for each IP in the container
    void forwardHits(const Dns::CachedIps &ips);

    /// initialize lookup timestamps for Dns::LookupDetails delay calculation
    void lookupsStarting() { firstLookupStart = lastLookupEnd = current_time; }

    /// inform recipient of a finished lookup
    void forwardLookup(const char *error);

    /// \returns milliseconds since the first lookup start
    int totalResponseTime() const { return tvSubMsec(firstLookupStart, current_time); }

protected:
    /// \returns not yet reported lookup delay in milliseconds
    int additionalLookupDelay() const { return tvSubMsec(lastLookupEnd, current_time); }

private:
    /* receiverObj and receiverFun are mutually exclusive */
    CbcPointer<Dns::IpReceiver> receiverObj; ///< gets incremental and final results
    IPH *receiverFun = nullptr; ///< gets final results
    CallbackData receiverData; ///< caller-specific data for the handler (optional)

    struct timeval firstLookupStart {0,0}; ///< time of the idnsALookup() call
    struct timeval lastLookupEnd {0,0}; ///< time of the last noteLookup() call
};

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
    CBDATA_CLASS(ipcache_entry);

public:
    ipcache_entry(const char *);
    ~ipcache_entry();

    hash_link hash;     /* must be first */
    time_t lastref;
    time_t expires;
    ipcache_addrs addrs;
    IpCacheLookupForwarder handler;
    char *error_message;

    dlink_node lru;
    unsigned short locks;
    struct Flags {
        Flags() : negcached(false), fromhosts(false) {}

        bool negcached;
        bool fromhosts;
    } flags;

    bool sawCname = false;

    const char *name() const { return static_cast<const char*>(hash.key); }

    /// milliseconds since the first lookup start or -1 if there were no lookups
    int totalResponseTime() const;
    /// milliseconds since the last lookup start or -1 if there were no lookups
    int additionalLookupDelay() const;

    /// adds the contents of a "good" DNS A or AAAA record to stored IPs
    template <class Specs>
    void addGood(const rfc1035_rr &rr, Specs &specs);

    /// remembers the last error seen, overwriting any previous errors
    void latestError(const char *text, const int debugLevel = 3);

protected:
    void updateTtl(const unsigned int rrTtl);
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

// forward-decls
static void stat_ipcache_get(StoreEntry *);

static FREE ipcacheFreeEntry;
static IDNSCB ipcacheHandleReply;
static int ipcacheExpiredEntry(ipcache_entry *);
static ipcache_entry *ipcache_get(const char *);
static void ipcacheLockEntry(ipcache_entry *);
static void ipcacheStatPrint(ipcache_entry *, StoreEntry *);
static void ipcacheUnlockEntry(ipcache_entry *);
static void ipcacheRelease(ipcache_entry *, bool dofree = true);
static const Dns::CachedIps *ipcacheCheckNumeric(const char *name);
static void ipcache_nbgethostbyname_(const char *name, IpCacheLookupForwarder handler);

/// \ingroup IPCacheInternal
static hash_table *ip_table = nullptr;

/// \ingroup IPCacheInternal
static long ipcache_low = 180;
/// \ingroup IPCacheInternal
static long ipcache_high = 200;

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;
#endif

CBDATA_CLASS_INIT(ipcache_entry);

IpCacheLookupForwarder::IpCacheLookupForwarder(const CbcPointer<Dns::IpReceiver> &receiver):
    receiverObj(receiver)
{
}

IpCacheLookupForwarder::IpCacheLookupForwarder(IPH *fun, void *data):
    receiverFun(fun), receiverData(data)
{
}

void
IpCacheLookupForwarder::finalCallback(const Dns::CachedIps *addrs, const Dns::LookupDetails &details)
{
    debugs(14, 7, addrs << " " << details);
    if (receiverObj.set()) {
        if (auto receiver = receiverObj.valid())
            receiver->noteIps(addrs, details);
        receiverObj.clear();
    } else if (receiverFun) {
        if (receiverData.valid()) {
            const Dns::CachedIps *emptyIsNil = (addrs && !addrs->empty()) ? addrs : nullptr;
            receiverFun(emptyIsNil, details, receiverData.validDone());
        }
        receiverFun = nullptr;
    }
}

/// forwards an IP notification
/// \returns whether it may be possible to deliver more notifications
bool
IpCacheLookupForwarder::forwardIp(const Ip::Address &ip)
{
    debugs(14, 7, ip);
    if (receiverObj.set()) {
        if (auto receiver = receiverObj.valid()) {
            receiver->noteIp(ip);
            return true;
        }
        return false;
    }
    // else do nothing: ReceiverFun does not do incremental notifications
    return false;
}

/// convenience wrapper to safely forwardIp() for each IP in the container
void
IpCacheLookupForwarder::forwardHits(const Dns::CachedIps &ips)
{
    if (receiverObj.set()) {
        for (const auto &ip: ips.good()) {
            if (!forwardIp(ip))
                break; // receiver gone
        }
    }
    // else do nothing: ReceiverFun does not do incremental notifications
}

void
IpCacheLookupForwarder::forwardLookup(const char *error)
{
    // Lookups run concurrently, but HttpRequest::recordLookup() thinks they
    // are sequential. Give it just the new, yet-unaccounted-for delay.
    if (receiverObj.set()) {
        if (auto receiver = receiverObj.valid()) {
            receiver->noteLookup(Dns::LookupDetails(SBuf(error), additionalLookupDelay()));
            lastLookupEnd = current_time;
        }
    }
    // else do nothing: ReceiverFun gets no individual lookup notifications
}

/// \ingroup IPCacheInternal
inline int ipcacheCount() { return ip_table ? ip_table->count : 0; }

/**
 \ingroup IPCacheInternal
 *
 * removes the given ipcache entry
 */
static void
ipcacheRelease(ipcache_entry * i, bool dofree)
{
    if (!i) {
        debugs(14, DBG_CRITICAL, "ipcacheRelease: Releasing entry with i=<NULL>");
        return;
    }

    if (!i || !i->hash.key) {
        debugs(14, DBG_CRITICAL, "ipcacheRelease: Releasing entry without hash link!");
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
    if (ip_table != nullptr)
        return (ipcache_entry *) hash_lookup(ip_table, name);
    else
        return nullptr;
}

/// \ingroup IPCacheInternal
static int
ipcacheExpiredEntry(ipcache_entry * i)
{
    /* all static entries are locked, so this takes care of them too */

    if (i->locks != 0)
        return 0;

    if (i->addrs.empty())
        if (0 == i->flags.negcached)
            return 1;

    if (i->expires > squid_curtime)
        return 0;

    return 1;
}

/// \ingroup IPCacheAPI
void
ipcache_purgelru(void *)
{
    dlink_node *m;
    dlink_node *prev = nullptr;
    ipcache_entry *i;
    int removed = 0;
    eventAdd("ipcache_purgelru", ipcache_purgelru, nullptr, 10.0, 1);

    for (m = lru_list.tail; m; m = prev) {
        if (ipcacheCount() < ipcache_low)
            break;

        prev = m->prev;

        i = (ipcache_entry *)m->data;

        if (i->locks != 0)
            continue;

        ipcacheRelease(i);

        ++removed;
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
    ipcache_entry *i = nullptr, *t;

    while (m) {
        if (i != nullptr) {    /* need to delay deletion */
            ipcacheRelease(i);  /* we just override locks */
            i = nullptr;
        }

        t = (ipcache_entry*)m->data;

        if (t->flags.fromhosts)
            i = t;

        m = m->next;
    }

    if (i != nullptr)
        ipcacheRelease(i);
}

ipcache_entry::ipcache_entry(const char *aName):
    lastref(0),
    expires(0),
    error_message(nullptr),
    locks(0) // XXX: use Lock type ?
{
    hash.key = xstrdup(aName);
    Tolower(static_cast<char*>(hash.key));
    expires = squid_curtime + Config.negativeDnsTtl;
}

/// \ingroup IPCacheInternal
static void
ipcacheAddEntry(ipcache_entry * i)
{
    hash_link *e = (hash_link *)hash_lookup(ip_table, i->hash.key);

    if (nullptr != e) {
        /* avoid collision */
        ipcache_entry *q = (ipcache_entry *) e;
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
ipcacheCallback(ipcache_entry *i, const bool hit, const int wait)
{
    i->lastref = squid_curtime;

    ipcacheLockEntry(i);

    if (hit)
        i->handler.forwardHits(i->addrs);
    const Dns::LookupDetails details(SBuf(i->error_message), wait);
    i->handler.finalCallback(&i->addrs, details);

    ipcacheUnlockEntry(i);
}

void
ipcache_entry::latestError(const char *text, const int debugLevel)
{
    debugs(14, debugLevel, "ERROR: DNS failure while resolving " << name() << ": " << text);
    safe_free(error_message);
    error_message = xstrdup(text);
}

static void
ipcacheParse(ipcache_entry *i, const rfc1035_rr * answers, int nr, const char *error_message)
{
    int k;

    // XXX: Callers use zero ancount instead of -1 on errors!
    if (nr < 0) {
        i->latestError(error_message);
        return;
    }

    if (nr == 0) {
        i->latestError("No DNS records");
        return;
    }

    debugs(14, 3, nr << " answers for " << i->name());
    assert(answers);

    for (k = 0; k < nr; ++k) {

        if (Ip::EnableIpv6 && answers[k].type == RFC1035_TYPE_AAAA) {
            static const RrSpecs<struct in6_addr> QuadA = { "IPv6", IpcacheStats.rr_aaaa };
            i->addGood(answers[k], QuadA);
            continue;
        }

        if (answers[k].type == RFC1035_TYPE_A) {
            static const RrSpecs<struct in_addr> SingleA = { "IPv4", IpcacheStats.rr_a };
            i->addGood(answers[k], SingleA);
            continue;
        }

        /* With A and AAAA, the CNAME does not necessarily come with additional records to use. */
        if (answers[k].type == RFC1035_TYPE_CNAME) {
            i->sawCname = true;
            ++IpcacheStats.rr_cname;
            continue;
        }

        // otherwise its an unknown RR. debug at level 9 since we usually want to ignore these and they are common.
        debugs(14, 9, "Unknown RR type received: type=" << answers[k].type << " starting at " << &(answers[k]) );
    }
}

template <class Specs>
void
ipcache_entry::addGood(const rfc1035_rr &rr, Specs &specs)
{
    typename Specs::DataType address;
    if (rr.rdlength != sizeof(address)) {
        debugs(14, DBG_IMPORTANT, "ERROR: Ignoring invalid " << specs.kind << " address record while resolving " << name());
        return;
    }

    ++specs.recordCounter;

    // Do not store more than 255 addresses (TODO: Why?)
    if (addrs.raw().size() >= 255)
        return;

    memcpy(&address, rr.rdata, sizeof(address));
    const Ip::Address ip = address;
    if (addrs.have(ip)) {
        debugs(14, 3, "refusing to add duplicate " << ip);
        return;
    }
    addrs.pushUnique(address);

    updateTtl(rr.ttl);

    debugs(14, 3, name() << " #" << addrs.size() << " " << ip);
    handler.forwardIp(ip); // we are only called with good IPs
}

void
ipcache_entry::updateTtl(const unsigned int rrTtl)
{
    const time_t ttl = std::min(std::max(
                                    Config.negativeDnsTtl, // smallest value allowed
                                    static_cast<time_t>(rrTtl)),
                                Config.positiveDnsTtl); // largest value allowed

    const time_t rrExpires = squid_curtime + ttl;
    if (addrs.size() <= 1) {
        debugs(14, 5, "use first " << ttl << " from RR TTL " << rrTtl);
        expires = rrExpires;
    } else if (rrExpires < expires) {
        debugs(14, 5, "use smaller " << ttl << " from RR TTL " << rrTtl << "; was: " << (expires - squid_curtime));
        expires = rrExpires;
    } else {
        debugs(14, 7, "ignore " << ttl << " from RR TTL " << rrTtl << "; keep: " << (expires - squid_curtime));
    }
}

/// \ingroup IPCacheInternal
static void
ipcacheHandleReply(void *data, const rfc1035_rr * answers, int na, const char *error_message, const bool lastAnswer)
{
    ipcache_entry *i = static_cast<ipcache_entry*>(data);

    i->handler.forwardLookup(error_message);
    ipcacheParse(i, answers, na, error_message);

    if (!lastAnswer)
        return;

    ++IpcacheStats.replies;
    const auto age = i->handler.totalResponseTime();
    statCounter.dns.svcTime.count(age);

    if (i->addrs.empty()) {
        i->flags.negcached = true;
        i->expires = squid_curtime + Config.negativeDnsTtl;

        if (!i->error_message) {
            i->latestError("No valid address records", DBG_IMPORTANT);
            if (i->sawCname)
                ++IpcacheStats.cname_only;
        }
    }

    debugs(14, 3, "done with " << i->name() << ": " << i->addrs);
    ipcacheAddEntry(i);
    ipcacheCallback(i, false, age);
}

/**
 \ingroup IPCacheAPI
 *
 \param name        Host to resolve.
 \param handler     Pointer to the function to be called when the reply
 *          from the IP cache (or the DNS if the IP cache misses)
 \param handlerData Information that is passed to the handler and does not affect the IP cache.
 *
 * XXX: on hits and some errors, the handler is called immediately instead
 * of scheduling an async call. This reentrant behavior means that the
 * user job must be extra careful after calling ipcache_nbgethostbyname,
 * especially if the handler destroys the job. Moreover, the job has
 * no way of knowing whether the reentrant call happened.
 * Comm::Connection setup usually protects the job by scheduling an async call,
 * but some user code calls ipcache_nbgethostbyname directly.
 */
void
ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData)
{
    debugs(14, 4, name);
    ipcache_nbgethostbyname_(name, IpCacheLookupForwarder(handler, handlerData));
}

void
Dns::nbgethostbyname(const char *name, const CbcPointer<IpReceiver> &receiver)
{
    debugs(14, 4, name);
    ipcache_nbgethostbyname_(name, IpCacheLookupForwarder(receiver));
}

/// implements ipcache_nbgethostbyname() and Dns::nbgethostbyname() APIs
static void
ipcache_nbgethostbyname_(const char *name, IpCacheLookupForwarder handler)
{
    ipcache_entry *i = nullptr;
    const ipcache_addrs *addrs = nullptr;
    ++IpcacheStats.requests;

    if (name == nullptr || name[0] == '\0') {
        debugs(14, 4, "ipcache_nbgethostbyname: Invalid name!");
        ++IpcacheStats.invalid;
        static const Dns::LookupDetails details(SBuf("Invalid hostname"), -1); // error, no lookup
        handler.finalCallback(nullptr, details);
        return;
    }

    if ((addrs = ipcacheCheckNumeric(name))) {
        debugs(14, 4, "ipcache_nbgethostbyname: BYPASS for '" << name << "' (already numeric)");
        handler.forwardHits(*addrs);
        ++IpcacheStats.numeric_hits;
        const Dns::LookupDetails details; // no error, no lookup
        handler.finalCallback(addrs, details);
        return;
    }

    i = ipcache_get(name);

    if (nullptr == i) {
        /* miss */
        (void) 0;
    } else if (ipcacheExpiredEntry(i)) {
        /* hit, but expired -- bummer */
        ipcacheRelease(i);
        i = nullptr;
    } else {
        /* hit */
        debugs(14, 4, "ipcache_nbgethostbyname: HIT for '" << name << "'");

        if (i->flags.negcached)
            ++IpcacheStats.negative_hits;
        else
            ++IpcacheStats.hits;

        i->handler = std::move(handler);
        ipcacheCallback(i, true, -1); // no lookup

        return;
    }

    debugs(14, 5, "ipcache_nbgethostbyname: MISS for '" << name << "'");
    ++IpcacheStats.misses;
    i = new ipcache_entry(name);
    i->handler = std::move(handler);
    i->handler.lookupsStarting();
    idnsALookup(hashKeyStr(&i->hash), ipcacheHandleReply, i);
}

/// \ingroup IPCacheInternal
static void
ipcacheRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("ipcache",
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
    debugs(14, Important(24), "Initializing IP Cache...");
    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));
    lru_list = dlink_list();

    ipcache_high = (long) (((float) Config.ipcache.size *
                            (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
                           (float) Config.ipcache.low) / (float) 100);
    n = hashPrime(ipcache_high / 4);
    ip_table = hash_create((HASHCMP *) strcmp, n, hash4);

    ipcacheRegisterWithCacheManager();
}

/**
 \ingroup IPCacheAPI
 *
 * Is different from ipcache_nbgethostbyname in that it only checks
 * if an entry exists in the cache and does not by default contact the DNS,
 * unless this is requested, by setting the flags.
 *
 \param name        Host name to resolve.
 \param flags       Default is NULL, set to IP_LOOKUP_IF_MISS
 *          to explicitly perform DNS lookups.
 *
 \retval NULL   An error occurred during lookup
 \retval NULL   No results available in cache and no lookup specified
 \retval *  Pointer to the ipcahce_addrs structure containing the lookup results
 */
const ipcache_addrs *
ipcache_gethostbyname(const char *name, int flags)
{
    ipcache_entry *i = nullptr;
    assert(name);
    debugs(14, 3, "ipcache_gethostbyname: '" << name  << "', flags=" << std::hex << flags);
    ++IpcacheStats.requests;
    i = ipcache_get(name);

    if (nullptr == i) {
        (void) 0;
    } else if (ipcacheExpiredEntry(i)) {
        ipcacheRelease(i);
        i = nullptr;
    } else if (i->flags.negcached) {
        ++IpcacheStats.negative_hits;
        // ignore i->error_message: the caller just checks IP cache presence
        return nullptr;
    } else {
        ++IpcacheStats.hits;
        i->lastref = squid_curtime;
        // ignore i->error_message: the caller just checks IP cache presence
        return &i->addrs;
    }

    /* no entry [any more] */

    if (const auto addrs = ipcacheCheckNumeric(name)) {
        ++IpcacheStats.numeric_hits;
        return addrs;
    }

    ++IpcacheStats.misses;

    if (flags & IP_LOOKUP_IF_MISS)
        ipcache_nbgethostbyname(name, nullptr, nullptr);

    return nullptr;
}

/// \ingroup IPCacheInternal
static void
ipcacheStatPrint(ipcache_entry * i, StoreEntry * sentry)
{
    char buf[MAX_IPSTRLEN];

    if (!sentry) {
        debugs(14, DBG_CRITICAL, "ERROR: sentry is NULL!");
        return;
    }

    if (!i) {
        debugs(14, DBG_CRITICAL, "ERROR: ipcache_entry is NULL!");
        storeAppendPrintf(sentry, "CRITICAL ERROR\n");
        return;
    }

    storeAppendPrintf(sentry, " %-32.32s %c%c %6d %6d %2d(%2d)",
                      hashKeyStr(&i->hash),
                      i->flags.fromhosts ? 'H' : ' ',
                      i->flags.negcached ? 'N' : ' ',
                      (int) (squid_curtime - i->lastref),
                      (int) ((i->flags.fromhosts ? -1 : i->expires - squid_curtime)),
                      static_cast<int>(i->addrs.size()),
                      static_cast<int>(i->addrs.badCount()));

    /** \par
     * Negative-cached entries have no IPs listed. */
    if (i->flags.negcached) {
        storeAppendPrintf(sentry, "\n");
        return;
    }

    /** \par
     * Cached entries have IPs listed with a BNF of:   ip-address '-' ('OK'|'BAD') */
    bool firstLine = true;
    for (const auto &addr: i->addrs.raw()) {
        /* Display tidy-up: IPv6 are so big make the list vertical */
        const char *indent = firstLine ? "" : "                                                         ";
        storeAppendPrintf(sentry, "%s %45.45s-%3s\n",
                          indent,
                          addr.ip.toStr(buf, MAX_IPSTRLEN),
                          addr.bad() ? "BAD" : "OK ");
        firstLine = false;
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
    assert(ip_table != nullptr);
    storeAppendPrintf(sentry, "IP Cache Statistics:\n");
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

/// \ingroup IPCacheAPI
void
ipcacheInvalidate(const char *name)
{
    ipcache_entry *i;

    if ((i = ipcache_get(name)) == nullptr)
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

    if ((i = ipcache_get(name)) == nullptr)
        return;

    if (i->flags.negcached)
        i->expires = squid_curtime;

    /*
     * NOTE, don't call ipcacheRelease here because we might be here due
     * to a thread started from a callback.
     */
}

/// \ingroup IPCacheAPI
static const Dns::CachedIps *
ipcacheCheckNumeric(const char *name)
{
    Ip::Address ip;
    if (!ip.fromHost(name))
        return nullptr;

    debugs(14, 4, "HIT_BYPASS for " << name << "=" << ip);
    static Dns::CachedIps static_addrs;
    static_addrs.reset(ip);
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
        debugs(14, DBG_IMPORTANT, "WARNING: ipcacheEntry unlocked with no lock! locks=" << i->locks);
        return;
    }

    -- i->locks;

    if (ipcacheExpiredEntry(i))
        ipcacheRelease(i);
}

/// find the next good IP, wrapping if needed
/// \returns whether the search was successful
bool
Dns::CachedIps::seekNewGood(const char *name)
{
    // linear search!
    for (size_t seen = 0; seen < ips.size(); ++seen) {
        if (++goodPosition >= ips.size())
            goodPosition = 0;
        if (!ips[goodPosition].bad()) {
            debugs(14, 3, "succeeded for " << name << ": " << *this);
            return true;
        }
    }
    goodPosition = ips.size();
    debugs(14, 3, "failed for " << name << ": " << *this);
    return false;
}

void
Dns::CachedIps::reset(const Ip::Address &ip)
{
    ips.clear();
    ips.emplace_back(ip);
    goodPosition = 0;
    // Assume that the given IP is good because CachedIps are designed to never
    // run out of good IPs.
    badCount_ = 0;
}

/// makes current() calls possible after a successful markAsBad()
void
Dns::CachedIps::restoreGoodness(const char *name)
{
    if (badCount() >= size()) {
        // There are no good IPs left. Clear all bad marks. This must help
        // because we are called only after a good address was tested as bad.
        for (auto &cachedIp: ips)
            cachedIp.forgetMarking();
        badCount_ = 0;
    }
    Must(seekNewGood(name));
    debugs(14, 3, "cleared all IPs for " << name << "; now back to " << *this);
}

bool
Dns::CachedIps::have(const Ip::Address &ip, size_t *positionOrNil) const
{
    // linear search!
    size_t pos = 0;
    for (const auto &cachedIp: ips) {
        if (cachedIp.ip == ip) {
            if (auto position = positionOrNil)
                *position = pos;
            debugs(14, 7, ip << " at " << pos << " in " << *this);
            return true;
        }
    }
    // no such address; leave *position as is
    debugs(14, 7, " no " << ip << " in " << *this);
    return false;
}

void
Dns::CachedIps::pushUnique(const Ip::Address &ip)
{
    assert(!have(ip));
    [[maybe_unused]] auto &cachedIp = ips.emplace_back(ip);
    assert(!cachedIp.bad());
}

void
Dns::CachedIps::reportCurrent(std::ostream &os) const
{
    if (empty())
        os << "[no cached IPs]";
    else if (goodPosition == size())
        os << "[" << size() << " bad cached IPs]"; // could only be temporary
    else
        os << current() << " #" << (goodPosition+1) << "/" << ips.size() << "-" << badCount();
}

void
Dns::CachedIps::markAsBad(const char *name, const Ip::Address &ip)
{
    size_t badPosition = 0;
    if (!have(ip, &badPosition))
        return; // no such address

    auto &cachedIp = ips[badPosition];
    if (cachedIp.bad())
        return; // already marked correctly

    cachedIp.markAsBad();
    ++badCount_;
    debugs(14, 2, ip << " of " << name);

    if (goodPosition == badPosition)
        restoreGoodness(name);
    // else nothing to do: goodPositon still points to a good IP
}

void
Dns::CachedIps::forgetMarking(const char *name, const Ip::Address &ip)
{
    if (!badCount_)
        return; // all IPs are already "good"

    size_t badPosition = 0;
    if (!have(ip, &badPosition))
        return; // no such address

    auto &cachedIp = ips[badPosition];
    if (!cachedIp.bad())
        return; // already marked correctly

    cachedIp.forgetMarking();
    assert(!cachedIp.bad());
    --badCount_;
    debugs(14, 2, ip << " of " << name);
}

/**
 * Marks the given address as BAD.
 * Does nothing if the domain name does not exist.
 *
 \param name    domain name to have an IP marked bad
 \param addr    specific address to be marked bad
 */
void
ipcacheMarkBadAddr(const char *name, const Ip::Address &addr)
{
    if (auto cached = ipcache_get(name))
        cached->addrs.markAsBad(name, addr);
}

/// \ingroup IPCacheAPI
void
ipcacheMarkGoodAddr(const char *name, const Ip::Address &addr)
{
    if (auto cached = ipcache_get(name))
        cached->addrs.forgetMarking(name, addr);
}

/// \ingroup IPCacheInternal
static void
ipcacheFreeEntry(void *data)
{
    ipcache_entry *i = (ipcache_entry *)data;
    delete i;
}

ipcache_entry::~ipcache_entry()
{
    xfree(error_message);
    xfree(hash.key);
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
 \param name    Hostname to be linked with IP
 \param ipaddr  IP Address to be cached.
 *
 \retval 0  Success.
 \retval 1  IP address is invalid or other error.
 */
int
ipcacheAddEntryFromHosts(const char *name, const char *ipaddr)
{
    ipcache_entry *i;

    Ip::Address ip;

    if (!(ip = ipaddr)) {
        if (strchr(ipaddr, ':') && strspn(ipaddr, "0123456789abcdefABCDEF:") == strlen(ipaddr)) {
            debugs(14, 3, "ipcacheAddEntryFromHosts: Skipping IPv6 address '" << ipaddr << "'");
        } else {
            debugs(14, DBG_IMPORTANT, "ERROR: ipcacheAddEntryFromHosts: Bad IP address '" << ipaddr << "'");
        }

        return 1;
    }

    if (!Ip::EnableIpv6 && ip.isIPv6()) {
        debugs(14, 2, "skips IPv6 address in /etc/hosts because IPv6 support was disabled: " << ip);
        return 1;
    }

    if ((i = ipcache_get(name))) {
        if (1 == i->flags.fromhosts) {
            ipcacheUnlockEntry(i);
        } else if (i->locks > 0) {
            debugs(14, DBG_IMPORTANT, "ERROR: ipcacheAddEntryFromHosts: cannot add static entry for locked name '" << name << "'");
            return 1;
        } else {
            ipcacheRelease(i);
        }
    }

    i = new ipcache_entry(name);
    i->addrs.pushUnique(ip);
    i->flags.fromhosts = true;
    ipcacheAddEntry(i);
    ipcacheLockEntry(i);
    return 0;
}

#if SQUID_SNMP
/**
 \ingroup IPCacheAPI
 *
 * The function to return the ip cache statistics to via SNMP
 */
variable_list *
snmp_netIpFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = nullptr;
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
        assert(!Answer);
    }

    return Answer;
}

#endif /*SQUID_SNMP */

