/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 48    Persistent Connections */

#include "squid.h"
#include "base/IoManip.h"
#include "base/PackableStream.h"
#include "CachePeer.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "SquidConfig.h"
#include "Store.h"

//TODO: re-attach to MemPools. WAS: static Mem::Allocator *pconn_fds_pool = nullptr;
PconnModule * PconnModule::instance = nullptr;

/* ========== PconnPool PRIVATE FUNCTIONS ============================================ */

const char *
PconnPool::key(const Comm::ConnectionPointer &destLink, const char *domain)
{
    LOCAL_ARRAY(char, buf, SQUIDHOSTNAMELEN * 3 + 10);

    destLink->remote.toUrl(buf, SQUIDHOSTNAMELEN * 3 + 10);

    // when connecting through a cache_peer, ignore the final destination
    if (destLink->getPeer())
        domain = nullptr;

    if (domain) {
        const int used = strlen(buf);
        snprintf(buf+used, SQUIDHOSTNAMELEN * 3 + 10-used, "/%s", domain);
    }

    debugs(48,6,"PconnPool::key(" << destLink << ", " << (domain?domain:"[no domain]") << ") is {" << buf << "}" );
    return buf;
}

void
PconnPool::dumpHist(std::ostream &yaml) const
{
    AtMostOnce heading(
        "  connection use histogram:\n"
        "    # requests per connection: closed connections that carried that many requests\n");

    for (int i = 0; i < PCONN_HIST_SZ; ++i) {
        if (hist[i] == 0)
            continue;

        yaml << heading <<
             "    " << i << ": " << hist[i] << "\n";
    }
}

void
PconnPool::dumpHash(std::ostream &yaml) const
{
    const auto hid = table;
    hash_first(hid);
    AtMostOnce title("  open connections list:\n");
    for (auto *walker = hash_next(hid); walker; walker = hash_next(hid)) {
        yaml << title <<
             "    \"" << static_cast<char *>(walker->key) << "\": " <<
             static_cast<Comm::IdleConnList *>(walker)->count() <<
             "\n";
    }
}

void
PconnPool::dump(std::ostream &yaml) const
{
    yaml << "pool " << descr << ":\n";
    dumpHist(yaml);
    dumpHash(yaml);
}

/* ========== PconnPool PUBLIC FUNCTIONS ============================================ */

PconnPool::PconnPool(const char *aDescr, const CbcPointer<PeerPoolMgr> &aMgr):
    table(nullptr), descr(aDescr),
    mgr(aMgr),
    theCount(0)
{
    int i;
    table = hash_create((HASHCMP *) strcmp, 229, hash_string);

    for (i = 0; i < PCONN_HIST_SZ; ++i)
        hist[i] = 0;

    PconnModule::GetInstance()->add(this);
}

static void
DeleteIdleConnList(void *hashItem)
{
    delete static_cast<Comm::IdleConnList *>(hashItem);
}

PconnPool::~PconnPool()
{
    PconnModule::GetInstance()->remove(this);
    hashFreeItems(table, &DeleteIdleConnList);
    hashFreeMemory(table);
    descr = nullptr;
}

void
PconnPool::push(const Comm::ConnectionPointer &conn, const char *domain)
{
    if (fdUsageHigh()) {
        debugs(48, 3, "Not many unused FDs");
        conn->close();
        return;
    } else if (shutting_down) {
        conn->close();
        debugs(48, 3, "Squid is shutting down. Refusing to do anything");
        return;
    }
    // TODO: also close used pconns if we exceed peer max-conn limit

    const char *aKey = key(conn, domain);
    auto *list = static_cast<Comm::IdleConnList *>(hash_lookup(table, aKey));

    if (!list) {
        list = new Comm::IdleConnList(aKey, this);
        debugs(48, 3, "new IdleConnList for {" << hashKeyStr(list) << "}" );
        hash_join(table, list);
    } else {
        debugs(48, 3, "found IdleConnList for {" << hashKeyStr(list) << "}" );
    }

    list->push(conn);
    assert(!comm_has_incomplete_write(conn->fd));

    LOCAL_ARRAY(char, desc, FD_DESC_SZ);
    snprintf(desc, FD_DESC_SZ, "Idle server: %s", aKey);
    fd_note(conn->fd, desc);
    debugs(48, 3, "pushed " << conn << " for " << aKey);

    // successful push notifications resume multi-connection opening sequence
    notifyManager("push");
}

Comm::ConnectionPointer
PconnPool::pop(const Comm::ConnectionPointer &dest, const char *domain, bool keepOpen)
{
    // always call shared pool first because we need to close an idle
    // connection there if we have to use a standby connection.
    if (const auto direct = popStored(dest, domain, keepOpen))
        return direct;

    // either there was no pconn to pop or this is not a retriable xaction
    if (const auto peer = dest->getPeer()) {
        if (peer->standby.pool)
            return peer->standby.pool->popStored(dest, domain, true);
    }

    return nullptr;
}

/// implements pop() API while disregarding peer standby pools
/// \returns an open connection or nil
Comm::ConnectionPointer
PconnPool::popStored(const Comm::ConnectionPointer &dest, const char *domain, const bool keepOpen)
{
    const char * aKey = key(dest, domain);

    auto *list = static_cast<Comm::IdleConnList *>(hash_lookup(table, aKey));
    if (!list) {
        debugs(48, 3, "lookup for key {" << aKey << "} failed.");
        // failure notifications resume standby conn creation after fdUsageHigh
        notifyManager("pop lookup failure");
        return Comm::ConnectionPointer();
    } else {
        debugs(48, 3, "found " << hashKeyStr(list) <<
               (keepOpen ? " to use" : " to kill"));
    }

    if (const auto popped = list->findUseable(dest)) { // may delete list
        // successful pop notifications replenish standby connections pool
        notifyManager("pop");

        if (keepOpen)
            return popped;

        popped->close();
        return Comm::ConnectionPointer();
    }

    // failure notifications resume standby conn creation after fdUsageHigh
    notifyManager("pop usability failure");
    return Comm::ConnectionPointer();
}

void
PconnPool::notifyManager(const char *reason)
{
    if (mgr.valid())
        PeerPoolMgr::Checkpoint(mgr, reason);
}

void
PconnPool::closeN(int n)
{
    hash_table *hid = table;
    hash_first(hid);

    // close N connections, one per list, to treat all lists "fairly"
    for (int i = 0; i < n && count(); ++i) {

        hash_link *current = hash_next(hid);
        if (!current) {
            hash_first(hid);
            current = hash_next(hid);
            Must(current); // must have one because the count() was positive
        }

        // may delete current
        static_cast<Comm::IdleConnList *>(current)->closeN(1);
    }
}

void
PconnPool::unlinkList(Comm::IdleConnList *list)
{
    theCount -= list->count();
    assert(theCount >= 0);
    hash_remove_link(table, list);
}

void
PconnPool::noteUses(int uses)
{
    if (uses >= PCONN_HIST_SZ)
        uses = PCONN_HIST_SZ - 1;

    ++hist[uses];
}

/* ========== PconnModule ============================================ */

/*
 * This simple class exists only for the cache manager
 */

PconnModule::PconnModule(): pools()
{
    registerWithCacheManager();
}

PconnModule *
PconnModule::GetInstance()
{
    if (instance == nullptr)
        instance = new PconnModule;

    return instance;
}

void
PconnModule::registerWithCacheManager(void)
{
    Mgr::RegisterAction("pconn",
                        "Persistent Connection Utilization Histograms",
                        DumpWrapper, Mgr::Protected::no, Mgr::Atomic::yes,
                        Mgr::Format::yaml);
}

void
PconnModule::add(PconnPool *aPool)
{
    pools.insert(aPool);
}

void
PconnModule::remove(PconnPool *aPool)
{
    pools.erase(aPool);
}

void
PconnModule::dump(std::ostream &yaml)
{
    for (const auto &p: pools)
        p->dump(yaml);
}

void
PconnModule::DumpWrapper(StoreEntry *e)
{
    PackableStream yaml(*e);
    PconnModule::GetInstance()->dump(yaml);
}

