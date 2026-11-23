/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PCONN_H
#define SQUID_SRC_PCONN_H

#include "base/CbcPointer.h"
#include "comm/IdleConnList.h"
#include "hash.h"

#include <set>
#include <iosfwd>

/**
 \defgroup PConnAPI Persistent Connection API
 \ingroup Component
 */

class PconnPool;
class PeerPoolMgr;
class StoreEntry;
class IdleConnLimit;
class IdleConnList;

/** \ingroup PConnAPI
 * Manages idle persistent connections to a caller-defined set of
 * servers (e.g., all HTTP servers). Uses a collection of IdleConnLists
 * internally to list the individual open connections to each server.
 * Controls lists existence and limits the total number of
 * idle connections across the collection.
 */
class PconnPool
{

public:
    PconnPool(const char *aDescription, const CbcPointer<PeerPoolMgr> &aMgr);
    ~PconnPool();

    void moduleInit();
    void push(const Comm::ConnectionPointer &serverConn, const char *domain);

    /**
     * Returns either a pointer to a popped connection to dest or nil.
     * Closes the connection before returning its pointer unless keepOpen.
     * For connection going to a cache_peer, supports standby connection pools.
     *
     * A caller with a non-retriable transaction should set keepOpen to false
     * and call pop() anyway, even though the caller does not want a pconn.
     * This forces us to close an available persistent connection, avoiding
     * creating a growing number of open connections when many transactions
     * create (and push) persistent connections but are not retriable and,
     * hence, do not need to pop a connection.
     */
    Comm::ConnectionPointer pop(const Comm::ConnectionPointer &dest, const char *domain, bool keepOpen);
    void count(int uses);
    void dump(std::ostream &) const;
    void unlinkList(IdleConnList *list);
    void noteUses(int uses);
    /// closes any n connections, regardless of their destination
    void closeN(int n);
    int count() const { return theCount; }
    void noteConnectionAdded() { ++theCount; }
    void noteConnectionRemoved() { assert(theCount > 0); --theCount; }

    // sends an async message to the pool manager, if any
    void notifyManager(const char *reason);

private:

    static const char *key(const Comm::ConnectionPointer &destLink, const char *domain);

    Comm::ConnectionPointer popStored(const Comm::ConnectionPointer &dest, const char *domain, const bool keepOpen);
    void dumpHist(std::ostream &) const;
    void dumpHash(std::ostream &) const;

    int hist[PCONN_HIST_SZ];
    hash_table *table;
    const char *descr;
    CbcPointer<PeerPoolMgr> mgr; ///< optional pool manager (for notifications)
    int theCount; ///< the number of pooled connections
};

class StoreEntry;
class PconnPool;

/** \ingroup PConnAPI
 * The global registry of persistent connection pools.
 */
class PconnModule
{

public:
    /** the module is a singleton until we have instance based cachemanager
     * management
     */
    static PconnModule * GetInstance();
    /** A thunk to the still C like CacheManager callback api. */
    static void DumpWrapper(StoreEntry *e);

    PconnModule();
    void registerWithCacheManager(void);

    void add(PconnPool *);
    void remove(PconnPool *); ///< unregister and forget about this pool object

    void dump(std::ostream &yaml);

private:
    typedef std::set<PconnPool*> Pools; ///< unordered PconnPool collection
    Pools pools; ///< all live pools

    static PconnModule * instance;
};

#endif /* SQUID_SRC_PCONN_H */

