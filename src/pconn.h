/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PCONN_H
#define SQUID_PCONN_H

#include "base/CbcPointer.h"
#include "base/RunnersRegistry.h"
#include "mgr/forward.h"

#include <set>

/**
 \defgroup PConnAPI Persistent Connection API
 \ingroup Component
 *
 \todo CLEANUP: Break multiple classes out of the generic pconn.h header
 */

class PconnPool;
class PeerPoolMgr;

#include "cbdata.h"
#include "hash.h"
/* for IOCB */
#include "comm.h"

/// \ingroup PConnAPI
#define PCONN_HIST_SZ (1<<16)

/** \ingroup PConnAPI
 * A list of connections currently open to a particular destination end-point.
 */
class IdleConnList: public hash_link, private IndependentRunner
{
    CBDATA_CLASS(IdleConnList);

public:
    IdleConnList(const char *key, PconnPool *parent);
    ~IdleConnList();

    /// Pass control of the connection to the idle list.
    void push(const Comm::ConnectionPointer &conn);

    /// get first conn which is not pending read fd.
    Comm::ConnectionPointer pop();

    /** Search the list for a connection which matches the 'key' details
     * and pop it off the list.
     * The list is created based on remote IP:port hash. This further filters
     * the choices based on specific local-end details requested.
     * If nothing usable is found the a nil pointer is returned.
     */
    Comm::ConnectionPointer findUseable(const Comm::ConnectionPointer &key);

    void clearHandlers(const Comm::ConnectionPointer &conn);

    int count() const { return size_; }
    void closeN(size_t count);

    // IndependentRunner API
    virtual void endingShutdown();
private:
    bool isAvailable(int i) const;
    bool removeAt(int index);
    int findIndexOf(const Comm::ConnectionPointer &conn) const;
    void findAndClose(const Comm::ConnectionPointer &conn);
    static IOCB Read;
    static CTCB Timeout;

private:
    /** List of connections we are holding.
     * Sorted as FIFO list for most efficient speeds on pop() and findUsable()
     * The worst-case pop() and scans occur on timeout and link closure events
     * where timing is less critical. Occasional slow additions are okay.
     */
    Comm::ConnectionPointer *theList_;

    /// Number of entries theList can currently hold without re-allocating (capacity).
    int capacity_;
    ///< Number of in-use entries in theList
    int size_;

    /** The pool containing this sub-list.
     * The parent performs all stats accounting, and
     * will delete us when it dies. It persists for the
     * full duration of our existence.
     */
    PconnPool *parent_;

    char fakeReadBuf_[4096]; // TODO: kill magic number.
};

#include "ip/forward.h"

class StoreEntry;
class IdleConnLimit;

/* for hash_table */
#include "hash.h"

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
    void dumpHist(StoreEntry *e) const;
    void dumpHash(StoreEntry *e) const;
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

    OBJH dump;

private:
    typedef std::set<PconnPool*> Pools; ///< unordered PconnPool collection
    Pools pools; ///< all live pools

    static PconnModule * instance;
};

#endif /* SQUID_PCONN_H */

