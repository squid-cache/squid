/*
 * $Id$
 */
#ifndef SQUID_PCONN_H
#define SQUID_PCONN_H

/**
 \defgroup PConnAPI Persistent Connection API
 \ingroup Component
 *
 \todo CLEANUP: Break multiple classes out of the generic pconn.h header
 */

class PconnPool;

/* for CBDATA_CLASS2() macros */
#include "cbdata.h"
/* for hash_link */
#include "hash.h"
/* for IOCB */
#include "comm.h"

/// \ingroup PConnAPI
#define MAX_NUM_PCONN_POOLS 10

/// \ingroup PConnAPI
#define PCONN_HIST_SZ (1<<16)

/** \ingroup PConnAPI
 * A list of connections currently open to a particular destination end-point.
 */
class IdleConnList
{
public:
    IdleConnList(const char *key, PconnPool *parent);
    ~IdleConnList();
    int numIdle() const { return nfds; }

    /// Pass control of the connection to the idle list.
    void push(const Comm::ConnectionPointer &conn);

    /** Search the list for a connection which matches the 'key' details
     * and pop it off the list.
     * The list is created based on remote IP:port hash. This further filters
     * the choices based on specific local-end details requested.
     * If nothing usable is found the a nil pointer is returned.
     */
    Comm::ConnectionPointer findUseable(const Comm::ConnectionPointer &key);

    void clearHandlers(const Comm::ConnectionPointer &conn);

private:
    bool removeAt(int index);
    int findIndexOf(const Comm::ConnectionPointer &conn) const;
    static IOCB Read;
    static PF Timeout;

public:
    hash_link hash;             /** must be first */

private:
    /** List of connections we are holding.
     * Sorted oldest to newest for most efficient speeds on pop() and findUsable()
     * The worst-case pop() and scans occur on timeout and link closure events
     * where timing is less critical. Occasional slow additions are okay.
     */
    Comm::ConnectionPointer *theList;

    /// Number of entries theList can currently hold without re-allocating (capacity).
    int nfds_alloc;
    ///< Number of in-use entries in theList
    int nfds;

    /** The pool containing this sub-list.
     * The parent performs all stats accounting, and
     * will delete us when it dies. It persists for the
     * full duration of our existence.
     */
    PconnPool *parent;

    char fakeReadBuf[4096]; // TODO: kill magic number.

    CBDATA_CLASS2(IdleConnList);
};


#include "ip/forward.h"

class StoreEntry;
class IdleConnLimit;

/* for hash_table */
#include "hash.h"

/** \ingroup PConnAPI
 * A pool of persistent connections for a particular service type.
 * HTTP servers being one such pool type, ICAP services another etc.
 */
class PconnPool
{

public:
    PconnPool(const char *);
    ~PconnPool();

    void moduleInit();
    void push(const Comm::ConnectionPointer &serverConn, const char *domain);

    /**
     * Updates destLink to point at an existing open connection if available and retriable.
     * Otherwise, return false.
     *
     * We close available persistent connection if the caller transaction is not
     * retriable to avoid having a growing number of open connections when many
     * transactions create persistent connections but are not retriable.
     */
    Comm::ConnectionPointer pop(const Comm::ConnectionPointer &destLink, const char *domain, bool retriable);
    void count(int uses);
    void dumpHist(StoreEntry *e) const;
    void dumpHash(StoreEntry *e) const;
    void unlinkList(IdleConnList *list) const;

private:

    static const char *key(const Comm::ConnectionPointer &destLink, const char *domain);

    int hist[PCONN_HIST_SZ];
    hash_table *table;
    const char *descr;
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

    OBJH dump;

private:
    PconnPool **pools;

    static PconnModule * instance;

    int poolCount;
};

#endif /* SQUID_PCONN_H */
