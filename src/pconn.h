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

/// \ingroup PConnAPI
class IdleConnList
{
public:
    IdleConnList(const char *key, PconnPool *parent);
    ~IdleConnList();

    int findFDIndex(int fd); ///< search from the end of array
    void removeFD(int fd);
    void push(int fd);
    int findUseableFD();     ///< find first from the end not pending read fd.
    void clearHandlers(int fd);

    int count() const { return nfds; }

private:
    static IOCB read;
    static PF timeout;

public:
    hash_link hash;             /** must be first */

private:
    int *fds;
    int nfds_alloc;
    int nfds;
    PconnPool *parent;
    char fakeReadBuf[4096];
    CBDATA_CLASS2(IdleConnList);
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
    PconnPool(const char *);
    ~PconnPool();

    void moduleInit();
    void push(int fd, const char *host, u_short port, const char *domain, Ip::Address &client_address);
    int pop(const char *host, u_short port, const char *domain, Ip::Address &client_address, bool retriable);
    void noteUses(int uses);
    void dumpHist(StoreEntry *e);
    void dumpHash(StoreEntry *e);
    void unlinkList(IdleConnList *list);
    void closeN(int n, const char *host, u_short port, const char *domain, Ip::Address &client_address);
    int count() const { return theCount; }
    void noteConnectionAdded() { ++theCount; }
    void noteConnectionRemoved() { assert(theCount > 0); --theCount; }

private:

    static const char *key(const char *host, u_short port, const char *domain, Ip::Address &client_address);

    int hist[PCONN_HIST_SZ];
    hash_table *table;
    const char *descr;
    int theCount; ///< the number of pooled connections
};


class StoreEntry;
class PconnPool;

/// \ingroup PConnAPI
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
