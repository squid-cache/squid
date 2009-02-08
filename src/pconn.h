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
    int numIdle() { return nfds; }

    int findFDIndex(int fd); ///< search from the end of array
    void removeFD(int fd);
    void push(int fd);
    int findUseableFD();     ///< find first from the end not pending read fd.
    void clearHandlers(int fd);

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


class IpAddress;
class StoreEntry;
class IdleConnLimit;

/* for hash_table */
#include "hash.h"

/// \ingroup PConnAPI
class PconnPool
{

public:
    PconnPool(const char *);
    ~PconnPool();

    void moduleInit();
    void push(int fd, const char *host, u_short port, const char *domain, IpAddress &client_address);
    int pop(const char *host, u_short port, const char *domain, IpAddress &client_address, bool retriable);
    void count(int uses);
    void dumpHist(StoreEntry *e);
    void dumpHash(StoreEntry *e);
    void unlinkList(IdleConnList *list) const;

private:

    static const char *key(const char *host, u_short port, const char *domain, IpAddress &client_address);

    int hist[PCONN_HIST_SZ];
    hash_table *table;
    const char *descr;

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
