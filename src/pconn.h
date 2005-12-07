
#ifndef SQUID_PCONN_H
#define SQUID_PCONN_H

#define MAX_NUM_PCONN_POOLS 10
#define PCONN_HIST_SZ (1<<16)

class PconnPool;

class IdleConnList
{

public:
    IdleConnList(const char *key, PconnPool *parent);
    ~IdleConnList();
    int numIdle() { return nfds; }

    int findFDIndex(int fd);
    void removeFD(int fd);
    void push(int fd);
    int findUseableFD();
    void clearHandlers(int fd);

private:
    static IOCB read;
    static PF timeout;

public:
    hash_link hash;             /* must be first */

private:
    int *fds;
    int nfds_alloc;
    int nfds;
    PconnPool *parent;
    char fakeReadBuf[4096];
    CBDATA_CLASS2(IdleConnList);
};

class PconnPool
{

public:
    PconnPool(const char *);

    void moduleInit();
    void push(int fd, const char *host, u_short port, const char *domain);
    int pop(const char *host, u_short port, const char *domain);
    void count(int uses);
    void dumpHist(StoreEntry *e);
    void unlinkList(IdleConnList *list) const;

private:

    static const char *key(const char *host, u_short port, const char *domain);

    int hist[PCONN_HIST_SZ];
    hash_table *table;
    const char *descr;

};

class PconnModule
{

public:
    PconnModule();

    void add
        (PconnPool *);

    OBJH dump;

private:
    PconnPool **pools;

    int poolCount;
};

#endif /* SQUID_PCONN_H */
