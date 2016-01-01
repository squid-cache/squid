/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side DISKD I/O functions. */

#ifndef __STORE_DISKDIOSTRATEGY_H__
#define __STORE_DISKDIOSTRATEGY_H__

struct diomsg;

/// \ingroup diskd
class SharedMemory
{

public:
    void put(ssize_t);
    void *get(ssize_t *);
    void init(int ikey, int magic2);
    SharedMemory() : nbufs(0), buf(nullptr), inuse_map(nullptr), id(0) {}

    int nbufs;
    char *buf;
    char *inuse_map;
    int id;
};

#include "DiskIO/DiskIOStrategy.h"
#include "StoreIOState.h"

class DiskFile;

class DiskdFile;
class Lock;
class ReadRequest;

/// \ingroup diskd
class DiskdIOStrategy : public DiskIOStrategy
{

public:
    DiskdIOStrategy();
    virtual bool shedLoad();
    virtual int load();
    virtual RefCount<DiskFile> newFile(char const *path);
    virtual bool unlinkdUseful() const;
    virtual void unlinkFile (char const *);
    virtual ConfigOption *getOptionTree() const;
    virtual void init();
    virtual void sync();
    virtual int callback();
    virtual void statfs(StoreEntry & sentry) const;
    int send(int mtype, int id, DiskdFile *theFile, size_t size, off_t offset, ssize_t shm_offset, Lock *requestor);

    /** public for accessing return address's */
    SharedMemory shm;

private:
    static size_t newInstance();
    static size_t nextInstanceID;
    void openFailed();
    bool optionQ1Parse(char const *option, const char *value, int reconfiguring);
    void optionQ1Dump(StoreEntry * e) const;
    bool optionQ2Parse(char const *option, const char *value, int reconfiguring);
    void optionQ2Dump(StoreEntry * e) const;
    int send(int mtype, int id, RefCount<StoreIOState> sio, size_t size, off_t offset, ssize_t shm_offset);
    int SEND(diomsg * M, int mtype, int id, size_t size, off_t offset, ssize_t shm_offset);
    void handle(diomsg * M);
    void unlinkDone(diomsg * M);

    /**
     * magic1 is the number of messages away which we
     * stop allowing open/create for.
     */
    int magic1;

    /**
     * magic2 is the point at which we start blocking on msgsnd/msgrcv.
     * If a queue has magic2 (or more) messages away, then we read the
     * queue until the level falls below magic2.  Recommended value
     * is 75% of SHMBUFS.
     */
    int magic2;

    int away;
    int smsgid;
    int rmsgid;
    int wfd;
    size_t instanceID;
};

/// \ingroup diskd
#define SHMBUF_BLKSZ SM_PAGE_SIZE

/// \ingroup diskd
struct diskd_stats_t {
    int open_fail_queue_len;
    int block_queue_len;
    int max_away;
    int max_shmuse;
    int shmbuf_count;
    int sent_count;
    int recv_count;
    int sio_id;

    struct {
        int ops;
        int success;
        int fail;
    }

    open, create, close, unlink, read, write;
};

/// \ingroup diskd
extern diskd_stats_t diskd_stats;

#endif

