/*
 * store_diskd.h
 *
 * Internal declarations for the diskd routines
 */

#ifndef __STORE_DISKD_H__
#define __STORE_DISKD_H__

#include "ufscommon.h"

/*
 * magic2 is the point at which we start blocking on msgsnd/msgrcv.
 * If a queue has magic2 (or more) messages away, then we read the
 * queue until the level falls below magic2.  Recommended value
 * is 75% of SHMBUFS. magic1 is the number of messages away which we
 * stop allowing open/create for.
 */

typedef struct _diomsg diomsg;

class DiskdIO;

class DiskdFile : public DiskFile
{

public:
    virtual void deleteSelf() const;
    void * operator new (size_t);
    void operator delete (void *);
    DiskdFile (char const *path, DiskdIO *);
    ~DiskdFile();
    virtual void open (int, mode_t, IORequestor::Pointer);
    virtual void create (int, mode_t, IORequestor::Pointer);
    virtual void read(char *, off_t, size_t);
    virtual void write(char const *buf, size_t size, off_t offset, FREE *free_func);
    virtual void close ();
    virtual bool error() const;
    virtual bool canRead() const;
    virtual bool ioInProgress()const;

    /* Temporary */
    int getID() const {return id;}

    void completed (diomsg *);

private:
    int id;
    char const *path_;
    bool errorOccured;
    DiskdIO *IO;
    IORequestor::Pointer ioRequestor;
    CBDATA_CLASS(DiskdFile);
    void openDone(diomsg *);
    void createDone (diomsg *);
    void readDone (diomsg *);
    void writeDone (diomsg *);
    void closeDone (diomsg *);
    int mode;
    void notifyClient();
    bool canNotifyClient() const;
    void ioAway();
    void ioCompleted();
    size_t inProgressIOs;
};

class SharedMemory
{

public:
    void put(off_t);

    void *get
    (off_t *);

    void init (int ikey, int magic2);

    int nbufs;

    char *buf;

    char *inuse_map;

    int id;
};

#include "dio.h"

struct _diskd_stats
{
    int open_fail_queue_len;
    int block_queue_len;
    int max_away;
    int max_shmuse;
    int shmbuf_count;
    int sent_count;
    int recv_count;
    int sio_id;

    struct
    {
        int ops;
        int success;
        int fail;
    }

    open, create, close, unlink, read, write;
};

typedef struct _diskd_stats diskd_stats_t;

class SwapDir;
#define SHMBUF_BLKSZ SM_PAGE_SIZE

extern diskd_stats_t diskd_stats;

#include "fs/ufs/IOModule.h"

class DiskdIOModule : public IOModule
{

public:
    static DiskdIOModule &GetInstance();
    DiskdIOModule();
    virtual void init();
    virtual void shutdown();
    virtual UFSStrategy *createSwapDirIOStrategy();

private:
    static DiskdIOModule *Instance;
    bool initialised;
};

/* Per SwapDir instance */

class DiskdIO : public UFSStrategy
{

public:
    DiskdIO();
    virtual bool shedLoad();
    virtual void deleteSelf() const;
    virtual void openFailed();
    virtual int load();
    virtual StoreIOState::Pointer createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const;
    virtual DiskFile::Pointer newFile (char const *path);
    virtual SwapDirOption *getOptionTree() const;
    virtual void unlinkFile (char const *);
    void storeDiskdHandle(diomsg * M);
    virtual void init();
    virtual int callback();
    virtual void sync();
    virtual void statfs(StoreEntry & sentry)const;
    int away;
    int magic1;
    int magic2;
    int smsgid;
    int rmsgid;
    int wfd;
    SharedMemory shm;

private:
    static size_t newInstance();
    bool optionQ1Parse(char const *option, const char *value, int reconfiguring);
    void optionQ1Dump(StoreEntry * e) const;
    bool optionQ2Parse(char const *option, const char *value, int reconfiguring);
    void optionQ2Dump(StoreEntry * e) const;
    void unlinkDone(diomsg * M);
    static size_t nextInstanceID;
    size_t instanceID;
};

extern void storeDiskdStats(StoreEntry * sentry);

#endif
