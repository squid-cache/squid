/*
 * store_ufs.h
 *
 * Internal declarations for the ufs routines
 */

#ifndef __STORE_UFS_H__
#define __STORE_UFS_H__

#include "ufscommon.h"

class UFSFile : public DiskFile
{

public:
    void *operator new(size_t);
    void operator delete(void *);
    UFSFile (char const *path);
    ~UFSFile();
    virtual void open (int, mode_t, IORequestor::Pointer);
    virtual void create (int, mode_t, IORequestor::Pointer);
    virtual void read(char *, off_t, size_t);
    virtual void write(char const *buf, size_t size, off_t offset, FREE *free_func);
    virtual void close ();
    virtual bool error() const;
    virtual int getFD() const { return fd;}

    virtual bool canRead() const;
    virtual bool ioInProgress()const;

private:
    static DRCB ReadDone;
    static DWCB WriteDone;
    CBDATA_CLASS(UFSFile);
    int fd;
    bool closed;
    void error (bool const &);
    bool error_;
    char const *path_;
    IORequestor::Pointer ioRequestor;
    void doClose();
    void readDone(int fd, const char *buf, int len, int errflag);
    void writeDone(int fd, int errflag, size_t len);
};

#include "SwapDir.h"
/*
 * Store IO stuff
 */
/* For things that aren't factored well yet */

class UfsIO : public UFSStrategy
{

public:
    virtual bool shedLoad();
    virtual int load();
    virtual StoreIOState::Pointer createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const;
    virtual DiskFile::Pointer newFile (char const *path);
    virtual void unlinkFile (char const *);
    static UfsIO Instance;
};

#include "fs/ufs/IOModule.h"

class UfsIOModule : public IOModule
{

public:
    static UfsIOModule &GetInstance();
    virtual void init();
    virtual void shutdown();
    virtual UFSStrategy *createSwapDirIOStrategy();

private:
    static UfsIOModule *Instance;
};

#endif
