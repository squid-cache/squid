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
    virtual void deleteSelf() const;
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

private:
    static DRCB ReadDone;
    static DWCB WriteDone;
    CBDATA_CLASS(UFSFile);
    int fd;
    char const *path_;
    IORequestor::Pointer ioRequestor;
    void doClose();
    void readDone(int fd, const char *buf, int len, int errflag);
    void writeDone(int fd, int errflag, size_t len);
};

class ufsstate_t : public UFSStoreState
{

public:
    virtual void deleteSelf() const {delete this;}

    void * operator new (size_t);
    void operator delete (void *);
    ufsstate_t(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data);
    ~ufsstate_t();
    void close();
    void ioCompletedNotification();
    void readCompleted(const char *buf, int len, int errflag);
    void writeCompleted(int errflag, size_t len);
    void closeCompleted();

private:
    CBDATA_CLASS(ufsstate_t);
    void doCallback (int);
};


#include "SwapDir.h"
/*
 * Store IO stuff
 */
/* For things that aren't factored well yet */

class UfsSwapDir: public UFSSwapDir
{
    virtual void dump(StoreEntry &)const;
    virtual void unlink(StoreEntry &);
    virtual int canStore(StoreEntry const&)const;
    virtual void parse (int index, char *path);
    virtual void reconfigure (int, char *);
    virtual void unlinkFile (char const *);
};

class UfsIO : public UFSStrategy
{

public:
    virtual bool shedLoad();
    virtual void deleteSelf() const;
    virtual StoreIOState::Pointer createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const;
    virtual DiskFile::Pointer newFile (char const *path);
    static UfsIO Instance;
};

#endif
