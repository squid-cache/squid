/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_UFS_UFSSTORESTATE_H
#define SQUID_FS_UFS_UFSSTORESTATE_H

#include "DiskIO/IORequestor.h"
#include "SquidList.h"
#include "StoreIOState.h"

namespace Fs
{
namespace Ufs
{

class UFSStoreState : public StoreIOState, public IORequestor
{
    CBDATA_CLASS(UFSStoreState);

public:
    UFSStoreState(SwapDir * SD, StoreEntry * anEntry, STIOCB * callback_, void *callback_data_);
    ~UFSStoreState();
    virtual void close(int how);
    virtual void closeCompleted();
    // protected:
    virtual void ioCompletedNotification();
    virtual void readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest>);
    virtual void writeCompleted(int errflag, size_t len, RefCount<WriteRequest>);
    RefCount<DiskFile> theFile;
    bool opening;
    bool creating;
    bool closing;
    bool reading;
    bool writing;
    /* StoreIOState API */
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    virtual bool write(char const *buf, size_t size, off_t offset, FREE * free_func);

protected:
    virtual void doCloseCallback (int errflag);

    class _queued_read
    {
        MEMPROXY_CLASS(UFSStoreState::_queued_read);
    public:
        _queued_read() : buf(NULL), size(0), offset(0), callback(NULL), callback_data(NULL) {}

        char *buf;
        size_t size;
        off_t offset;
        STRCB *callback;
        void *callback_data;
    };

    class _queued_write
    {
        MEMPROXY_CLASS(UFSStoreState::_queued_write);
    public:
        _queued_write() : buf(NULL), size(0), offset(0), free_func(NULL) {}

        char const *buf;
        size_t size;
        off_t offset;
        FREE *free_func;
    };

    /** \todo These should be in the IO strategy */

    struct {
        /**
         * DPW 2006-05-24
         * the write_draining flag is used to avoid recursion inside
         * the UFSStoreState::drainWriteQueue() method.
         */
        bool write_draining;
        /**
         * DPW 2006-05-24
         * The try_closing flag is set by UFSStoreState::tryClosing()
         * when UFSStoreState wants to close the file, but cannot
         * because of pending I/Os.  If set, UFSStoreState will
         * try to close again in the I/O callbacks.
         */
        bool try_closing;
    } flags;
    link_list *pending_reads;
    link_list *pending_writes;
    void queueRead(char *, size_t, off_t, STRCB *, void *);
    void queueWrite(char const *, size_t, off_t, FREE *);
    bool kickReadQueue();
    void drainWriteQueue();
    void tryClosing();
    char *read_buf;

private:
    void openDone();
    void freePending();
    void doWrite();
};

} //namespace Ufs
} //namespace Fs

#endif /* SQUID_FS_UFS_UFSSTORESTATE_H */

