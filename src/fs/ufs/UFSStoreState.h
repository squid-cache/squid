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
/// \ingroup UFS
class UFSStoreState : public StoreIOState, public IORequestor
{
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
    public:
        MEMPROXY_CLASS(UFSStoreState::_queued_read);
        char *buf;
        size_t size;
        off_t offset;
        STRCB *callback;
        void *callback_data;

    };

    class _queued_write
    {
    public:
        MEMPROXY_CLASS(UFSStoreState::_queued_write);
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
    CBDATA_CLASS2(UFSStoreState);
};

MEMPROXY_CLASS_INLINE(UFSStoreState::_queued_read);
MEMPROXY_CLASS_INLINE(UFSStoreState::_queued_write);

} //namespace Ufs
} //namespace Fs

#endif /* SQUID_FS_UFS_UFSSTORESTATE_H */

