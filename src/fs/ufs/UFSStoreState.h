/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FS_UFS_UFSSTORESTATE_H
#define SQUID_SRC_FS_UFS_UFSSTORESTATE_H

#include "DiskIO/IORequestor.h"
#include "StoreIOState.h"

#include <queue>

namespace Fs
{
namespace Ufs
{

class UFSStoreState : public StoreIOState, public IORequestor
{
    CBDATA_CLASS(UFSStoreState);

public:
    UFSStoreState(SwapDir * SD, StoreEntry * anEntry, STIOCB * callback_, void *callback_data_);
    ~UFSStoreState() override;
    void close(int how) override;
    void closeCompleted() override;
    // protected:
    void ioCompletedNotification() override;
    void readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest>) override;
    void writeCompleted(int errflag, size_t len, RefCount<WriteRequest>) override;
    RefCount<DiskFile> theFile;
    bool opening;
    bool creating;
    bool closing;
    bool reading;
    bool writing;
    /* StoreIOState API */
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data) override;
    bool write(char const *buf, size_t size, off_t offset, FREE * free_func) override;

protected:
    virtual void doCloseCallback (int errflag);

    class _queued_read
    {
        MEMPROXY_CLASS(UFSStoreState::_queued_read);
    public:
        _queued_read(char *b, size_t s, off_t o, STRCB *cb, void *data) :
            buf(b),
            size(s),
            offset(o),
            callback(cb),
            callback_data(cbdataReference(data))
        {}
        ~_queued_read() {
            cbdataReferenceDone(callback_data);
        }
        _queued_read(const _queued_read &qr) = delete;
        _queued_read &operator =(const _queued_read &qr) = delete;

        char *buf;
        size_t size;
        off_t offset;
        STRCB *callback;
        void *callback_data;
    };
    std::queue<Ufs::UFSStoreState::_queued_read> pending_reads;

    class _queued_write
    {
        MEMPROXY_CLASS(UFSStoreState::_queued_write);
    public:
        _queued_write(const char *b, size_t s, off_t o, FREE *f) :
            buf(b),
            size(s),
            offset(o),
            free_func(f)
        {}
        ~_queued_write() {
            /*
              * DPW 2006-05-24
              * Note "free_func" is memNodeWriteComplete(), which doesn't
              * really free the memory.  Instead it clears the node's
              * write_pending flag.
              */
            if (free_func && buf)
                free_func(const_cast<char *>(buf));
        }
        _queued_write(const _queued_write &qr) = delete;
        _queued_write &operator =(const _queued_write &qr) = delete;

        char const *buf;
        size_t size;
        off_t offset;
        FREE *free_func;
    };
    std::queue<Ufs::UFSStoreState::_queued_write> pending_writes;

    // TODO: These should be in the IO strategy

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

#endif /* SQUID_SRC_FS_UFS_UFSSTORESTATE_H */

