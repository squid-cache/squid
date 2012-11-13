/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
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
    void * operator new (size_t);
    void operator delete (void *);
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
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    void write(char const *buf, size_t size, off_t offset, FREE * free_func);

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
    CBDATA_CLASS(UFSStoreState);
};

MEMPROXY_CLASS_INLINE(UFSStoreState::_queued_read);
MEMPROXY_CLASS_INLINE(UFSStoreState::_queued_write);

} //namespace Ufs
} //namespace Fs

#endif /* SQUID_FS_UFS_UFSSTORESTATE_H */
