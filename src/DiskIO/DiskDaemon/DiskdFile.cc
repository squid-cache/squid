/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side DISKD I/O functions. */

#include "squid.h"
#include "ConfigOption.h"
#include "diomsg.h"
#include "DiskdFile.h"
#include "DiskdIOStrategy.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "StatCounters.h"

#if HAVE_SYS_IPC_H
#include <sys/ipc.h>
#endif
#if HAVE_SYS_MSG_H
#include <sys/msg.h>
#endif
#if HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif

CBDATA_CLASS_INIT(DiskdFile);

DiskdFile::DiskdFile(char const *aPath, DiskdIOStrategy *anIO) :
    errorOccured(false),
    IO(anIO),
    mode(0),
    inProgressIOs(0)
{
    assert(aPath);
    debugs(79, 3, "DiskdFile::DiskdFile: " << aPath);
    path_ = xstrdup(aPath);
    id = diskd_stats.sio_id;
    ++diskd_stats.sio_id;
}

DiskdFile::~DiskdFile()
{
    assert(inProgressIOs == 0);
    safe_free (path_);
}

void
DiskdFile::open(int flags, mode_t, RefCount<IORequestor> callback)
{
    debugs(79, 3, "DiskdFile::open: " << this << " opening for " << callback.getRaw());
    assert(ioRequestor.getRaw() == NULL);
    ioRequestor = callback;
    assert(callback.getRaw());
    mode = flags;
    ssize_t shm_offset;
    char *buf = (char *)IO->shm.get(&shm_offset);
    xstrncpy(buf, path_, SHMBUF_BLKSZ);
    ioAway();
    int x = IO->send(_MQD_OPEN,
                     id,
                     this,
                     strlen(buf) + 1,
                     mode,
                     shm_offset,
                     NULL);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        //        IO->shm.put (shm_offset);
        ioRequestor->ioCompletedNotification();
        ioRequestor = NULL;
    }

    ++diskd_stats.open.ops;
}

void
DiskdFile::create(int flags, mode_t, RefCount<IORequestor> callback)
{
    debugs(79, 3, "DiskdFile::create: " << this << " creating for " << callback.getRaw());
    assert (ioRequestor.getRaw() == NULL);
    ioRequestor = callback;
    assert (callback.getRaw());
    mode = flags;
    ssize_t shm_offset;
    char *buf = (char *)IO->shm.get(&shm_offset);
    xstrncpy(buf, path_, SHMBUF_BLKSZ);
    ioAway();
    int x = IO->send(_MQD_CREATE,
                     id,
                     this,
                     strlen(buf) + 1,
                     mode,
                     shm_offset,
                     NULL);

    if (x < 0) {
        int xerrno = errno;
        ioCompleted();
        errorOccured = true;
        //        IO->shm.put (shm_offset);
        debugs(79, DBG_IMPORTANT, "storeDiskdSend CREATE: " << xstrerr(xerrno));
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    ++diskd_stats.create.ops;
}

void
DiskdFile::read(ReadRequest *aRead)
{
    assert (ioRequestor.getRaw() != NULL);
    ssize_t shm_offset;
    char *rbuf = (char *)IO->shm.get(&shm_offset);
    assert(rbuf);
    ioAway();
    int x = IO->send(_MQD_READ,
                     id,
                     this,
                     aRead->len,
                     aRead->offset,
                     shm_offset,
                     aRead);

    if (x < 0) {
        int xerrno = errno;
        ioCompleted();
        errorOccured = true;
        //        IO->shm.put (shm_offset);
        debugs(79, DBG_IMPORTANT, "storeDiskdSend READ: " << xstrerr(xerrno));
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    ++diskd_stats.read.ops;
}

void
DiskdFile::close()
{
    debugs(79, 3, "DiskdFile::close: " << this << " closing for " << ioRequestor.getRaw());
    assert (ioRequestor.getRaw());
    ioAway();
    int x = IO->send(_MQD_CLOSE,
                     id,
                     this,
                     0,
                     0,
                     -1,
                     NULL);

    if (x < 0) {
        int xerrno = errno;
        ioCompleted();
        errorOccured = true;
        debugs(79, DBG_IMPORTANT, "storeDiskdSend CLOSE: " << xstrerr(xerrno));
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    ++diskd_stats.close.ops;
}

bool
DiskdFile::error() const
{
    return errorOccured;
}

bool
DiskdFile::canRead() const
{
    return !error();
}

bool
DiskdFile::canNotifyClient() const
{
    if (!ioRequestor.getRaw()) {
        debugs(79, 3, "DiskdFile::canNotifyClient: No ioRequestor to notify");
        return false;
    }

    return true;
}

void
DiskdFile::notifyClient()
{
    if (!canNotifyClient()) {
        return;
    }

    ioRequestor->ioCompletedNotification();
}

void
DiskdFile::completed(diomsg *M)
{
    assert (M->newstyle);

    switch (M->mtype) {

    case _MQD_OPEN:
        openDone(M);
        break;

    case _MQD_CREATE:
        createDone(M);
        break;

    case _MQD_CLOSE:
        closeDone(M);
        break;

    case _MQD_READ:
        readDone(M);
        break;

    case _MQD_WRITE:
        writeDone(M);
        break;

    case _MQD_UNLINK:
        assert (0);
        break;

    default:
        assert(0);
        break;
    }
}

void
DiskdFile::openDone(diomsg *M)
{
    ++statCounter.syscalls.disk.opens;
    debugs(79, 3, "storeDiskdOpenDone: status " << M->status);

    if (M->status < 0) {
        ++diskd_stats.open.fail;
        errorOccured = true;
    } else {
        ++diskd_stats.open.success;
    }

    ioCompleted();
    notifyClient();
}

void
DiskdFile::createDone(diomsg *M)
{
    ++statCounter.syscalls.disk.opens;
    debugs(79, 3, "storeDiskdCreateDone: status " << M->status);

    if (M->status < 0) {
        ++diskd_stats.create.fail;
        errorOccured = true;
    } else {
        ++diskd_stats.create.success;
    }

    ioCompleted();
    notifyClient();
}

void
DiskdFile::write(WriteRequest *aRequest)
{
    debugs(79, 3, "DiskdFile::write: this " << (void *)this << ", buf " << (void *)aRequest->buf << ", off " << aRequest->offset << ", len " << aRequest->len);
    ssize_t shm_offset;
    char *sbuf = (char *)IO->shm.get(&shm_offset);
    memcpy(sbuf, aRequest->buf, aRequest->len);

    if (aRequest->free_func)
        aRequest->free_func(const_cast<char *>(aRequest->buf));

    ioAway();

    int x = IO->send(_MQD_WRITE,
                     id,
                     this,
                     aRequest->len,
                     aRequest->offset,
                     shm_offset,
                     aRequest);

    if (x < 0) {
        int xerrno = errno;
        ioCompleted();
        errorOccured = true;
        debugs(79, DBG_IMPORTANT, "storeDiskdSend WRITE: " << xstrerr(xerrno));
        //        IO->shm.put (shm_offset);
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    ++diskd_stats.write.ops;
}

void
DiskdFile::ioAway()
{
    ++inProgressIOs;
}

void
DiskdFile::ioCompleted()
{
    --inProgressIOs;
}

void
DiskdFile::closeDone(diomsg * M)
{
    ++statCounter.syscalls.disk.closes;
    debugs(79, 3, "DiskdFile::closeDone: status " << M->status);

    if (M->status < 0) {
        ++diskd_stats.close.fail;
        errorOccured = true;
    } else {
        ++diskd_stats.close.success;
    }

    ioCompleted();

    if (canNotifyClient())
        ioRequestor->closeCompleted();

    ioRequestor = NULL;
}

void
DiskdFile::readDone(diomsg * M)
{
    ++statCounter.syscalls.disk.reads;
    debugs(79, 3, "DiskdFile::readDone: status " << M->status);
    assert (M->requestor);
    ReadRequest::Pointer readRequest = dynamic_cast<ReadRequest *>(M->requestor);

    /* remove the free protection */
    if (readRequest != NULL) {
        const uint32_t lcount = readRequest->unlock();
        if (lcount == 0)
            debugs(79, DBG_IMPORTANT, "invariant check failed: readRequest reference count is 0");
    }

    if (M->status < 0) {
        ++diskd_stats.read.fail;
        ioCompleted();
        errorOccured = true;
        ioRequestor->readCompleted(NULL, -1, DISK_ERROR, readRequest);
        return;
    }

    ++diskd_stats.read.success;

    ioCompleted();
    ioRequestor->readCompleted (IO->shm.buf + M->shm_offset,  M->status, DISK_OK, readRequest);
}

void
DiskdFile::writeDone(diomsg *M)
{
    ++statCounter.syscalls.disk.writes;
    debugs(79, 3, "storeDiskdWriteDone: status " << M->status);
    assert (M->requestor);
    WriteRequest::Pointer writeRequest = dynamic_cast<WriteRequest *>(M->requestor);

    /* remove the free protection */
    if (writeRequest != NULL) {
        const uint32_t lcount = writeRequest->unlock();
        if (lcount == 0)
            debugs(79, DBG_IMPORTANT, "invariant check failed: writeRequest reference count is 0");
    }

    if (M->status < 0) {
        errorOccured = true;
        ++diskd_stats.write.fail;
        ioCompleted();
        ioRequestor->writeCompleted (DISK_ERROR,0, writeRequest);
        return;
    }

    ++diskd_stats.write.success;
    ioCompleted();
    ioRequestor->writeCompleted (DISK_OK,M->status, writeRequest);
}

bool
DiskdFile::ioInProgress()const
{
    return inProgressIOs != 0;
}

