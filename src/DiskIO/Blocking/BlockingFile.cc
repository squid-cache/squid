/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "BlockingFile.h"
#include "Debug.h"
#include "defines.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs_io.h"
#include "globals.h"

#include <cerrno>

CBDATA_CLASS_INIT(BlockingFile);

BlockingFile::BlockingFile(char const *aPath) : fd(-1), closed(true), error_(false)
{
    assert(aPath);
    debugs(79, 3, "BlockingFile::BlockingFile: " << aPath);
    path_ = xstrdup(aPath);
}

BlockingFile::~BlockingFile()
{
    safe_free(path_);
    doClose();
}

void
BlockingFile::open(int flags, mode_t, RefCount<IORequestor> callback)
{
    /* Simulate async calls */
    fd = file_open(path_ , flags);
    ioRequestor = callback;

    if (fd < 0) {
        debugs(79, 3, "BlockingFile::open: got failure (" << errno << ")");
        error(true);
    } else {
        closed = false;
        ++store_open_disk_fd;
        debugs(79, 3, "BlockingFile::open: opened FD " << fd);
    }

    callback->ioCompletedNotification();
}

/**
 * Alias for BlockingFile::open(...)
 \copydoc BlockingFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
 */
void
BlockingFile::create(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    /* We use the same logic path for open */
    open(flags, mode, callback);
}

void BlockingFile::doClose()
{
    if (fd > -1) {
        closed = true;
        file_close(fd);
        --store_open_disk_fd;
        fd = -1;
    }
}

void
BlockingFile::close()
{
    debugs(79, 3, "BlockingFile::close: " << this << " closing for " << ioRequestor.getRaw());
    doClose();
    assert (ioRequestor.getRaw());
    ioRequestor->closeCompleted();
}

bool
BlockingFile::canRead() const
{
    return fd > -1;
}

bool
BlockingFile::error() const
{
    if ((fd < 0 && !closed) || error_)
        return true;

    return false;
}

void BlockingFile::error(bool const &aBool)
{
    error_ = aBool;
}

void
BlockingFile::read(ReadRequest *aRequest)
{
    assert (fd > -1);
    assert (ioRequestor.getRaw());
    readRequest = aRequest;
    debugs(79, 3, HERE << aRequest->len << " for FD " << fd << " at " << aRequest->offset);
    file_read(fd, aRequest->buf, aRequest->len, aRequest->offset, ReadDone, this);
}

void
BlockingFile::ReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
{
    BlockingFile *myFile = static_cast<BlockingFile *>(my_data);
    assert (myFile);
    myFile->readDone (fd, buf, len, errflag);
}

void
BlockingFile::write(WriteRequest *aRequest)
{
    debugs(79, 3, HERE << aRequest->len << " for FD " << fd << " at " << aRequest->offset);
    writeRequest = aRequest;
    file_write(fd,
               aRequest->offset,
               (char *)aRequest->buf,
               aRequest->len,
               WriteDone,
               this,
               aRequest->free_func);
}

bool
BlockingFile::ioInProgress() const
{
    /** \retval false   IO is never pending with UFS */
    return false;
}

/*  === STATIC =========================================================== */

void
BlockingFile::readDone(int rvfd, const char *buf, int len, int errflag)
{
    debugs(79, 3, "BlockingFile::readDone: FD " << rvfd);
    assert (fd == rvfd);

    ssize_t rlen;

    if (errflag) {
        debugs(79, 3, "BlockingFile::readDone: got failure (" << errflag << ")");
        rlen = -1;
    } else {
        rlen = (ssize_t) len;
    }

    if (errflag == DISK_EOF)
        errflag = DISK_OK;  /* EOF is signalled by len == 0, not errors... */

    ReadRequest::Pointer result = readRequest;

    readRequest = NULL;

    ioRequestor->readCompleted(buf, rlen, errflag, result);
}

void
BlockingFile::WriteDone (int fd, int errflag, size_t len, void *me)
{
    BlockingFile *aFile = static_cast<BlockingFile *>(me);
    aFile->writeDone (fd, errflag, len);
}

void
BlockingFile::writeDone(int rvfd, int errflag, size_t len)
{
    assert (rvfd == fd);
    debugs(79, 3, HERE << "FD " << fd << ", len " << len);

    WriteRequest::Pointer result = writeRequest;
    writeRequest = NULL;

    if (errflag) {
        debugs(79, DBG_CRITICAL, "storeUfsWriteDone: got failure (" << errflag << ")");
        doClose();
        ioRequestor->writeCompleted (DISK_ERROR,0, result);
        return;
    }

    ioRequestor->writeCompleted(DISK_OK, len, result);
}

