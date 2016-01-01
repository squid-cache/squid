/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "disk.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "DiskThreadsDiskFile.h"
#include "fd.h"
#include "Generic.h"
#include "globals.h"
#include "StatCounters.h"
#include "Store.h"

#include <cerrno>

/* === PUBLIC =========================================================== */

CBDATA_CLASS_INIT(DiskThreadsDiskFile);

DiskThreadsDiskFile::DiskThreadsDiskFile(char const *aPath, DiskThreadsIOStrategy *anIO):fd(-1), errorOccured (false), IO(anIO),
    inProgressIOs (0)
{
    assert(aPath);
    debugs(79, 3, "UFSFile::UFSFile: " << aPath);
    path_ = xstrdup(aPath);
}

DiskThreadsDiskFile::~DiskThreadsDiskFile()
{
    safe_free(path_);
    doClose();
}

void
DiskThreadsDiskFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    ++statCounter.syscalls.disk.opens;
#if !ASYNC_OPEN

    fd = file_open(path_, flags);

    if (fd < 0) {
        debugs(79, 3, "DiskThreadsDiskFile::open: got failure (" << errno << ")");
        errorOccured = true;
        return;
    }

#endif
    ++Opening_FD;

    ioRequestor = callback;

    ++inProgressIOs;

#if ASYNC_OPEN

    aioOpen(path_, flags, mode, DiskThreadsDiskFile::OpenDone, this);

#else

    openDone(fd, NULL, fd, 0);

#endif
}

void
DiskThreadsDiskFile::read(ReadRequest * request)
{
    debugs(79, 3, "DiskThreadsDiskFile::read: " << this << ", size " << request->len);
    assert (fd > -1);
    assert (ioRequestor.getRaw());
    ++statCounter.syscalls.disk.reads;
    ++inProgressIOs;
#if ASYNC_READ

    aioRead(fd, request->offset, request->len, ReadDone, new IoResult<ReadRequest>(this, request));
#else

    file_read(fd, request->buf, request->len, request->offset, ReadDone, new IoResult<ReadRequest>(this, request));
#endif
}

void
DiskThreadsDiskFile::create(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    ++statCounter.syscalls.disk.opens;
#if !ASYNC_CREATE

    int fd = file_open(path_, flags);

    if (fd < 0) {
        debugs(79, 3, "DiskThreadsDiskFile::create: got failure (" << errno << ")");
        errorOccured = true;
        return;
    }

#endif
    ++Opening_FD;

    ioRequestor = callback;

    ++inProgressIOs;

#if ASYNC_CREATE

    aioOpen(path_, flags, mode, DiskThreadsDiskFile::OpenDone, this);

#else

    openDone (fd, NULL, fd, 0);

#endif
}

bool
DiskThreadsDiskFile::error() const
{
    return errorOccured;
}

void
DiskThreadsDiskFile::OpenDone(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno)
{
    DiskThreadsDiskFile *myFile = static_cast<DiskThreadsDiskFile *>(cbdata);
    myFile->openDone (fd, buf, aio_return, aio_errno);
}

void
DiskThreadsDiskFile::openDone(int unused, const char *unused2, int anFD, int errflag)
{
    debugs(79, 3, "DiskThreadsDiskFile::openDone: FD " << anFD << ", errflag " << errflag);
    --Opening_FD;

    fd = anFD;

    if (errflag || fd < 0) {
        errno = errflag;
        debugs(79, DBG_CRITICAL, "DiskThreadsDiskFile::openDone: " << xstrerror());
        debugs(79, DBG_IMPORTANT, "\t" << path_);
        errorOccured = true;
    } else {
        ++store_open_disk_fd;
        commSetCloseOnExec(fd);
        fd_open(fd, FD_FILE, path_);
    }

    IORequestor::Pointer t = ioRequestor;
    --inProgressIOs;
    t->ioCompletedNotification();

    debugs(79, 3, "DiskThreadsDiskFile::openDone: exiting");
}

void DiskThreadsDiskFile::doClose()
{
    if (fd > -1) {
        ++statCounter.syscalls.disk.closes;
#if ASYNC_CLOSE

        aioClose(fd);
        fd_close(fd);
#else

        aioCancel(fd);
        file_close(fd);
#endif

        --store_open_disk_fd;
        fd = -1;
    }
}

void
DiskThreadsDiskFile::close()
{
    debugs(79, 3, "DiskThreadsDiskFile::close: " << this << " closing for " << ioRequestor.getRaw());

    if (!ioInProgress()) {
        doClose();
        assert (ioRequestor != NULL);
        ioRequestor->closeCompleted();
        return;
    } else {
        debugs(79, DBG_CRITICAL, HERE << "DiskThreadsDiskFile::close: " <<
               "did NOT close because ioInProgress() is true.  now what?");
    }
}

bool
DiskThreadsDiskFile::canRead() const
{
    debugs(79, 3, "DiskThreadsDiskFile::canRead: fd is " << fd);
    return fd > -1;
}

void
DiskThreadsDiskFile::write(WriteRequest * writeRequest)
{
    debugs(79, 3, "DiskThreadsDiskFile::write: FD " << fd);
    ++statCounter.syscalls.disk.writes;
    ++inProgressIOs;
#if ASYNC_WRITE

    aioWrite(fd, writeRequest->offset, (char *)writeRequest->buf, writeRequest->len, WriteDone, new IoResult<WriteRequest>(this, writeRequest),
             writeRequest->free_func);
#else

    file_write(fd, writeRequest->offset, (char *)writeRequest->buf, writeRequest->len, WriteDone, new IoResult<WriteRequest>(this, writeRequest),
               writeRequest->free_func);
#endif
}

bool
DiskThreadsDiskFile::canWrite() const
{
    return fd > -1;
}

bool
DiskThreadsDiskFile::ioInProgress() const
{
    return inProgressIOs > 0;
}

/*  === STATIC =========================================================== */

#if ASYNC_READ
void
DiskThreadsDiskFile::ReadDone(int fd, void *my_data, const char *buf, int len, int errflag)
#else
void
DiskThreadsDiskFile::ReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
#endif
{
    IoResult<ReadRequest> * result = static_cast<IoResult<ReadRequest> *>(my_data);
    assert (result);
    result->file->readDone(fd, buf, len, errflag, result->request);
    delete result;
}

void
DiskThreadsDiskFile::readDone(int rvfd, const char *buf, int len, int errflag, RefCount<ReadRequest> request)
{
    debugs(79, 3, "DiskThreadsDiskFile::readDone: FD " << rvfd);
    assert (fd == rvfd);

    ssize_t rlen;

    if (errflag) {
        debugs(79, 3, "DiskThreadsDiskFile::readDone: got failure (" << errflag << ")");
        rlen = -1;
    } else {
        rlen = (ssize_t) len;
    }

#if ASYNC_READ
    /* translate errflag from errno to Squid disk error */
    errno = errflag;

    if (errflag)
        errflag = DISK_ERROR;
    else
        errflag = DISK_OK;

#else

    if (errflag == DISK_EOF)
        errflag = DISK_OK;  /* EOF is signalled by len == 0, not errors... */

#endif

    --inProgressIOs;

    ioRequestor->readCompleted(buf, rlen, errflag, request);
}

void
DiskThreadsDiskFile::
#if ASYNC_WRITE
WriteDone(int fd, void *my_data, const char *buf, int len, int errflag)
#else
WriteDone(int fd, int errflag, size_t len, void *my_data)
#endif
{
    IoResult<WriteRequest> * result = static_cast<IoResult<WriteRequest> *>(my_data);
    assert (result);
    result->file->writeDone(fd, errflag, len, result->request);
    delete result;
}

void
DiskThreadsDiskFile::writeDone(int rvfd, int errflag, size_t len, RefCount<WriteRequest> request)
{
    assert (rvfd == fd);
    static int loop_detect = 0;

#if ASYNC_WRITE
    /* Translate from errno to Squid disk error */

    if (errflag)
        errflag = errflag == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR;
    else
        errflag = DISK_OK;

#endif

    debugs(79, 3, "DiskThreadsDiskFile::writeDone: FD " << fd << ", len " << len << ", err=" << errflag);

    ++loop_detect;
    assert(loop_detect < 10);

    --inProgressIOs;

    ioRequestor->writeCompleted(errflag, len, request);

    --loop_detect;
}

/** \cond AUTODOCS_IGNORE */
template <class RT>
cbdata_type IoResult<RT>::CBDATA_IoResult = CBDATA_UNKNOWN;
/** \endcond */

