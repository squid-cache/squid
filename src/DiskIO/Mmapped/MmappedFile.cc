/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "Debug.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/Mmapped/MmappedFile.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs_io.h"
#include "globals.h"

#include <cerrno>
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

// Some systems such as Hurd provide mmap() API but do not support MAP_NORESERVE
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

CBDATA_CLASS_INIT(MmappedFile);

// helper class to deal with mmap(2) offset alignment and other low-level specs
class Mmapping
{
public:
    Mmapping(int fd, size_t length, int prot, int flags, off_t offset);
    ~Mmapping();

    void *map(); ///< calls mmap(2); returns usable buffer or nil on failure
    bool unmap(); ///< unmaps previously mapped buffer, if any

private:
    const int fd; ///< descriptor of the mmapped file
    const size_t length; ///< user-requested data length, needed for munmap
    const int prot; ///< mmap(2) "protection" flags
    const int flags; ///< other mmap(2) flags
    const off_t offset; ///< user-requested data offset

    off_t delta; ///< mapped buffer increment to hit user offset
    void *buf; ///< buffer returned by mmap, needed for munmap
};

MmappedFile::MmappedFile(char const *aPath): fd(-1),
    minOffset(0), maxOffset(-1), error_(false)
{
    assert(aPath);
    path_ = xstrdup(aPath);
    debugs(79,5, HERE << this << ' ' << path_);
}

MmappedFile::~MmappedFile()
{
    safe_free(path_);
    doClose();
}

// XXX: almost a copy of BlockingFile::open
void
MmappedFile::open(int flags, mode_t, RefCount<IORequestor> callback)
{
    assert(fd < 0);

    /* Simulate async calls */
    fd = file_open(path_, flags);
    ioRequestor = callback;

    if (fd < 0) {
        int xerrno = errno;
        debugs(79,3, "open error: " << xstrerr(xerrno));
        error_ = true;
    } else {
        ++store_open_disk_fd;
        debugs(79,3, "FD " << fd);

        // setup mapping boundaries
        struct stat sb;
        if (fstat(fd, &sb) == 0)
            maxOffset = sb.st_size; // we do not expect it to change
    }

    callback->ioCompletedNotification();
}

/**
 * Alias for MmappedFile::open(...)
 \copydoc MmappedFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
 */
void
MmappedFile::create(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    /* We use the same logic path for open */
    open(flags, mode, callback);
}

void MmappedFile::doClose()
{
    if (fd >= 0) {
        file_close(fd);
        fd = -1;
        --store_open_disk_fd;
    }
}

void
MmappedFile::close()
{
    debugs(79, 3, HERE << this << " closing for " << ioRequestor);
    doClose();
    assert(ioRequestor != NULL);
    ioRequestor->closeCompleted();
}

bool
MmappedFile::canRead() const
{
    return fd >= 0;
}

bool
MmappedFile::canWrite() const
{
    return fd >= 0;
}

bool
MmappedFile::error() const
{
    return error_;
}

void
MmappedFile::read(ReadRequest *aRequest)
{
    debugs(79,3, HERE << "(FD " << fd << ", " << aRequest->len << ", " <<
           aRequest->offset << ")");

    assert(fd >= 0);
    assert(ioRequestor != NULL);
    assert(aRequest->len > 0); // TODO: work around mmap failures on zero-len?
    assert(aRequest->offset >= 0);
    assert(!error_); // TODO: propagate instead?

    assert(minOffset < 0 || minOffset <= aRequest->offset);
    assert(maxOffset < 0 || static_cast<uint64_t>(aRequest->offset + aRequest->len) <= static_cast<uint64_t>(maxOffset));

    Mmapping mapping(fd, aRequest->len, PROT_READ, MAP_PRIVATE | MAP_NORESERVE,
                     aRequest->offset);

    bool done = false;
    if (void *buf = mapping.map()) {
        memcpy(aRequest->buf, buf, aRequest->len);
        done = mapping.unmap();
    }
    error_ = !done;

    const ssize_t rlen = error_ ? -1 : (ssize_t)aRequest->len;
    const int errflag = error_ ? DISK_ERROR :DISK_OK;
    ioRequestor->readCompleted(aRequest->buf, rlen, errflag, aRequest);
}

void
MmappedFile::write(WriteRequest *aRequest)
{
    debugs(79,3, HERE << "(FD " << fd << ", " << aRequest->len << ", " <<
           aRequest->offset << ")");

    assert(fd >= 0);
    assert(ioRequestor != NULL);
    assert(aRequest->len > 0); // TODO: work around mmap failures on zero-len?
    assert(aRequest->offset >= 0);
    assert(!error_); // TODO: propagate instead?

    assert(minOffset < 0 || minOffset <= aRequest->offset);
    assert(maxOffset < 0 || static_cast<uint64_t>(aRequest->offset + aRequest->len) <= static_cast<uint64_t>(maxOffset));

    const ssize_t written =
        pwrite(fd, aRequest->buf, aRequest->len, aRequest->offset);
    if (written < 0) {
        debugs(79, DBG_IMPORTANT, HERE << "error: " << xstrerr(errno));
        error_ = true;
    } else if (static_cast<size_t>(written) != aRequest->len) {
        debugs(79, DBG_IMPORTANT, HERE << "problem: " << written << " < " << aRequest->len);
        error_ = true;
    }

    if (aRequest->free_func)
        (aRequest->free_func)(const_cast<char*>(aRequest->buf)); // broken API?

    if (!error_) {
        debugs(79,5, HERE << "wrote " << aRequest->len << " to FD " << fd << " at " << aRequest->offset);
    } else {
        doClose();
    }

    const ssize_t rlen = error_ ? 0 : (ssize_t)aRequest->len;
    const int errflag = error_ ? DISK_ERROR :DISK_OK;
    ioRequestor->writeCompleted(errflag, rlen, aRequest);
}

/// we only support blocking I/O
bool
MmappedFile::ioInProgress() const
{
    return false;
}

Mmapping::Mmapping(int aFd, size_t aLength, int aProt, int aFlags, off_t anOffset):
    fd(aFd), length(aLength), prot(aProt), flags(aFlags), offset(anOffset),
    delta(-1), buf(NULL)
{
}

Mmapping::~Mmapping()
{
    if (buf)
        unmap();
}

void *
Mmapping::map()
{
    // mmap(2) requires that offset is a multiple of the page size
    static const int pageSize = getpagesize();
    delta = offset % pageSize;

    buf = mmap(NULL, length + delta, prot, flags, fd, offset - delta);

    if (buf == MAP_FAILED) {
        const int errNo = errno;
        debugs(79,3, HERE << "error FD " << fd << "mmap(" << length << '+' <<
               delta << ", " << offset << '-' << delta << "): " << xstrerr(errNo));
        buf = NULL;
        return NULL;
    }

    return static_cast<char*>(buf) + delta;
}

bool
Mmapping::unmap()
{
    debugs(79,9, HERE << "FD " << fd <<
           " munmap(" << buf << ", " << length << '+' << delta << ')');

    if (!buf) // forgot or failed to map
        return false;

    const bool error = munmap(buf, length + delta) != 0;
    if (error) {
        const int errNo = errno;
        debugs(79,3, HERE << "error FD " << fd <<
               " munmap(" << buf << ", " << length << '+' << delta << "): " <<
               "): " << xstrerr(errNo));
    }
    buf = NULL;
    return !error;
}

// TODO: check MAP_NORESERVE, consider MAP_POPULATE and MAP_FIXED

