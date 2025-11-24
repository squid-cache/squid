/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "comm.h"
#include "debug/Stream.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/OIO/File.h"
#include "DiskIO/OIO/Strategy.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fd.h"
#include "fs_io.h"
#include "globals.h"
#include "StatCounters.h"

#include <cerrno>

CBDATA_NAMESPACED_CLASS_INIT(DiskIO::OIO,File);

DiskIO::OIO::File::File(char const *aPath, Strategy *aStrategy)
{
    assert(aPath);
    path = aPath;
    strategy = aStrategy;
    debugs(79, 3, aPath);
}

void
DiskIO::OIO::File::open(int flags, mode_t, IORequestor::Pointer callback)
{
   if (flags & O_WRONLY)
        flags |= O_APPEND;

    flags |= O_BINARY;

    errno = 0;

    DWORD dwDesiredAccess;
    if (flags & O_WRONLY)
        dwDesiredAccess = GENERIC_WRITE;
    else
        dwDesiredAccess = (flags & O_RDONLY) ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE;

    DWORD dwCreationDisposition;
    if (flags & O_TRUNC)
        dwCreationDisposition = CREATE_ALWAYS;
    else
        dwCreationDisposition = (flags & O_CREAT) ? OPEN_ALWAYS : OPEN_EXISTING;

    auto hndl = CreateFile(path.termedBuf(), dwDesiredAccess, 0, nullptr, dwCreationDisposition, FILE_FLAG_OVERLAPPED, NULL);
    if (hndl != INVALID_HANDLE_VALUE) {
        ++ statCounter.syscalls.disk.opens;
        fd = _open_osfhandle(reinterpret_cast<intptr_t>(hndl), 0);
        commSetCloseOnExec(fd);
        fd_open(fd, FD_FILE, path.termedBuf());
        closed = false;
        ++store_open_disk_fd;
        debugs(79, 3, "opened FD " << fd);
    } else {
        fd = DISK_ERROR;
        auto xerrno = GetLastError();
        debugs(79, 3, "got failure: " << xstrerr(xerrno));
        error(true);
    }

    ioRequestor = callback;
    callback->ioCompletedNotification();
}

void
DiskIO::OIO::File::create(int flags, mode_t mode, IORequestor::Pointer callback)
{
    open(flags, mode, callback);
}

static VOID CALLBACK
IoCompletionRoutine(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped)
{
    auto *aiocbp = static_cast<struct aiocb *>(lpOverlapped->hEvent);

    aiocbp->aio_sigevent.sigev_notify = dwErrorCode;
    aiocbp->aio_sigevent.sigev_signo = dwNumberOfBytesTransfered;
    debugs(81, 7, "OIO operation complete: errorcode=" << dwErrorCode << " nbytes=" << dwNumberOfBytesTransfered);
    xfree(lpOverlapped);
}

static HANDLE
HandleFromFd(int fd)
{
    return reinterpret_cast<HANDLE>(_get_osfhandle(fd));
}

void
DiskIO::OIO::File::read(ReadRequest *request)
{
    assert(strategy->aq.aq_state == AQ_STATE_SETUP);

    /* Find a free slot */
    const auto slot = strategy->findSlot();
    if (slot < 0) {
        /* No free slot? Callback error, and return */
        debugs(79, DBG_IMPORTANT, "WARNING: out of aiocb slots!");
        fatal("Aiee! out of aiocb slots! - TODO fix and wrap file_read\n");
        /* fall back to blocking method */
        //        file_read(fd, request->buf, request->len, request->offset, callback, data);
        return;
    }

    /* Mark slot as ours */
    auto qe = &strategy->aq.aq_queue[slot];
    qe->aq_e_state = AQ_ENTRY_USED;
    qe->aq_e_callback_data = cbdataReference(request);
    qe->theFile = cbdataReference(this);
    qe->aq_e_type = AQ_ENTRY_READ;
    qe->aq_e_free = nullptr;
    qe->aq_e_buf = request->buf;
    qe->aq_e_fd = getFD();

    /* Account */
    ++ strategy->aq.aq_numpending;

    /* Initiate I/O */
    auto *aiocbp = &qe->aq_e_aiocb;
    aiocbp->aio_fildes = getFD();
    aiocbp->aio_nbytes = request->len;
    aiocbp->aio_offset = request->offset;
    aiocbp->aio_buf = request->buf;
    aiocbp->aio_sigevent.sigev_notify = EINPROGRESS;
    aiocbp->aio_sigevent.sigev_signo = -1;

    auto Overlapped = (LPOVERLAPPED) xcalloc(1, sizeof(OVERLAPPED));
#if _FILE_OFFSET_BITS==64
#ifdef __GNUC__
    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000LL);
    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000LL);
#else
    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000);
    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000);
#endif
#else
    Overlapped->Offset = aiocbp->aio_offset;
    Overlapped->OffsetHigh = 0;
#endif
    Overlapped->hEvent = aiocbp;

    if (!ReadFileEx(HandleFromFd(aiocbp->aio_fildes), aiocbp->aio_buf, aiocbp->aio_nbytes, Overlapped, IoCompletionRoutine))
        fatalf("Aiee! OIO ReadFileEx() returned error: %s\n", xstrerr(GetLastError()));
}

void
DiskIO::OIO::File::write(WriteRequest *request)
{
    assert(strategy->aq.aq_state == AQ_STATE_SETUP);

    /* Find a free slot */
    const auto slot = strategy->findSlot();
    if (slot < 0) {
        /* No free slot? Callback error, and return */
        debugs(79, DBG_IMPORTANT, "WARNING: out of oiocb slots!");
        fatal("Aiee! out of oiocb slots TODO fix and wrap file_write !\n");
        /* fall back to blocking method */
        //        file_write(fd, offset, buf, len, callback, data, freefunc);
        return;
    }

    /* Mark slot as ours */
    auto qe = &strategy->aq.aq_queue[slot];
    qe->aq_e_state = AQ_ENTRY_USED;
    qe->aq_e_callback_data = cbdataReference(request);
    qe->theFile = cbdataReference(this);
    qe->aq_e_type = AQ_ENTRY_WRITE;
    qe->aq_e_free = request->free_func;
    qe->aq_e_buf = const_cast<char *>(request->buf);
    qe->aq_e_fd = fd;

    /* Account */
    ++strategy->aq.aq_numpending;

    /* Initiate I/O */
    auto *aiocbp = &qe->aq_e_aiocb;
    aiocbp->aio_fildes = fd;
    aiocbp->aio_nbytes = request->len;
    aiocbp->aio_offset = request->offset;
    aiocbp->aio_buf = (void *)request->buf;
    aiocbp->aio_sigevent.sigev_notify = EINPROGRESS;
    aiocbp->aio_sigevent.sigev_signo = -1;

    auto Overlapped = static_cast<LPOVERLAPPED>(xcalloc(1, sizeof(OVERLAPPED)));
#if _FILE_OFFSET_BITS==64
#ifdef __GNUC__
    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000LL);
    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000LL);
#else
    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000);
    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000);
#endif
#else
    Overlapped->Offset = aiocbp->aio_offset;
    Overlapped->OffsetHigh = 0;
#endif
    Overlapped->hEvent = aiocbp;

    if (!WriteFileEx(HandleFromFd(aiocbp->aio_fildes), aiocbp->aio_buf, aiocbp->aio_nbytes, Overlapped, IoCompletionRoutine))
        fatalf("Aiee! OIO WriteFileEx() returned error: %s\n", xstrerr(GetLastError()));
}

void
DiskIO::OIO::File::close()
{
    assert(!closed);
    file_close(fd);

    fd = -1;
    closed = true;
    assert(ioRequestor);
    ioRequestor->closeCompleted();
}
