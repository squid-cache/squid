/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 81    aio_xxx() POSIX emulation on Windows */

#include "squid.h"
#include "comm.h"
#include "DiskIO/AIO/aio_win32.h"
#include "fd.h"
#include "StatCounters.h"
#include "win32.h"

#include <cerrno>

#if _SQUID_WINDOWS_
VOID CALLBACK IoCompletionRoutine(DWORD dwErrorCode,
                                  DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped)
{

    struct aiocb *aiocbp = (struct aiocb *) lpOverlapped->hEvent;

    aiocbp->aio_sigevent.sigev_notify = dwErrorCode;
    aiocbp->aio_sigevent.sigev_signo = dwNumberOfBytesTransfered;
    debugs(81, 7, "AIO operation complete: errorcode=" << dwErrorCode << " nbytes=" << dwNumberOfBytesTransfered);
    xfree(lpOverlapped);
}

int aio_read(struct aiocb *aiocbp)
{
    LPOVERLAPPED Overlapped;
    BOOL IoOperationStatus;

    /* Allocate an overlapped structure. */
    Overlapped = (LPOVERLAPPED) xcalloc(1, sizeof(OVERLAPPED));

    if (!Overlapped) {
        errno = ENOMEM;
        return -1;
    }

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

    aiocbp->aio_sigevent.sigev_notify = EINPROGRESS;

    aiocbp->aio_sigevent.sigev_signo = -1;

    IoOperationStatus = ReadFileEx((HANDLE)_get_osfhandle(aiocbp->aio_fildes),
                                   aiocbp->aio_buf,
                                   aiocbp->aio_nbytes,
                                   Overlapped,
                                   IoCompletionRoutine);

    /* Test to see if the I/O was queued successfully. */
    if (!IoOperationStatus) {
        errno = GetLastError();
        debugs(81, DBG_IMPORTANT, "aio_read: GetLastError=" << errno  );
        return -1;
    }

    /* The I/O queued successfully. Go back into the
       alertable wait for I/O completion or for
       more I/O requests. */
    return 0;
}

int aio_read64(struct aiocb64 *aiocbp)
{
    LPOVERLAPPED Overlapped;
    BOOL IoOperationStatus;

    /* Allocate an overlapped structure. */
    Overlapped = (LPOVERLAPPED) xcalloc(1, sizeof(OVERLAPPED));

    if (!Overlapped) {
        errno = ENOMEM;
        return -1;
    }

#ifdef __GNUC__
    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000LL);

    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000LL);

#else

    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000);

    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000);

#endif

    Overlapped->hEvent = aiocbp;

    aiocbp->aio_sigevent.sigev_notify = EINPROGRESS;

    aiocbp->aio_sigevent.sigev_signo = -1;

    IoOperationStatus = ReadFileEx((HANDLE)_get_osfhandle(aiocbp->aio_fildes),
                                   aiocbp->aio_buf,
                                   aiocbp->aio_nbytes,
                                   Overlapped,
                                   IoCompletionRoutine);

    /* Test to see if the I/O was queued successfully. */
    if (!IoOperationStatus) {
        errno = GetLastError();
        debugs(81, DBG_IMPORTANT, "aio_read: GetLastError=" << errno  );
        return -1;
    }

    /* The I/O queued successfully. Go back into the
       alertable wait for I/O completion or for
       more I/O requests. */
    return 0;
}

int aio_write(struct aiocb *aiocbp)
{
    LPOVERLAPPED Overlapped;
    BOOL IoOperationStatus;

    /* Allocate an overlapped structure. */
    Overlapped = (LPOVERLAPPED) xcalloc(1, sizeof(OVERLAPPED));

    if (!Overlapped) {
        errno = ENOMEM;
        return -1;
    }

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

    aiocbp->aio_sigevent.sigev_notify = EINPROGRESS;

    aiocbp->aio_sigevent.sigev_signo = -1;

    IoOperationStatus = WriteFileEx((HANDLE)_get_osfhandle(aiocbp->aio_fildes),
                                    aiocbp->aio_buf,
                                    aiocbp->aio_nbytes,
                                    Overlapped,
                                    IoCompletionRoutine);

    /* Test to see if the I/O was queued successfully. */
    if (!IoOperationStatus) {
        errno = GetLastError();
        debugs(81, DBG_IMPORTANT, "aio_write: GetLastError=" << errno  );
        return -1;
    }

    /* The I/O queued successfully. Go back into the
       alertable wait for I/O completion or for
       more I/O requests. */
    return 0;
}

int aio_write64(struct aiocb64 *aiocbp)
{
    LPOVERLAPPED Overlapped;
    BOOL IoOperationStatus;

    /* Allocate an overlapped structure. */
    Overlapped = (LPOVERLAPPED) xcalloc(1, sizeof(OVERLAPPED));

    if (!Overlapped) {
        errno = ENOMEM;
        return -1;
    }

#ifdef __GNUC__
    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000LL);

    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000LL);

#else

    Overlapped->Offset = (DWORD) (aiocbp->aio_offset % 0x100000000);

    Overlapped->OffsetHigh = (DWORD) (aiocbp->aio_offset / 0x100000000);

#endif

    Overlapped->hEvent = aiocbp;

    aiocbp->aio_sigevent.sigev_notify = EINPROGRESS;

    aiocbp->aio_sigevent.sigev_signo = -1;

    IoOperationStatus = WriteFileEx((HANDLE)_get_osfhandle(aiocbp->aio_fildes),
                                    aiocbp->aio_buf,
                                    aiocbp->aio_nbytes,
                                    Overlapped,
                                    IoCompletionRoutine);

    /* Test to see if the I/O was queued successfully. */
    if (!IoOperationStatus) {
        errno = GetLastError();
        debugs(81, DBG_IMPORTANT, "aio_write: GetLastError=" << errno  );
        return -1;
    }

    /* The I/O queued successfully. Go back into the
       alertable wait for I/O completion or for
       more I/O requests. */
    return 0;
}

int aio_error(const struct aiocb * aiocbp)
{
    return aiocbp->aio_sigevent.sigev_notify;
}

int aio_error64(const struct aiocb64 * aiocbp)
{
    return aiocbp->aio_sigevent.sigev_notify;
}

int aio_open(const char *path, int mode)
{
    HANDLE hndl;
    DWORD dwCreationDisposition;
    DWORD dwDesiredAccess;
    int fd;

    if (mode & O_WRONLY)
        mode |= O_APPEND;

    mode |= O_BINARY;

    errno = 0;

    if (mode & O_WRONLY)
        dwDesiredAccess = GENERIC_WRITE;
    else
        dwDesiredAccess = (mode & O_RDONLY) ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE;

    if (mode & O_TRUNC)
        dwCreationDisposition = CREATE_ALWAYS;
    else
        dwCreationDisposition = (mode & O_CREAT) ? OPEN_ALWAYS : OPEN_EXISTING;

    if ((hndl = CreateFile(path,                    /* file name               */
                           dwDesiredAccess,         /* access mode             */
                           0,                       /* share mode              */
                           NULL,                    /* SD                      */
                           dwCreationDisposition,   /* how to create           */
                           FILE_FLAG_OVERLAPPED,    /* file attributes         */
                           NULL                     /* handle to template file */
                          )) != INVALID_HANDLE_VALUE) {
        ++ statCounter.syscalls.disk.opens;
        fd = _open_osfhandle((long) hndl, 0);
        commSetCloseOnExec(fd);
        fd_open(fd, FD_FILE, path);
    } else {
        errno = GetLastError();
        fd = DISK_ERROR;
    }

    return fd;
}

void aio_close(int fd)
{
    CloseHandle((HANDLE)_get_osfhandle(fd));
    fd_close(fd);
    ++ statCounter.syscalls.disk.closes;
}

ssize_t aio_return(struct aiocb * aiocbp)
{
    return aiocbp->aio_sigevent.sigev_signo;
}

ssize_t aio_return64(struct aiocb64 * aiocbp)

{
    return aiocbp->aio_sigevent.sigev_signo;
}
#endif /* _SQUID_WINDOWS_ */

