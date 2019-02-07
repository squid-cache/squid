/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

/**
 * \par
 * These routines are simple plugin replacements for the file_* routines
 * in disk.c . They back-end into the POSIX AIO routines to provide
 * a nice and simple async IO framework for COSS.
 *
 * \par
 * AIO is suitable for COSS - the only sync operations that the standard
 * supports are read/write, and since COSS works on a single file
 * per storedir it should work just fine.
 */

#include "squid.h"
#include "Debug.h"
#include "DiskIO/AIO/AIODiskFile.h"
#include "DiskIO/AIO/AIODiskIOStrategy.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs_io.h"
#include "globals.h"

#include <cerrno>

CBDATA_CLASS_INIT(AIODiskFile);

AIODiskFile::AIODiskFile(char const *aPath, AIODiskIOStrategy *aStrategy) : fd(-1), closed(true), error_(false)
{
    assert (aPath);
    path = aPath;
    strategy = aStrategy;
    debugs(79, 3, "AIODiskFile::AIODiskFile: " << aPath);
}

AIODiskFile::~AIODiskFile()
{}

void
AIODiskFile::error(bool const &aBool)
{
    error_ = aBool;
}

void
AIODiskFile::open(int flags, mode_t, RefCount<IORequestor> callback)
{
    /* Simulate async calls */
#if _SQUID_WINDOWS_
    fd = aio_open(path.termedBuf(), flags);
#else
    fd = file_open(path.termedBuf() , flags);
#endif

    ioRequestor = callback;

    if (fd < 0) {
        debugs(79, 3, HERE << ": got failure (" << errno << ")");
        error(true);
    } else {
        closed = false;
        ++store_open_disk_fd;
        debugs(79, 3, HERE << ": opened FD " << fd);
    }

    callback->ioCompletedNotification();
}

void
AIODiskFile::create(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    /* We use the same logic path for open */
    open(flags, mode, callback);
}

void
AIODiskFile::read(ReadRequest *request)
{
    int slot;
    async_queue_entry_t *qe;

    assert(strategy->aq.aq_state == AQ_STATE_SETUP);

    /* Find a free slot */
    slot = strategy->findSlot();

    if (slot < 0) {
        /* No free slot? Callback error, and return */
        fatal("Aiee! out of aiocb slots! - FIXME and wrap file_read\n");
        debugs(79, DBG_IMPORTANT, "WARNING: out of aiocb slots!");
        /* fall back to blocking method */
        //        file_read(fd, request->buf, request->len, request->offset, callback, data);
        return;
    }

    /* Mark slot as ours */
    qe = &strategy->aq.aq_queue[slot];

    qe->aq_e_state = AQ_ENTRY_USED;

    qe->aq_e_callback_data = cbdataReference(request);

    qe->theFile = cbdataReference(this);

    qe->aq_e_type = AQ_ENTRY_READ;

    qe->aq_e_free = NULL;

    qe->aq_e_buf =  request->buf;

    qe->aq_e_fd = getFD();

    qe->aq_e_aiocb.aio_fildes = getFD();

    qe->aq_e_aiocb.aio_nbytes = request->len;

    qe->aq_e_aiocb.aio_offset =  request->offset;

    qe->aq_e_aiocb.aio_buf =  request->buf;

    /* Account */
    ++ strategy->aq.aq_numpending;

    /* Initiate aio */
    if (aio_read(&qe->aq_e_aiocb) < 0) {
        int xerrno = errno;
        fatalf("Aiee! aio_read() returned error (%d)  FIXME and wrap file_read !\n", xerrno);
        debugs(79, DBG_IMPORTANT, "WARNING: aio_read() returned error: " << xstrerr(xerrno));
        /* fall back to blocking method */
        //        file_read(fd, request->buf, request->len, request->offset, callback, data);
    }

}

void
AIODiskFile::write(WriteRequest *request)
{
    int slot;
    async_queue_entry_t *qe;

    assert(strategy->aq.aq_state == AQ_STATE_SETUP);

    /* Find a free slot */
    slot = strategy->findSlot();

    if (slot < 0) {
        /* No free slot? Callback error, and return */
        fatal("Aiee! out of aiocb slots FIXME and wrap file_write !\n");
        debugs(79, DBG_IMPORTANT, "WARNING: out of aiocb slots!");
        /* fall back to blocking method */
        //        file_write(fd, offset, buf, len, callback, data, freefunc);
        return;
    }

    /* Mark slot as ours */
    qe = &strategy->aq.aq_queue[slot];

    qe->aq_e_state = AQ_ENTRY_USED;

    qe->aq_e_callback_data = cbdataReference(request);

    qe->theFile = cbdataReference(this);

    qe->aq_e_type = AQ_ENTRY_WRITE;

    qe->aq_e_free = request->free_func;

    qe->aq_e_buf = (void *)request->buf;

    qe->aq_e_fd = fd;

    qe->aq_e_aiocb.aio_fildes = fd;

    qe->aq_e_aiocb.aio_nbytes = request->len;

    qe->aq_e_aiocb.aio_offset = request->offset;

    qe->aq_e_aiocb.aio_buf = (void *)request->buf;

    /* Account */
    ++strategy->aq.aq_numpending;

    /* Initiate aio */
    if (aio_write(&qe->aq_e_aiocb) < 0) {
        int xerrno = errno;
        fatalf("Aiee! aio_write() returned error (%d) FIXME and wrap file_write !\n", xerrno);
        debugs(79, DBG_IMPORTANT, "WARNING: aio_write() returned error: " << xstrerr(xerrno));
        /* fall back to blocking method */
        //       file_write(fd, offset, buf, len, callback, data, freefunc);
    }
}

void
AIODiskFile::close ()
{
    assert (!closed);
#if _SQUID_WINDOWS_
    aio_close(fd);
#else
    file_close(fd);
#endif

    fd = -1;
    closed = true;
    assert (ioRequestor != NULL);
    ioRequestor->closeCompleted();
}

bool
AIODiskFile::canRead() const
{
    return true;
}

bool
AIODiskFile::canWrite() const
{
    return true;
}

int
AIODiskFile::getFD() const
{
    return fd;
}

bool
AIODiskFile::error() const
{
    return error_;
}

bool
AIODiskFile::ioInProgress() const
{
    return false;
}

