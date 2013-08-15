/*
 * AUTHOR: Adrian Chadd <adrian@squid-cache.org>
 * DEBUG: section 79   Disk IO Routines
 *
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

/**
 *
 \par
 * These routines are simple plugin replacements for the file_* routines
 * in disk.c . They back-end into the POSIX AIO routines to provide
 * a nice and simple async IO framework for COSS.
 *
 \par
 * AIO is suitable for COSS - the only sync operations that the standard
 * supports are read/write, and since COSS works on a single file
 * per storedir it should work just fine.
 */

#include "squid.h"
#include "AIODiskFile.h"
#include "AIODiskIOStrategy.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "disk.h"
#include "globals.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

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
AIODiskFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
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
        fatalf("Aiee! aio_read() returned error (%d)  FIXME and wrap file_read !\n", errno);
        debugs(79, DBG_IMPORTANT, "WARNING: aio_read() returned error: " << xstrerror());
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
        fatalf("Aiee! aio_write() returned error (%d) FIXME and wrap file_write !\n", errno);
        debugs(79, DBG_IMPORTANT, "WARNING: aio_write() returned error: " << xstrerror());
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
