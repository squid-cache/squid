
/*
 * $Id: DiskdFile.cc,v 1.2 2004/12/21 17:28:29 robertc Exp $
 *
 * DEBUG: section 79    Squid-side DISKD I/O functions.
 * AUTHOR: Duane Wessels
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
 * CopyRight (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "DiskdFile.h"
#include "ConfigOption.h"
#include "diomsg.h"

#include "DiskdIOStrategy.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
CBDATA_CLASS_INIT(DiskdFile);

void *
DiskdFile::operator new (size_t)
{
    CBDATA_INIT_TYPE(DiskdFile);
    DiskdFile *result = cbdataAlloc(DiskdFile);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    debug (79,3)("diskdFile with base %p allocating\n", result);
    return result;
}

void
DiskdFile::operator delete (void *address)
{
    DiskdFile *t = static_cast<DiskdFile *>(address);
    debug (79,3)("diskdFile with base %p deleting\n",t);
    cbdataFree(t);
}

DiskdFile::DiskdFile (char const *aPath, DiskdIOStrategy *anIO) : errorOccured (false), IO(anIO),
        inProgressIOs (0)
{
    assert (aPath);
    debug (79,3)("DiskdFile::DiskdFile: %s\n", aPath);
    path_ = xstrdup (aPath);
    id = diskd_stats.sio_id++;
}

DiskdFile::~DiskdFile()
{
    assert (inProgressIOs == 0);
    safe_free (path_);
}

void
DiskdFile::open (int flags, mode_t aMode, IORequestor::Pointer callback)
{
    debug (79,3)("DiskdFile::open: %p opening for %p\n", this, callback.getRaw());
    assert (ioRequestor.getRaw() == NULL);
    ioRequestor = callback;
    assert (callback.getRaw());
    mode = flags;
    off_t shm_offset;
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

    diskd_stats.open.ops++;
}

void
DiskdFile::create (int flags, mode_t aMode, IORequestor::Pointer callback)
{
    debug (79,3)("DiskdFile::create: %p creating for %p\n", this, callback.getRaw());
    assert (ioRequestor.getRaw() == NULL);
    ioRequestor = callback;
    assert (callback.getRaw());
    mode = flags;
    off_t shm_offset;
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
        ioCompleted();
        errorOccured = true;
        //        IO->shm.put (shm_offset);
        debug(79, 1) ("storeDiskdSend CREATE: %s\n", xstrerror());
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.create.ops++;
}

void
DiskdFile::read(ReadRequest *aRead)
{
    assert (ioRequestor.getRaw() != NULL);
    off_t shm_offset;
    char *rbuf = (char *)IO->shm.get(&shm_offset);
    assert(rbuf);
    ioAway();
    int x = IO->send(_MQD_READ,
                     id,
                     this,
                     (int) aRead->len,
                     (int) aRead->offset,
                     shm_offset,
                     aRead);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        //        IO->shm.put (shm_offset);
        debug(79, 1) ("storeDiskdSend READ: %s\n", xstrerror());
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.read.ops++;
}

void
DiskdFile::close()
{
    debug (79,3)("DiskdFile::close: %p closing for %p\n", this, ioRequestor.getRaw());
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
        ioCompleted();
        errorOccured = true;
        debug(79, 1) ("storeDiskdSend CLOSE: %s\n", xstrerror());
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.close.ops++;
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
        debug (79,3)("DiskdFile::canNotifyClient: No ioRequestor to notify\n");
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
    statCounter.syscalls.disk.opens++;
    debug(79, 3) ("storeDiskdOpenDone: status %d\n", M->status);

    if (M->status < 0) {
        diskd_stats.open.fail++;
        errorOccured = true;
    } else {
        diskd_stats.open.success++;
    }

    ioCompleted();
    notifyClient();
}

void
DiskdFile::createDone(diomsg *M)
{
    statCounter.syscalls.disk.opens++;
    debug(79, 3) ("storeDiskdCreateDone: status %d\n", M->status);

    if (M->status < 0) {
        diskd_stats.create.fail++;
        errorOccured = true;
    } else {
        diskd_stats.create.success++;
    }

    ioCompleted();
    notifyClient();
}

void
DiskdFile::write(WriteRequest *aRequest)
{
    debugs(79, 3, "DiskdFile::write: this " << (void *)this << ", buf " << (void *)aRequest->buf << ", off " << aRequest->offset << ", len " << aRequest->len);
    off_t shm_offset;
    char *sbuf = (char *)IO->shm.get(&shm_offset);
    xmemcpy(sbuf, aRequest->buf, aRequest->len);

    if (aRequest->free_func)
        aRequest->free_func(const_cast<char *>(aRequest->buf));

    ioAway();

    int x = IO->send(_MQD_WRITE,
                     id,
                     this,
                     (int) aRequest->len,
                     (int) aRequest->offset,
                     shm_offset,
                     aRequest);

    if (x < 0) {
        ioCompleted()
        ;
        errorOccured = true;
        debug(79, 1) ("storeDiskdSend WRITE: %s\n", xstrerror());
        //        IO->shm.put (shm_offset);
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.write.ops++;
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
    statCounter.syscalls.disk.closes++;
    debug(79, 3) ("DiskdFile::closeDone: status %d\n", M->status);

    if (M->status < 0) {
        diskd_stats.close.fail++;
        errorOccured = true;
    } else {
        diskd_stats.close.success++;
    }

    ioCompleted();

    if (canNotifyClient())
        ioRequestor->closeCompleted();

    ioRequestor = NULL;
}

void
DiskdFile::readDone(diomsg * M)
{
    statCounter.syscalls.disk.reads++;
    debug(79, 3) ("DiskdFile::readDone: status %d\n", M->status);
    assert (M->requestor);
    ReadRequest::Pointer readRequest = dynamic_cast<ReadRequest *>(M->requestor);
    /* remove the free protection */
    readRequest->RefCountDereference();

    if (M->status < 0) {
        diskd_stats.read.fail++;
        ioCompleted();
        errorOccured = true;
        ioRequestor->readCompleted(NULL, -1, DISK_ERROR, readRequest);
        return;
    }

    diskd_stats.read.success++;

    ioCompleted();
    ioRequestor->readCompleted (IO->shm.buf + M->shm_offset,  M->status, DISK_OK, readRequest);
}

void
DiskdFile::writeDone(diomsg *M)
{
    statCounter.syscalls.disk.writes++;
    debug(79, 3) ("storeDiskdWriteDone: status %d\n", M->status);
    assert (M->requestor);
    WriteRequest::Pointer writeRequest = dynamic_cast<WriteRequest *>(M->requestor);
    /* remove the free protection */
    writeRequest->RefCountDereference();

    if (M->status < 0) {
        errorOccured = true;
        diskd_stats.write.fail++;
        ioCompleted();
        ioRequestor->writeCompleted (DISK_ERROR,0, writeRequest);
        return;
    }

    diskd_stats.write.success++;
    ioCompleted();
    ioRequestor->writeCompleted (DISK_OK,M->status, writeRequest);
}

bool
DiskdFile::ioInProgress()const
{
    return inProgressIOs != 0;
}
