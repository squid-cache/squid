
/*
 * $Id: BlockingFile.cc,v 1.2 2004/12/21 17:28:29 robertc Exp $
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Robert Collins
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

#include "BlockingFile.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"

CBDATA_CLASS_INIT(BlockingFile);
void *
BlockingFile::operator new (size_t)
{
    CBDATA_INIT_TYPE(BlockingFile);
    BlockingFile *result = cbdataAlloc(BlockingFile);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    return result;
}

void
BlockingFile::operator delete (void *address)
{
    BlockingFile *t = static_cast<BlockingFile *>(address);
    cbdataFree(t);
}

BlockingFile::BlockingFile (char const *aPath) : fd (-1), closed (true), error_(false)
{
    assert (aPath);
    debug (79,3)("BlockingFile::BlockingFile: %s\n", aPath);
    path_ = xstrdup (aPath);
}

BlockingFile::~BlockingFile()
{
    safe_free (path_);
    doClose();
}

void
BlockingFile::open (int flags, mode_t mode, IORequestor::Pointer callback)
{
    /* Simulate async calls */
    fd = file_open(path_ , flags);
    ioRequestor = callback;

    if (fd < 0) {
        debug(79, 3) ("BlockingFile::open: got failure (%d)\n", errno);
        error(true);
    } else {
        closed = false;
        store_open_disk_fd++;
        debug(79, 3) ("BlockingFile::open: opened FD %d\n", fd);
    }

    callback->ioCompletedNotification();
}

void
BlockingFile::create (int flags, mode_t mode, IORequestor::Pointer callback)
{
    /* We use the same logic path for open */
    open(flags, mode, callback);
}


void BlockingFile::doClose()
{
    if (fd > -1) {
        closed = true;
        file_close(fd);
        store_open_disk_fd--;
        fd = -1;
    }
}

void
BlockingFile::close ()
{
    debug (79,3)("BlockingFile::close: %p closing for %p\n", this, ioRequestor.getRaw());
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
    debug(79, 3) ("storeUfsWrite: FD %d\n",fd);
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
BlockingFile::ioInProgress()const
{
    /* IO is never pending with UFS */
    return false;
}

/*  === STATIC =========================================================== */

void
BlockingFile::readDone(int rvfd, const char *buf, int len, int errflag)
{
    debug (79,3)("BlockingFile::readDone: FD %d\n",rvfd);
    assert (fd == rvfd);

    ssize_t rlen;

    if (errflag) {
        debug(79, 3) ("BlockingFile::readDone: got failure (%d)\n", errflag);
        rlen = -1;
    } else {
        rlen = (ssize_t) len;
    }

    if (errflag == DISK_EOF)
        errflag = DISK_OK;	/* EOF is signalled by len == 0, not errors... */

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
    debug(79, 3) ("storeUfsWriteDone: FD %d, len %ld\n",
                  fd, (long int) len);

    WriteRequest::Pointer result = writeRequest;
    writeRequest = NULL;

    if (errflag) {
        debug(79, 0) ("storeUfsWriteDone: got failure (%d)\n", errflag);
        doClose();
        ioRequestor->writeCompleted (DISK_ERROR,0, result);
        return;
    }

    ioRequestor->writeCompleted(DISK_OK, len, result);
}

