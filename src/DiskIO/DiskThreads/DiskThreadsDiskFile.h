
/*
 * $Id: DiskThreadsDiskFile.h,v 1.2 2006/08/21 00:50:45 robertc Exp $
 *
 * DEBUG: section 79    Disk IO Routines
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

#ifndef SQUID_DISKTHREADSDISKFILE_H
#define SQUID_DISKTHREADSDISKFILE_H
#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskThreads.h"

class DiskThreadsDiskFile : public DiskFile
{

public:
    void * operator new (size_t);
    void operator delete (void *);
    DiskThreadsDiskFile (char const *path, DiskThreadsIOStrategy *);
    ~DiskThreadsDiskFile();
    virtual void open (int, mode_t, RefCount<IORequestor>);
    virtual void create (int, mode_t, RefCount<IORequestor>);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close ();
    virtual bool error() const;
    virtual int getFD() const { return fd;}

    virtual bool canRead() const;
    virtual bool canWrite() const;
    virtual bool ioInProgress()const;

private:
#if ASYNC_READ

    static AIOCB ReadDone;
#else

    static DRCB ReadDone;
#endif
#if ASYNC_WRITE

    static AIOCB WriteDone;
#else

    static DWCB WriteDone;
#endif

    int fd;
    bool errorOccured;
    char const *path_;
    DiskThreadsIOStrategy *IO;
    size_t inProgressIOs;
    static AIOCB OpenDone;
    void openDone(int fd, const char *buf, int aio_return, int aio_errno);
    RefCount<IORequestor> ioRequestor;
    CBDATA_CLASS(DiskThreadsDiskFile);
    void doClose();

    void readDone(int fd, const char *buf, int len, int errflag, RefCount<ReadRequest>);
    void writeDone (int fd, int errflag, size_t len, RefCount<WriteRequest>);
};

#include "DiskIO/ReadRequest.h"

template <class RT>

class IoResult
{

public:
    void * operator new (size_t);
    void operator delete (void *);
    IoResult(RefCount<DiskThreadsDiskFile> aFile, RefCount<RT> aRequest) : file(aFile), request(aRequest){}

    RefCount<DiskThreadsDiskFile> file;
    RefCount<RT> request;

private:
    CBDATA_CLASS(IoResult);
};

template <class RT>
IoResult<RT>
IOResult(RefCount<RT> aRequest, RefCount<DiskThreadsDiskFile> aFile) { return IoResult<RT>(aFile, aRequest);}

#endif /* SQUID_DISKTHREADSDISKFILE_H */
