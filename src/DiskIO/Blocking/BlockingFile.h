/*
 * $Id$
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

#ifndef SQUID_BLOCKINGFILE_H
#define SQUID_BLOCKINGFILE_H

#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"

class BlockingFile : public DiskFile
{

public:
    void *operator new(size_t);
    void operator delete(void *);
    BlockingFile(char const *path);
    ~BlockingFile();
    virtual void open(int flags, mode_t mode, RefCount<IORequestor> callback);
    virtual void create(int flags, mode_t mode, RefCount<IORequestor> callback);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close();
    virtual bool error() const;
    virtual int getFD() const { return fd;}

    virtual bool canRead() const;
    virtual bool ioInProgress() const;

private:
    static DRCB ReadDone;
    static DWCB WriteDone;
    CBDATA_CLASS(BlockingFile);
    int fd;
    bool closed;
    void error (bool const &);
    bool error_;
    char const *path_;
    RefCount<IORequestor> ioRequestor;
    RefCount<ReadRequest> readRequest;
    RefCount<WriteRequest> writeRequest;
    void doClose();
    void readDone(int fd, const char *buf, int len, int errflag);
    void writeDone(int fd, int errflag, size_t len);
};

#endif /* SQUID_BLOCKINGFILE_H */
