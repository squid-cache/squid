/*
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
 * Copyright (c) 2003 Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_DISKFILE_H
#define SQUID_DISKFILE_H

#include "base/RefCount.h"
#include "typedefs.h"

class IORequestor;

class ReadRequest;

class WriteRequest;

class DiskFile : public RefCountable
{

public:

    /// generally useful configuration options supported by some children
    class Config
    {
    public:
        Config(): ioTimeout(0), ioRate(-1) {}

        /// canRead/Write should return false if expected I/O delay exceeds it
        time_msec_t ioTimeout; // not enforced if zero, which is the default

        /// shape I/O request stream to approach that many per second
        int ioRate; // not enforced if negative, which is the default
    };

    typedef RefCount<DiskFile> Pointer;

    /// notes supported configuration options; kids must call this first
    virtual void configure(const Config &cfg) {}

    virtual void open(int flags, mode_t mode, RefCount<IORequestor> callback) = 0;
    virtual void create(int flags, mode_t mode, RefCount<IORequestor> callback) = 0;
    virtual void read(ReadRequest *) = 0;
    virtual void write(WriteRequest *) = 0;
    virtual void close() = 0;
    virtual bool canRead() const = 0;
    virtual bool canWrite() const {return true;}

    /** During migration only */
    virtual int getFD() const {return -1;}

    virtual bool error() const = 0;

    /** Inform callers if there is IO in progress */
    virtual bool ioInProgress() const = 0;
};

#endif /* SQUID_DISKFILE_H */
