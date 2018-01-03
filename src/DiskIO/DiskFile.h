/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DISKFILE_H
#define SQUID_DISKFILE_H

#include "base/RefCount.h"
#include "SquidTime.h"

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
    virtual void configure(const Config &) {}

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

