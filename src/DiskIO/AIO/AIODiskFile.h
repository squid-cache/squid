/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AIODISKFILE_H
#define SQUID_AIODISKFILE_H

#if USE_DISKIO_AIO

#include "async_io.h"
#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "SquidString.h"

class AIODiskIOStrategy;

class AIODiskFile : public DiskFile
{

public:

    friend class AIODiskIOStrategy;
    AIODiskFile (char const *path, AIODiskIOStrategy *);
    ~AIODiskFile();

    /// \bug the code has this as "IORequestor::Pointer callback"
    virtual void open(int flags, mode_t mode, RefCount<IORequestor> callback);

    virtual void create (int, mode_t, RefCount<IORequestor>);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close ();
    virtual bool canRead() const;
    virtual bool canWrite() const;

    /* During migration only */
    virtual int getFD() const;

    virtual bool error() const;

    /* Inform callers if there is IO in progress */
    virtual bool ioInProgress() const;

private:
    void error(bool const &);
    int fd;
    String path;
    AIODiskIOStrategy *strategy;
    RefCount<IORequestor> ioRequestor;
    bool closed;
    bool error_;
    CBDATA_CLASS2(AIODiskFile);
};

#endif /* USE_DISKIO_AIO */
#endif /* SQUID_AIODISKFILE_H */

