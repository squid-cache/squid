/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AIODISKFILE_H
#define SQUID_AIODISKFILE_H

#if HAVE_DISKIO_MODULE_AIO

#include "cbdata.h"
#include "DiskIO/AIO/async_io.h"
#include "DiskIO/DiskFile.h"
#include "SquidString.h"

class AIODiskIOStrategy;

class AIODiskFile : public DiskFile
{
    CBDATA_CLASS(AIODiskFile);

public:

    friend class AIODiskIOStrategy;
    AIODiskFile (char const *path, AIODiskIOStrategy *);
    ~AIODiskFile() override;

    // XXX: the code has this as "IORequestor::Pointer callback"
    void open(int flags, mode_t mode, RefCount<IORequestor> callback) override;

    void create (int, mode_t, RefCount<IORequestor>) override;
    void read(ReadRequest *) override;
    void write(WriteRequest *) override;
    void close () override;
    bool canRead() const override;
    bool canWrite() const override;

    /* During migration only */
    int getFD() const override;

    bool error() const override;

    /* Inform callers if there is IO in progress */
    bool ioInProgress() const override;

private:
    void error(bool const &);
    int fd;
    String path;
    AIODiskIOStrategy *strategy;
    RefCount<IORequestor> ioRequestor;
    bool closed;
    bool error_;
};

#endif /* HAVE_DISKIO_MODULE_AIO */
#endif /* SQUID_AIODISKFILE_H */

