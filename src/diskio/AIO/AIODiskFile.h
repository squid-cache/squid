/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_AIO_AIODISKFILE_H
#define SQUID_SRC_DISKIO_AIO_AIODISKFILE_H

#if USE_DISKIO_AIO

#include "cbdata.h"
#include "diskio/AIO/async_io.h"
#include "diskio/DiskFile.h"
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

#endif /* USE_DISKIO_AIO */
#endif /* SQUID_SRC_DISKIO_AIO_AIODISKFILE_H */
