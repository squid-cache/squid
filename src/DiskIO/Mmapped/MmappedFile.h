/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_MMAPPED_MMAPPEDFILE_H
#define SQUID_SRC_DISKIO_MMAPPED_MMAPPEDFILE_H

#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"

class MmappedFile : public DiskFile
{
    CBDATA_CLASS(MmappedFile);

public:
    MmappedFile(char const *path);
    ~MmappedFile() override;
    void open(int flags, mode_t mode, RefCount<IORequestor> callback) override;
    void create(int flags, mode_t mode, RefCount<IORequestor> callback) override;
    void read(ReadRequest *) override;
    void write(WriteRequest *) override;
    void close() override;
    bool error() const override;
    int getFD() const override { return fd;}

    bool canRead() const override;
    bool canWrite() const override;
    bool ioInProgress() const override;

private:
    char const *path_;
    RefCount<IORequestor> ioRequestor;
    //RefCount<ReadRequest> readRequest;
    //RefCount<WriteRequest> writeRequest;
    int fd;

    // mmapped memory leads to SEGV and bus errors if it maps beyond file
    int64_t minOffset; ///< enforced if not negative (to preserve file headers)
    int64_t maxOffset; ///< enforced if not negative (to avoid crashes)

    bool error_;

    void doClose();
};

#endif /* SQUID_SRC_DISKIO_MMAPPED_MMAPPEDFILE_H */

