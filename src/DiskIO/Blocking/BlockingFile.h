/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#ifndef SQUID_BLOCKINGFILE_H
#define SQUID_BLOCKINGFILE_H

#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "typedefs.h" //DRCB, DWCB

class BlockingFile : public DiskFile
{
    CBDATA_CLASS(BlockingFile);

public:
    BlockingFile(char const *path);
    ~BlockingFile() override;
    void open(int flags, mode_t mode, RefCount<IORequestor> callback) override;
    void create(int flags, mode_t mode, RefCount<IORequestor> callback) override;
    void read(ReadRequest *) override;
    void write(WriteRequest *) override;
    void close() override;
    bool error() const override;
    int getFD() const override { return fd;}

    bool canRead() const override;
    bool ioInProgress() const override;

private:
    static DRCB ReadDone;
    static DWCB WriteDone;
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

