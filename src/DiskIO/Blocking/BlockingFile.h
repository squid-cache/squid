/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

class BlockingFile : public DiskFile
{

public:
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

    CBDATA_CLASS2(BlockingFile);
};

#endif /* SQUID_BLOCKINGFILE_H */

