/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side DISKD I/O functions. */

#ifndef SQUID_SRC_DISKIO_DISKDAEMON_DISKDFILE_H
#define SQUID_SRC_DISKIO_DISKDAEMON_DISKDFILE_H

#include "cbdata.h"
#include "DiskIO/DiskFile.h"

class DiskdIOStrategy;

struct diomsg;

/**
 \ingroup diskd
 */
class DiskdFile : public DiskFile
{
    CBDATA_CLASS(DiskdFile);

public:
    DiskdFile(char const *path, DiskdIOStrategy *);
    ~DiskdFile() override;
    void open(int flags, mode_t aMode, RefCount<IORequestor> callback) override;
    void create(int flags, mode_t aMode, RefCount<IORequestor> callback) override;
    void read(ReadRequest *) override;
    void write(WriteRequest *) override;
    void close() override;
    bool error() const override;
    bool canRead() const override;
    bool ioInProgress() const override;

    /* Temporary */
    int getID() const {return id;}

    void completed(diomsg *);

private:
    int id;
    char const *path_;
    bool errorOccured;
    DiskdIOStrategy *IO;
    RefCount<IORequestor> ioRequestor;
    void openDone(diomsg *);
    void createDone (diomsg *);
    void readDone (diomsg *);
    void writeDone (diomsg *);
    void closeDone (diomsg *);
    int mode;
    void notifyClient();
    bool canNotifyClient() const;
    void ioAway();
    void ioCompleted();
    size_t inProgressIOs;
};

#endif /* SQUID_SRC_DISKIO_DISKDAEMON_DISKDFILE_H */

