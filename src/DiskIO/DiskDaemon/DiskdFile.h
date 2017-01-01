/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side DISKD I/O functions. */

#ifndef __STORE_DISKDFILE_H__
#define __STORE_DISKDFILE_H__

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
    ~DiskdFile();
    virtual void open(int flags, mode_t aMode, RefCount<IORequestor> callback);
    virtual void create(int flags, mode_t aMode, RefCount<IORequestor> callback);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close();
    virtual bool error() const;
    virtual bool canRead() const;
    virtual bool ioInProgress() const;

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

#endif

