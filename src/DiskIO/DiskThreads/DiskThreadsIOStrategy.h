/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side Disk I/O functions. */

#ifndef __STORE_DISKTHREADEDIOSTRATEGY_H__
#define __STORE_DISKTHREADEDIOSTRATEGY_H__

#define _AIO_OPEN   0
#define _AIO_READ   1
#define _AIO_WRITE  2
#define _AIO_CLOSE  3
#define _AIO_UNLINK 4
#define _AIO_OPENDIR    5
#define _AIO_STAT   6
#include "DiskIO/DiskIOStrategy.h"

class DiskThreadsIOStrategy : public DiskIOStrategy
{

public:
    DiskThreadsIOStrategy();
    virtual bool shedLoad();
    virtual int load();
    virtual RefCount<DiskFile> newFile(char const *path);
    virtual bool unlinkdUseful() const;
    virtual void unlinkFile (char const *);
    virtual int callback();
    virtual void sync();
    virtual void init();
    void done();
    /* Todo: add access limitations */
    bool initialised;
    static DiskThreadsIOStrategy Instance;

private:
    static void aioStats(StoreEntry * sentry);
    void registerWithCacheManager(void);
};

#endif

