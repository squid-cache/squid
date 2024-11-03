/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side Disk I/O functions. */

#ifndef SQUID_SRC_DISKIO_DISKTHREADS_DISKTHREADSIOSTRATEGY_H
#define SQUID_SRC_DISKIO_DISKTHREADS_DISKTHREADSIOSTRATEGY_H

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
    bool shedLoad() override;
    int load() override;
    RefCount<DiskFile> newFile(char const *path) override;
    bool unlinkdUseful() const override;
    void unlinkFile (char const *) override;
    int callback() override;
    void sync() override;
    void init() override;
    void done();
    /* Todo: add access limitations */
    bool initialised;
    static DiskThreadsIOStrategy Instance;

private:
    static void aioStats(StoreEntry * sentry);
    void registerWithCacheManager(void);
};

#endif /* SQUID_SRC_DISKIO_DISKTHREADS_DISKTHREADSIOSTRATEGY_H */

