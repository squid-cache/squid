/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_AIO_AIODISKIOSTRATEGY_H
#define SQUID_SRC_DISKIO_AIO_AIODISKIOSTRATEGY_H

#if HAVE_DISKIO_MODULE_AIO

#include "DiskIO/AIO/async_io.h"
#include "DiskIO/DiskIOStrategy.h"

class AIODiskIOStrategy : public DiskIOStrategy
{

public:
    AIODiskIOStrategy();
    ~AIODiskIOStrategy() override;

    bool shedLoad() override;
    /* What is the current load? 999 = 99.9% */
    int load() override;
    /* Return a handle for performing IO operations */
    RefCount<DiskFile> newFile (char const *path) override;
    /* flush all IO operations  */
    void sync() override;
    /** whether the IO Strategy can use unlinkd */
    bool unlinkdUseful() const override;
    /* unlink a file by path */
    void unlinkFile (char const *) override;

    /* perform any pending callbacks */
    int callback() override;

    /* Init per-instance logic */
    void init() override;

    /* cachemgr output on the IO instance stats */
    void statfs(StoreEntry & sentry)const override;
    /* module specific options */
    ConfigOption *getOptionTree() const override;
    /* a file descriptor */
    int fd;
    /* queue of requests */
    async_queue_t aq;

    int findSlot();
};

#endif /* HAVE_DISKIO_MODULE_AIO */
#endif /* SQUID_SRC_DISKIO_AIO_AIODISKIOSTRATEGY_H */

