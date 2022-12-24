/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
    virtual ~AIODiskIOStrategy();

    virtual bool shedLoad();
    /* What is the current load? 999 = 99.9% */
    virtual int load();
    /* Return a handle for performing IO operations */
    virtual RefCount<DiskFile> newFile (char const *path);
    /* flush all IO operations  */
    virtual void sync();
    /** whether the IO Strategy can use unlinkd */
    virtual bool unlinkdUseful() const;
    /* unlink a file by path */
    virtual void unlinkFile (char const *);

    /* perform any pending callbacks */
    virtual int callback();

    /* Init per-instance logic */
    virtual void init();

    /* cachemgr output on the IO instance stats */
    virtual void statfs(StoreEntry & sentry)const;
    /* module specific options */
    virtual ConfigOption *getOptionTree() const;
    /* a file descriptor */
    int fd;
    /* queue of requests */
    async_queue_t aq;

    int findSlot();
};

#endif /* HAVE_DISKIO_MODULE_AIO */
#endif /* SQUID_SRC_DISKIO_AIO_AIODISKIOSTRATEGY_H */

