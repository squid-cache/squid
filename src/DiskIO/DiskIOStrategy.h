/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DISKIOSTRATEGY_H
#define SQUID_DISKIOSTRATEGY_H

#include "base/RefCount.h"
#include "Store.h"

class DiskFile;

class ConfigOption;

class DiskIOStrategy
{

public:
    virtual ~DiskIOStrategy() {}

    /** Can the IO Strategy handle more requests ? */
    virtual bool shedLoad() = 0;

    /** What is the current load? 999 = 99.9% */
    virtual int load() = 0;

    /** Return a handle for performing IO operations */
    virtual RefCount<DiskFile> newFile(char const *path) = 0;

    /** flush all IO operations  */
    virtual void sync() {}

    /** whether the IO Strategy can use unlinkd */
    virtual bool unlinkdUseful() const = 0;

    /** unlink a file by path */
    virtual void unlinkFile(char const *) = 0;

    /** perform any pending callbacks */
    virtual int callback() { return 0; }

    /** Init per-instance logic */
    virtual void init() {}

    /** cachemgr output on the IO instance stats */
    virtual void statfs(StoreEntry &) const {}

    /** module specific options */
    virtual ConfigOption *getOptionTree() const {return NULL;}
};

/* Because we need the DiskFile definition for newFile. */
#include "DiskFile.h"

class SingletonIOStrategy : public DiskIOStrategy
{

public:
    SingletonIOStrategy(DiskIOStrategy *anIO) : io(anIO) {}

    virtual bool shedLoad() { return io->shedLoad(); }

    virtual int load() { return io->load(); }

    virtual RefCount<DiskFile> newFile (char const *path) {return io->newFile(path); }

    virtual void sync() { io->sync(); }

    virtual bool unlinkdUseful() const { return io->unlinkdUseful(); }

    virtual void unlinkFile(char const *path) { io->unlinkFile(path); }

    virtual int callback() { return io->callback(); }

    virtual void init() { io->init(); }

    virtual void statfs(StoreEntry & sentry) const { io->statfs(sentry); }

    virtual ConfigOption *getOptionTree() const { return io->getOptionTree(); }

private:
    DiskIOStrategy *io;
};

#endif /* SQUID_DISKIOSTRATEGY_H */

