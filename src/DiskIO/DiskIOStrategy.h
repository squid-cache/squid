/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    virtual ConfigOption *getOptionTree() const {return nullptr;}
};

/* Because we need the DiskFile definition for newFile. */
#include "DiskFile.h"

class SingletonIOStrategy : public DiskIOStrategy
{

public:
    SingletonIOStrategy(DiskIOStrategy *anIO) : io(anIO) {}

    bool shedLoad() override { return io->shedLoad(); }

    int load() override { return io->load(); }

    RefCount<DiskFile> newFile (char const *path) override {return io->newFile(path); }

    void sync() override { io->sync(); }

    bool unlinkdUseful() const override { return io->unlinkdUseful(); }

    void unlinkFile(char const *path) override { io->unlinkFile(path); }

    int callback() override { return io->callback(); }

    void init() override { io->init(); }

    void statfs(StoreEntry & sentry) const override { io->statfs(sentry); }

    ConfigOption *getOptionTree() const override { return io->getOptionTree(); }

private:
    DiskIOStrategy *io;
};

#endif /* SQUID_DISKIOSTRATEGY_H */

