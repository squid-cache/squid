/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_DISKTHREADS_DISKTHREADSDISKIOMODULE_H
#define SQUID_SRC_DISKIO_DISKTHREADS_DISKTHREADSDISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class DiskThreadsDiskIOModule : public DiskIOModule
{

public:
    static DiskThreadsDiskIOModule &GetInstance();
    DiskThreadsDiskIOModule();
    void init() override;
    //virtual void registerWithCacheManager(void);
    void gracefulShutdown() override;
    char const *type () const override;
    DiskIOStrategy* createStrategy() override;

private:
    static DiskThreadsDiskIOModule Instance;
};

#endif /* SQUID_SRC_DISKIO_DISKTHREADS_DISKTHREADSDISKIOMODULE_H */

