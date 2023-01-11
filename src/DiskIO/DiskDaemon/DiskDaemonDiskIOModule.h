/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DISKDAEMONDISKIOMODULE_H
#define SQUID_DISKDAEMONDISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class DiskDaemonDiskIOModule : public DiskIOModule
{

public:
    static DiskDaemonDiskIOModule &GetInstance();
    DiskDaemonDiskIOModule();
    virtual void init();
    virtual void gracefulShutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static DiskDaemonDiskIOModule Instance;
    bool initialised;
    void registerWithCacheManager(void);
};

#endif /* SQUID_DISKDAEMONDISKIOMODULE_H */

