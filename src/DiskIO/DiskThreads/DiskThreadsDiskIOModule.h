/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DISKTHREADSDISKIOMODULE_H
#define SQUID_DISKTHREADSDISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class DiskThreadsDiskIOModule : public DiskIOModule
{

public:
    static DiskThreadsDiskIOModule &GetInstance();
    DiskThreadsDiskIOModule();
    virtual void init();
    //virtual void registerWithCacheManager(void);
    virtual void gracefulShutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static DiskThreadsDiskIOModule Instance;
};

#endif /* SQUID_DISKTHREADSDISKIOMODULE_H */

