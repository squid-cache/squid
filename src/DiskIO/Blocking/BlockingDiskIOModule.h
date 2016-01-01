/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BLOCKINGDISKIOMODULE_H
#define SQUID_BLOCKINGDISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class BlockingDiskIOModule : public DiskIOModule
{

public:
    static BlockingDiskIOModule &GetInstance();
    BlockingDiskIOModule();
    virtual void init();
    virtual void gracefulShutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static BlockingDiskIOModule Instance;
};

#endif /* SQUID_BLOCKINGDISKIOMODULE_H */

