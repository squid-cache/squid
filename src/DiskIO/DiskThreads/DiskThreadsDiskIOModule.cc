/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "DiskThreadsDiskIOModule.h"
#include "DiskThreadsIOStrategy.h"

DiskThreadsDiskIOModule DiskThreadsDiskIOModule::Instance;
DiskThreadsDiskIOModule &
DiskThreadsDiskIOModule::GetInstance()
{
    return Instance;
}

DiskThreadsDiskIOModule::DiskThreadsDiskIOModule()
{
    ModuleAdd(*this);
}

void
DiskThreadsDiskIOModule::init()
{
    DiskThreadsIOStrategy::Instance.init();
}

void
DiskThreadsDiskIOModule::gracefulShutdown()
{
    DiskThreadsIOStrategy::Instance.done();
}

DiskIOStrategy *
DiskThreadsDiskIOModule::createStrategy()
{
    return new SingletonIOStrategy(&DiskThreadsIOStrategy::Instance);
}

char const *
DiskThreadsDiskIOModule::type () const
{
    return "DiskThreads";
}

