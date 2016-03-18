/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "BlockingDiskIOModule.h"
#include "BlockingIOStrategy.h"

BlockingDiskIOModule::BlockingDiskIOModule()
{
    ModuleAdd(*this);
}

BlockingDiskIOModule &
BlockingDiskIOModule::GetInstance()
{
    return Instance;
}

void
BlockingDiskIOModule::init()
{}

void
BlockingDiskIOModule::gracefulShutdown()
{}

DiskIOStrategy*
BlockingDiskIOModule::createStrategy()
{
    return new BlockingIOStrategy();
}

BlockingDiskIOModule BlockingDiskIOModule::Instance;

char const *
BlockingDiskIOModule::type () const
{
    return "Blocking";
}

