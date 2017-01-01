/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AIODiskIOModule.h"
#include "AIODiskIOStrategy.h"
#include "Store.h"

AIODiskIOModule::AIODiskIOModule()
{
    ModuleAdd(*this);
}

AIODiskIOModule &
AIODiskIOModule::GetInstance()
{
    return Instance;
}

void
AIODiskIOModule::init()
{}

void
AIODiskIOModule::gracefulShutdown()
{}

DiskIOStrategy *
AIODiskIOModule::createStrategy()
{
    return new AIODiskIOStrategy();
}

AIODiskIOModule AIODiskIOModule::Instance;

char const *
AIODiskIOModule::type () const
{
    return "AIO";
}

