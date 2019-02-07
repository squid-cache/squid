/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MmappedDiskIOModule.h"
#include "MmappedIOStrategy.h"

MmappedDiskIOModule::MmappedDiskIOModule()
{
    ModuleAdd(*this);
}

MmappedDiskIOModule &
MmappedDiskIOModule::GetInstance()
{
    return Instance;
}

void
MmappedDiskIOModule::init()
{}

void
MmappedDiskIOModule::gracefulShutdown()
{}

DiskIOStrategy*
MmappedDiskIOModule::createStrategy()
{
    return new MmappedIOStrategy();
}

MmappedDiskIOModule MmappedDiskIOModule::Instance;

char const *
MmappedDiskIOModule::type () const
{
    return "Mmapped";
}

