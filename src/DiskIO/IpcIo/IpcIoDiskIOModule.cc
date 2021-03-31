/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "IpcIoDiskIOModule.h"
#include "IpcIoIOStrategy.h"

IpcIoDiskIOModule::IpcIoDiskIOModule()
{
    ModuleAdd(*this);
}

IpcIoDiskIOModule &
IpcIoDiskIOModule::GetInstance()
{
    return Instance;
}

void
IpcIoDiskIOModule::init()
{}

void
IpcIoDiskIOModule::gracefulShutdown()
{}

DiskIOStrategy*
IpcIoDiskIOModule::createStrategy()
{
    return new IpcIoIOStrategy();
}

IpcIoDiskIOModule IpcIoDiskIOModule::Instance;

char const *
IpcIoDiskIOModule::type () const
{
    return "IpcIo";
}

