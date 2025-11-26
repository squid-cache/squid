/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "DiskIO/OIO/Module.h"
#include "DiskIO/OIO/Strategy.h"
#include "Store.h"

DiskIO::OIO::Module::Module()
{
    ModuleAdd(*this);
}

DiskIO::OIO::Module &
DiskIO::OIO::Module::GetInstance()
{
    static Module *Instance = new Module();
    return *Instance;
}

DiskIOStrategy *
DiskIO::OIO::Module::createStrategy()
{
    return new Strategy();
}
