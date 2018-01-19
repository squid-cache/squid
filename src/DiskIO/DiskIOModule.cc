/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 92    Storage File System */

#include "squid.h"
#include "DiskIOModule.h"

std::vector<DiskIOModule*> *DiskIOModule::_Modules = NULL;

//DiskIOModule() : initialised (false) {}

DiskIOModule::DiskIOModule()
{
    /** We cannot call ModuleAdd(*this)
     * here as the virtual methods are not yet available.
     * We leave that to PokeAllModules() later.
     */
}

void
DiskIOModule::SetupAllModules()
{
    DiskIOModule::PokeAllModules();

    for (iterator i = GetModules().begin(); i != GetModules().end(); ++i)
        /* Call the FS to set up capabilities and initialize the FS driver */
        (*i)->init();
}

void
DiskIOModule::ModuleAdd(DiskIOModule &instance)
{
    iterator i = GetModules().begin();

    while (i != GetModules().end()) {
        assert(strcmp((*i)->type(), instance.type()) != 0);
        ++i;
    }

    GetModules().push_back (&instance);
}

std::vector<DiskIOModule *> const &
DiskIOModule::Modules()
{
    return GetModules();
}

std::vector<DiskIOModule*> &
DiskIOModule::GetModules()
{
    if (!_Modules)
        _Modules = new std::vector<DiskIOModule *>;

    return *_Modules;
}

/**
 * Called when a graceful shutdown is to occur
 * of each fs module.
 */
void
DiskIOModule::FreeAllModules()
{
    while (!GetModules().empty()) {
        DiskIOModule *fs = GetModules().back();
        GetModules().pop_back();
        fs->gracefulShutdown();
    }
}

DiskIOModule *
DiskIOModule::Find(char const *type)
{
    for (iterator i = GetModules().begin(); i != GetModules().end(); ++i)
        if (strcasecmp(type, (*i)->type()) == 0)
            return *i;

    return NULL;
}

DiskIOModule *
DiskIOModule::FindDefault()
{
    /** Best IO options are in order: */
    DiskIOModule * result;
    result = Find("DiskThreads");
    if (NULL == result)
        result = Find("DiskDaemon");
    if (NULL == result)
        result = Find("AIO");
    if (NULL == result)
        result = Find("Blocking");
    return result;
}

