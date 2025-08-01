/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 92    Storage File System */

#include "squid.h"
#include "DiskIOModule.h"
#if USE_DISKIO
#include "diskio/AIO/AIODiskIOModule.h"
#include "diskio/Blocking/BlockingDiskIOModule.h"
#include "diskio/DiskDaemon/DiskDaemonDiskIOModule.h"
#include "diskio/DiskThreads/DiskThreadsDiskIOModule.h"
#include "diskio/IpcIo/IpcIoDiskIOModule.h"
#include "diskio/Mmapped/MmappedDiskIOModule.h"
#endif

std::vector<DiskIOModule*> *DiskIOModule::_Modules = nullptr;

//DiskIOModule() : initialised (false) {}

DiskIOModule::DiskIOModule()
{
    /** We cannot call ModuleAdd(*this)
     * here as the virtual methods are not yet available.
     * We leave that to SetupAllModules() later.
     */
}

void
DiskIOModule::SetupAllModules()
{
#if USE_DISKIO_AIO
    AIODiskIOModule::GetInstance();
#endif /* USE_DISKIO_AIO */

#if USE_DISKIO_BLOCKING
    BlockingDiskIOModule::GetInstance();
#endif /* USE_DISKIO_BLOCKING */

#if USE_DISKIO_DISKDAEMON
    DiskDaemonDiskIOModule::GetInstance();
#endif /* USE_DISKIO_DISKDAEMON */

#if USE_DISKIO_DISKTHREADS
    DiskThreadsDiskIOModule::GetInstance();
#endif /* USE_DISKIO_DISKTHREADS */

#if USE_DISKIO_IPCIO
    IpcIoDiskIOModule::GetInstance();
#endif /* USE_DISKIO_IPCIO */

#if USE_DISKIO_MMAPPED
    MmappedDiskIOModule::GetInstance();
#endif /* USE_DISKIO_MMAPPED */

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

    return nullptr;
}

DiskIOModule *
DiskIOModule::FindDefault()
{
    /** Best IO options are in order: */
    DiskIOModule * result;
    result = Find("DiskThreads");
    if (nullptr == result)
        result = Find("DiskDaemon");
    if (nullptr == result)
        result = Find("AIO");
    if (nullptr == result)
        result = Find("Blocking");
    return result;
}

