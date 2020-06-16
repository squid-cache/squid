/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 92    Storage File System */

#include "squid.h"
#include "StoreFileSystem.h"

std::vector<StoreFileSystem*> *StoreFileSystem::_FileSystems = NULL;

void
StoreFileSystem::RegisterAllFsWithCacheManager(void)
{
    for (iterator i = GetFileSystems().begin(); i != GetFileSystems().end(); ++i)
        (*i)->registerWithCacheManager();
}

void
StoreFileSystem::SetupAllFs()
{
    for (iterator i = GetFileSystems().begin(); i != GetFileSystems().end(); ++i)
        /* Call the FS to set up capabilities and initialize the FS driver */
        (*i)->setup();
}

void
StoreFileSystem::FsAdd(StoreFileSystem &instance)
{
    iterator i = GetFileSystems().begin();

    while (i != GetFileSystems().end()) {
        assert(strcmp((*i)->type(), instance.type()) != 0);
        ++i;
    }

    GetFileSystems().push_back (&instance);
}

std::vector<StoreFileSystem *> const &
StoreFileSystem::FileSystems()
{
    return GetFileSystems();
}

std::vector<StoreFileSystem*> &
StoreFileSystem::GetFileSystems()
{
    if (!_FileSystems)
        _FileSystems = new std::vector<StoreFileSystem *>;

    return *_FileSystems;
}

/*
 * called when a graceful shutdown is to occur
 * of each fs module.
 */
void
StoreFileSystem::FreeAllFs()
{
    while (!GetFileSystems().empty()) {
        StoreFileSystem *fs = GetFileSystems().back();
        GetFileSystems().pop_back();
        fs->done();
    }
}

/* no filesystem is required to export statistics */
void
StoreFileSystem::registerWithCacheManager(void)
{}

