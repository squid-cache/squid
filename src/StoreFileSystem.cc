/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 92    Storage File System */

#include "squid.h"
#include "StoreFileSystem.h"

std::vector<StoreFileSystem*> *StoreFileSystem::_FileSystems = nullptr;

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

StoreFileSystem *
StoreFileSystem::FindByType(const char *type)
{
    for (const auto fs: FileSystems()) {
        if (strcasecmp(type, fs->type()) == 0)
            return fs;
    }
    return nullptr;
}

