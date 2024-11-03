/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 92    Storage File System */

#include "squid.h"
#include "fs/rock/RockStoreFileSystem.h"
#include "fs/rock/RockSwapDir.h"

Rock::StoreFileSystem::StoreFileSystem()
{
    FsAdd(*this);
}

Rock::StoreFileSystem::~StoreFileSystem()
{
}

char const *
Rock::StoreFileSystem::type() const
{
    return "rock";
}

SwapDir *
Rock::StoreFileSystem::createSwapDir()
{
    return new SwapDir();
}

