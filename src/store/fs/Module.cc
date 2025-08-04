/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "store/fs/Module.h"
#include "store/fs/rock/RockStoreFileSystem.h"
#include "store/fs/ufs/StoreFSufs.h"
#include "store/fs/ufs/UFSSwapDir.h"

#if USE_STORE_FS_UFS
static Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir> *UfsInstance;
static Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir> *AufsInstance;
static Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir> *DiskdInstance;
#endif

#if USE_STORE_FS_ROCK
static Rock::StoreFileSystem *RockInstance = nullptr;
#endif

void Fs::Init()
{

#if USE_STORE_FS_UFS
    UfsInstance = new Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir>("Blocking", "ufs");
    AufsInstance = new Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir>("DiskThreads", "aufs");;
    DiskdInstance = new Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir>("DiskDaemon", "diskd");;
#endif

#if USE_STORE_FS_ROCK
    RockInstance = new Rock::StoreFileSystem();
#endif

}

