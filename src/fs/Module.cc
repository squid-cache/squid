/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Module.h"
#if defined(HAVE_FS_UFS) || defined(HAVE_FS_AUFS) || defined(HAVE_FS_DISKD)
#include "fs/ufs/StoreFSufs.h"
#include "fs/ufs/UFSSwapDir.h"
#endif

#if HAVE_FS_UFS
static Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir> *UfsInstance;
#endif

#if HAVE_FS_AUFS
static Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir> *AufsInstance;
#endif

#if HAVE_FS_DISKD
static Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir> *DiskdInstance;
#endif

#if HAVE_FS_ROCK
#include "fs/rock/RockStoreFileSystem.h"
static Rock::StoreFileSystem *RockInstance = NULL;
#endif

void Fs::Init()
{

#if HAVE_FS_UFS
    UfsInstance = new Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir>("Blocking", "ufs");
#endif

#if HAVE_FS_AUFS
    AufsInstance = new Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir>("DiskThreads", "aufs");;
#endif

#if HAVE_FS_DISKD
    DiskdInstance = new Fs::Ufs::StoreFSufs<Fs::Ufs::UFSSwapDir>("DiskDaemon", "diskd");;
#endif

#if HAVE_FS_ROCK
    RockInstance = new Rock::StoreFileSystem();
#endif

}

void Fs::Clean()
{
#if HAVE_FS_UFS
    delete UfsInstance;
#endif

#if HAVE_FS_AUFS
    delete AufsInstance;
#endif

#if HAVE_FS_DISKD
    delete DiskdInstance;
#endif

#if HAVE_FS_ROCK
    delete RockInstance;
#endif

}

