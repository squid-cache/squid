/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FS_UFS_STOREFSUFS_H
#define SQUID_SRC_FS_UFS_STOREFSUFS_H

/**
 \defgroup UFS  UFS Storage Filesystem
 \ingroup FileSystems
 */

#include "StoreFileSystem.h"

class DiskIOModule;

namespace Fs
{
namespace Ufs
{
/**
 \ingroup UFS, FileSystems
 *
 * Core UFS class. This template provides compile time aliases for
 * ufs/aufs/diskd to ease configuration conversion - each becomes a
 * StoreFS module whose createSwapDir method parameterises the common
 * UFSSwapDir with an IO module instance.
 */
template <class TheSwapDir>
class StoreFSufs : public StoreFileSystem
{
public:
    static StoreFileSystem &GetInstance();
    StoreFSufs(char const *DefaultModuleType, char const *label);
    ~StoreFSufs() override {}

    /* StoreFileSystem API */
    const char *type() const override;
    SwapDir *createSwapDir() override;

protected:
    DiskIOModule *IO;
    char const *moduleName;
    char const *label;
};

template <class C>
StoreFSufs<C>::StoreFSufs(char const *defaultModuleName, char const *aLabel) : IO(nullptr), moduleName(defaultModuleName), label(aLabel)
{
    FsAdd(*this);
}

template <class C>
char const *
StoreFSufs<C>::type() const
{
    return label;
}

template <class C>
SwapDir *
StoreFSufs<C>::createSwapDir()
{
    C *result = new C(type(), moduleName);
    return result;
}

} /* namespace Ufs */
} /* namespace Fs */

#endif /* SQUID_SRC_FS_UFS_STOREFSUFS_H */

