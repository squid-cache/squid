/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FS_ROCK_ROCKSTOREFILESYSTEM_H
#define SQUID_SRC_FS_ROCK_ROCKSTOREFILESYSTEM_H

#include "StoreFileSystem.h"

class StoreEntry;
namespace Rock
{

/// \ingroup Rock, FileSystems
class StoreFileSystem: public ::StoreFileSystem
{

public:
    static void Stats(StoreEntry * sentry);

    StoreFileSystem();
    ~StoreFileSystem() override;

    /* StoreFileSystem API */
    char const *type() const override;
    SwapDir *createSwapDir() override;

private:
    //static Stats Stats_;

    StoreFileSystem(const StoreFileSystem &); // not implemented
    StoreFileSystem &operator=(const StoreFileSystem &); // not implemented
};

} // namespace Rock

#endif /* SQUID_SRC_FS_ROCK_ROCKSTOREFILESYSTEM_H */

