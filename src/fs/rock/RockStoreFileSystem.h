/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_FS_H
#define SQUID_FS_ROCK_FS_H

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
    virtual ~StoreFileSystem();

    /* StoreFileSystem API */
    virtual char const *type() const override;
    virtual SwapDir *createSwapDir() override;

private:
    //static Stats Stats_;

    StoreFileSystem(const StoreFileSystem &); // not implemented
    StoreFileSystem &operator=(const StoreFileSystem &); // not implemented
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_FS_H */

