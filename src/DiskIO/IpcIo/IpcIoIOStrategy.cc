/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "IpcIoFile.h"
#include "IpcIoIOStrategy.h"
#include "unlinkd.h"

bool
IpcIoIOStrategy::shedLoad()
{
    return false;
}

int
IpcIoIOStrategy::load()
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

DiskFile::Pointer
IpcIoIOStrategy::newFile (char const *path)
{
    return new IpcIoFile (path);
}

bool
IpcIoIOStrategy::unlinkdUseful() const
{
    return true;
}

void
IpcIoIOStrategy::unlinkFile(char const *path)
{
    unlinkdUnlink(path);
}

