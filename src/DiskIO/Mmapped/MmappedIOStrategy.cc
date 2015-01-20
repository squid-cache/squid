/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "MmappedFile.h"
#include "MmappedIOStrategy.h"
#include "unlinkd.h"

bool
MmappedIOStrategy::shedLoad()
{
    return false;
}

int
MmappedIOStrategy::load()
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

DiskFile::Pointer
MmappedIOStrategy::newFile (char const *path)
{
    return new MmappedFile (path);
}

bool
MmappedIOStrategy::unlinkdUseful() const
{
    return true;
}

void
MmappedIOStrategy::unlinkFile(char const *path)
{
    unlinkdUnlink(path);
}

