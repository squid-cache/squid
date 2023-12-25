/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "BlockingFile.h"
#include "BlockingIOStrategy.h"
#include "unlinkd.h"

bool
BlockingIOStrategy::shedLoad()
{
    return false;
}

int
BlockingIOStrategy::load()
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

DiskFile::Pointer
BlockingIOStrategy::newFile (char const *path)
{
    return new BlockingFile (path);
}

bool
BlockingIOStrategy::unlinkdUseful() const
{
    return true;
}

void
BlockingIOStrategy::unlinkFile(char const *path)
{
    unlinkdUnlink(path);
}

